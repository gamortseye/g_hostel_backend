# main.py
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

# --------------------------
# Logging
# --------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("paystack-verifier")

# --------------------------
# Configuration (env variables)
# --------------------------
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
FIREBASE_JSON_STR = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
# optional: set PORT, etc.

if not PAYSTACK_SECRET_KEY:
    logger.error("PAYSTACK_SECRET_KEY is not set. Exiting.")
    # we don't raise here so container can still boot during local dev, but endpoints will fail clearly.

# --------------------------
# Initialize Firebase Admin
# --------------------------
if not firebase_admin._apps:
    if FIREBASE_JSON_STR:
        try:
            cred_info = json.loads(FIREBASE_JSON_STR)
            cred = credentials.Certificate(cred_info)
            firebase_admin.initialize_app(cred)
            logger.info("Firebase initialized from FIREBASE_SERVICE_ACCOUNT_JSON")
        except Exception as e:
            logger.exception("Failed to initialize firebase from env JSON: %s", e)
            raise
    else:
        # fallback to local file
        if os.path.exists("serviceAccountKey.json"):
            cred = credentials.Certificate("serviceAccountKey.json")
            firebase_admin.initialize_app(cred)
            logger.info("Firebase initialized from serviceAccountKey.json")
        else:
            logger.warning("No Firebase credentials found. Firestore client may fail.")

db = firestore.client()

# --------------------------
# FastAPI app
# --------------------------
app = FastAPI(title="Paystack Verifier", version="1.0")

# --------------------------
# Request model
# --------------------------
class PaymentRequest(BaseModel):
    reference: str = Field(..., description="Paystack transaction reference")
    uid: str = Field(..., description="User UID in Firestore")
    planId: str = Field(..., description="Plan identifier (e.g., '1-month' or '12-month')")
    amountGhs: float = Field(..., description="Expected amount in GHS (decimal)")

# --------------------------
# Helper: convert GHS float -> minor units (pesewas)
# --------------------------
def ghs_to_minor(amount_ghs: float) -> int:
    # multiply by 100 and round to nearest int
    return int(round(amount_ghs * 100))

# --------------------------
# Endpoint: health
# --------------------------
@app.get("/", status_code=200)
def home():
    return {"message": "Paystack verification server running"}

# --------------------------
# Endpoint: verify-payment
# --------------------------
@app.post("/verify-payment", status_code=200)
async def verify_payment(req: PaymentRequest):
    # Basic server-side checks
    if not PAYSTACK_SECRET_KEY:
        logger.error("Missing PAYSTACK_SECRET_KEY")
        raise HTTPException(status_code=500, detail="Server misconfiguration: missing Paystack key")

    # idempotency check: if we've already processed this reference, return success
    payments_col = db.collection("payments")
    payment_doc_ref = payments_col.document(req.reference)

    try:
        existing = payment_doc_ref.get()
        if existing.exists:
            existing_data = existing.to_dict() or {}
            existing_status = existing_data.get("status")
            logger.info("Reference %s already exists with status=%s", req.reference, existing_status)
            if existing_status == "success":
                # Already processed successfully — return success (idempotent)
                return {"status": "success", "message": "Reference already verified"}
            # otherwise: document exists but not successful — fall through and re-verify
    except Exception as e:
        logger.exception("Error checking existing payment: %s", e)
        # continue — we'll try verify, but log.

    # 1) Query Paystack verify endpoint
    paystack_url = f"https://api.paystack.co/transaction/verify/{req.reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(paystack_url, headers=headers)
        except Exception as e:
            logger.exception("Error contacting Paystack: %s", e)
            raise HTTPException(status_code=502, detail="Failed to contact Paystack")

    if resp.status_code != 200:
        logger.error("Paystack responded with non-200 (%d): %s", resp.status_code, resp.text)
        raise HTTPException(status_code=400, detail="Paystack verification failed")

    try:
        ps = resp.json()
    except Exception as e:
        logger.exception("Failed to parse Paystack JSON: %s", e)
        raise HTTPException(status_code=500, detail="Invalid Paystack response")

    # expected structure: { "status": true, "message": "...", "data": { ... } }
    if not ps.get("status"):
        logger.error("Paystack reported failure: %s", ps)
        raise HTTPException(status_code=400, detail="Paystack returned failure")

    data = ps.get("data") or {}
    tx_status = data.get("status")
    tx_amount = data.get("amount")  # amount in minor units (pesewas)
    tx_currency = data.get("currency") or "GHS"
    tx_reference = data.get("reference")

    # 2) Ensure Paystack transaction is successful
    if tx_status != "success":
        logger.warning("Transaction %s status is not success: %s", req.reference, tx_status)
        # Store the failed attempt for auditability
        try:
            payment_doc_ref.set({
                "uid": req.uid,
                "reference": req.reference,
                "paystack_response": ps,
                "status": tx_status,
                "createdAt": firestore.SERVER_TIMESTAMP
            }, merge=True)
        except Exception:
            logger.exception("Failed to record failed transaction")
        raise HTTPException(status_code=400, detail="Transaction is not successful")

    # 3) Validate amount matches
    expected_minor = ghs_to_minor(req.amountGhs)
    if tx_amount is None:
        logger.error("Paystack did not return amount for ref %s", req.reference)
        raise HTTPException(status_code=400, detail="Paystack response missing amount")

    if int(tx_amount) != expected_minor:
        # amount mismatch: log details and reject
        logger.error("Amount mismatch for ref %s: expected %d got %d", req.reference, expected_minor, int(tx_amount))
        # Write attempt
        try:
            payment_doc_ref.set({
                "uid": req.uid,
                "reference": req.reference,
                "paystack_response": ps,
                "status": "amount_mismatch",
                "expected_amount_minor": expected_minor,
                "received_amount_minor": int(tx_amount),
                "createdAt": firestore.SERVER_TIMESTAMP
            }, merge=True)
        except Exception:
            logger.exception("Failed to record mismatch transaction")
        raise HTTPException(status_code=400, detail="Payment amount mismatch")

    # 4) Optional: validate currency
    if tx_currency and tx_currency.upper() != "GHS":
        logger.warning("Currency mismatch for %s: got %s", req.reference, tx_currency)

    # 5) Idempotent write: create payments/{reference} and update user's subscription
    try:
        # Create payment document (id = reference)
        payment_doc_ref.set({
            "uid": req.uid,
            "reference": req.reference,
            "amountGhs": req.amountGhs,
            "amount_minor": int(tx_amount),
            "currency": tx_currency,
            "status": "success",
            "paystack_response": ps,  # store full response for auditing
            "createdAt": firestore.SERVER_TIMESTAMP
        }, merge=True)

        # Compute subscription end date
        now = datetime.utcnow()
        months_to_add = 12 if "12" in req.planId else 1
        # Best-effort end date using timedelta ~= 30*months (simpler than month arithmetic)
        end_date = now + timedelta(days=30 * months_to_add)

        # Update user subscription
        user_ref = db.collection("users").document(req.uid)
        user_ref.set({
            "subscriptionStatus": "active",
            "subscriptionPlan": req.planId,
            "subscriptionStart": now,
            "subscriptionEnd": end_date,
            "lastPayment": {
                "amount": req.amountGhs,
                "currency": "GHS",
                "reference": req.reference,
                "timestamp": firestore.SERVER_TIMESTAMP
            }
        }, merge=True)

        logger.info("Subscription updated for uid=%s ref=%s", req.uid, req.reference)
    except Exception as e:
        logger.exception("Firestore update failed: %s", e)
        # Try to store a failure marker in payments doc
        try:
            payment_doc_ref.set({
                "uid": req.uid,
                "reference": req.reference,
                "status": "db_error",
                "error": str(e),
                "paystack_response": ps,
                "createdAt": firestore.SERVER_TIMESTAMP
            }, merge=True)
        except Exception:
            logger.exception("Failed to write fallback payment failure doc")

        raise HTTPException(status_code=500, detail="Failed to record payment or update subscription")

    return {"status": "success", "message": "Payment verified and subscription updated"}

# --------------------------
# Uvicorn entry hint
# --------------------------
# Run with: uvicorn main:app --host 0.0.0.0 --port 8000
