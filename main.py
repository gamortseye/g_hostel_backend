# main.py
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict

import httpx
import firebase_admin
from firebase_admin import credentials, firestore, auth as admin_auth
from fastapi import FastAPI, HTTPException, Header, status, Request
from pydantic import BaseModel, Field

# --------------------------
# Logging
# --------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("paystack-verifier")

# --------------------------
# Config (env)
# --------------------------
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
FIREBASE_JSON_STR = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")

if not PAYSTACK_SECRET_KEY:
    logger.warning("PAYSTACK_SECRET_KEY not set - endpoint will fail if called.")

# --------------------------
# Firebase init
# --------------------------
if not firebase_admin._apps:
    if FIREBASE_JSON_STR:
        cred_info = json.loads(FIREBASE_JSON_STR)
        cred = credentials.Certificate(cred_info)
        firebase_admin.initialize_app(cred)
        logger.info("Initialized Firebase from FIREBASE_SERVICE_ACCOUNT_JSON")
    elif os.path.exists("serviceAccountKey.json"):
        cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
        logger.info("Initialized Firebase from serviceAccountKey.json")
    else:
        logger.warning("Firebase credentials not found; Firestore will fail on use.")

db = firestore.client()

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
# Helpers
# --------------------------
def ghs_to_minor(amount_ghs: float) -> int:
    return int(round(amount_ghs * 100))

# --------------------------
# Health
# --------------------------
@app.get("/")
def home():
    return {"message": "Paystack-verifier running"}

# --------------------------
# Verify endpoint
# --------------------------
@app.post("/verify-payment")
async def verify_payment(
    req: PaymentRequest,
    authorization: Optional[str] = Header(None),  # expecting "Bearer <idToken>"
):
    # 0. Basic checks
    if not PAYSTACK_SECRET_KEY:
        logger.error("PAYSTACK_SECRET_KEY missing on server.")
        raise HTTPException(status_code=500, detail="Server misconfiguration")

    # 1. Validate Authorization header (Firebase ID token)
    if not authorization or not authorization.lower().startswith("bearer "):
        logger.warning("Missing Authorization: Bearer <idToken>")
        raise HTTPException(status_code=401, detail="Missing id token")

    id_token = authorization.split(" ", 1)[1].strip()
    try:
        decoded_token = admin_auth.verify_id_token(id_token)
        token_uid = decoded_token.get("uid")
        if token_uid != req.uid:
            logger.warning("Token UID mismatch: token=%s request=%s", token_uid, req.uid)
            raise HTTPException(status_code=403, detail="Token UID mismatch")
    except Exception as e:
        logger.exception("Failed to verify id token: %s", e)
        raise HTTPException(status_code=401, detail="Invalid id token")

    # 2. Idempotency: if payments/{reference} exists and success, return success
    payments_col = db.collection("payments")
    payment_doc_ref = payments_col.document(req.reference)
    try:
        existing = payment_doc_ref.get()
        if existing.exists:
            ed = existing.to_dict() or {}
            if ed.get("status") == "success":
                logger.info("Reference already processed: %s", req.reference)
                return {"status": "success", "message": "Reference already processed"}
    except Exception:
        logger.exception("Error checking existing payments doc (non-fatal)")

    # 3. Verify with Paystack
    verify_url = f"https://api.paystack.co/transaction/verify/{req.reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(verify_url, headers=headers)
        except Exception as e:
            logger.exception("Failed to contact Paystack: %s", e)
            raise HTTPException(status_code=502, detail="Failed to contact Paystack")

    if resp.status_code != 200:
        logger.error("Paystack returned non-200: %s - %s", resp.status_code, resp.text)
        raise HTTPException(status_code=400, detail="Paystack verification failed")

    ps = resp.json()
    if not ps.get("status"):
        logger.error("Paystack status false: %s", ps)
        raise HTTPException(status_code=400, detail="Paystack reported failure")

    data = ps.get("data") or {}
    if data.get("status") != "success":
        # store attempt
        try:
            payment_doc_ref.set({
                "uid": req.uid,
                "reference": req.reference,
                "status": data.get("status"),
                "paystack_response": ps,
                "createdAt": firestore.SERVER_TIMESTAMP
            }, merge=True)
        except Exception:
            logger.exception("Could not write failed payment doc")
        raise HTTPException(status_code=400, detail="Transaction not successful")

    tx_amount = data.get("amount")  # minor unit
    if tx_amount is None:
        logger.error("Paystack response missing amount for reference %s", req.reference)
        raise HTTPException(status_code=400, detail="Paystack response missing amount")

    expected_minor = ghs_to_minor(req.amountGhs)
    if int(tx_amount) != expected_minor:
        logger.error("Amount mismatch: expected %d got %d", expected_minor, int(tx_amount))
        try:
            payment_doc_ref.set({
                "uid": req.uid,
                "reference": req.reference,
                "status": "amount_mismatch",
                "expected_amount_minor": expected_minor,
                "received_amount_minor": int(tx_amount),
                "paystack_response": ps,
                "createdAt": firestore.SERVER_TIMESTAMP
            }, merge=True)
        except Exception:
            logger.exception("Failed to write mismatch doc")
        raise HTTPException(status_code=400, detail="Payment amount mismatch")

    # 4. Everything ok -> write payment doc and update user subscription atomically-ish
    try:
        payment_doc_ref.set({
            "uid": req.uid,
            "reference": req.reference,
            "amountGhs": req.amountGhs,
            "amount_minor": int(tx_amount),
            "currency": data.get("currency", "GHS"),
            "status": "success",
            "paystack_response": ps,
            "createdAt": firestore.SERVER_TIMESTAMP
        }, merge=True)

        # compute subscription end date: 1 or 12 months
        months_to_add = 12 if "12" in req.planId else 1
        # Use server timestamp for start and calculate end date on server (approx 30*days)
        now = datetime.utcnow()
        end_date = now + timedelta(days=30 * months_to_add)

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

    except Exception as e:
        logger.exception("Failed to write Firestore records: %s", e)
        # try to mark payment as db_error
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
            logger.exception("Failed to write fallback payment doc")
        raise HTTPException(status_code=500, detail="Failed to update database")

    logger.info("Payment verified and subscription updated: %s", req.reference)
    return {"status": "success", "message": "Payment verified and subscription updated"}
