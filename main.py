# main.py
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel

# Configure logging (Render logs will show this)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pay-verify")

# --- CONFIG ---
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
FIREBASE_JSON = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
# Optionally allow a debug bypass token (not for prod)
DEBUG_ALLOW_NO_IDTOKEN = os.environ.get("DEBUG_ALLOW_NO_IDTOKEN", "false").lower() == "true"

if not PAYSTACK_SECRET_KEY:
    logger.error("PAYSTACK_SECRET_KEY not set in environment")
if not FIREBASE_JSON:
    logger.error("FIREBASE_SERVICE_ACCOUNT_JSON not set in environment")

# --- FIREBASE init ---
if not firebase_admin._apps:
    if FIREBASE_JSON:
        try:
            cred_info = json.loads(FIREBASE_JSON)
            cred = credentials.Certificate(cred_info)
            firebase_admin.initialize_app(cred)
            logger.info("Initialized Firebase Admin from ENV JSON")
        except Exception as e:
            logger.exception("Failed to initialize Firebase Admin from ENV JSON: %s", e)
            raise
    else:
        # try fallback to local file (dev only)
        if os.path.exists("serviceAccountKey.json"):
            cred = credentials.Certificate("serviceAccountKey.json")
            firebase_admin.initialize_app(cred)
            logger.info("Initialized Firebase Admin from local serviceAccountKey.json")
        else:
            logger.error("No Firebase credentials found. Exiting.")
            raise RuntimeError("FIREBASE service account JSON is required")

db = firestore.client()
app = FastAPI()

# Request model
class PaymentRequest(BaseModel):
    reference: str
    uid: str
    planId: str
    amountGhs: float

# Helper: verify firebase id token and return uid/email
async def verify_id_token(id_token: Optional[str]) -> dict:
    if not id_token:
        if DEBUG_ALLOW_NO_IDTOKEN:
            logger.warning("No id token provided but DEBUG_ALLOW_NO_IDTOKEN=true, continuing without user verification")
            return {}
        raise HTTPException(status_code=401, detail="Missing Authorization ID token")
    try:
        decoded = firebase_auth.verify_id_token(id_token)
        return decoded
    except Exception as e:
        logger.exception("Invalid ID token: %s", e)
        raise HTTPException(status_code=401, detail="Invalid ID token")

@app.post("/verify-payment")
async def verify_payment(payload: PaymentRequest, authorization: Optional[str] = Header(None)):
    """
    Verifies a Paystack transaction reference, ensures it's successful and matches expected amount & currency,
    then updates the user's Firestore document with subscription fields.
    """
    logger.info("Incoming verify-payment request: reference=%s uid=%s planId=%s amountGhs=%s", payload.reference, payload.uid, payload.planId, payload.amountGhs)

    # extract bearer token if present
    id_token = None
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            id_token = parts[1]

    # verify id token (optional dev bypass)
    decoded = await verify_id_token(id_token) if not DEBUG_ALLOW_NO_IDTOKEN else (firebase_auth.verify_id_token(id_token) if id_token else {})
    if decoded:
        # ensure token uid matches provided uid
        token_uid = decoded.get("uid")
        if token_uid and token_uid != payload.uid:
            logger.warning("Token UID (%s) does not match provided uid (%s)", token_uid, payload.uid)
            raise HTTPException(status_code=403, detail="Token does not match uid")

    # 1) call Paystack verify endpoint
    verify_url = f"https://api.paystack.co/transaction/verify/{payload.reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    logger.info("Calling Paystack verify: %s", verify_url)

    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            resp = await client.get(verify_url, headers=headers)
        except Exception as e:
            logger.exception("HTTP error calling Paystack: %s", e)
            raise HTTPException(status_code=502, detail="Failed to reach Paystack")

    if resp.status_code != 200:
        logger.error("Paystack verify returned non-200: %s %s", resp.status_code, resp.text)
        raise HTTPException(status_code=502, detail=f"Paystack verify failed: {resp.status_code}")

    data = resp.json()
    logger.info("Paystack response: %s", json.dumps(data))

    # Paystack returns top-level 'status' boolean and a 'data' dict
    if not data.get("status") or not data.get("data"):
        logger.error("Unexpected Paystack response shape")
        raise HTTPException(status_code=400, detail="Invalid Paystack response")

    tx = data["data"]
    tx_status = tx.get("status")
    tx_currency = tx.get("currency")
    tx_amount = tx.get("amount")  # amount is in minor unit (pesewas)
    tx_reference = tx.get("reference")

    if tx_status != "success":
        logger.warning("Transaction not successful according to Paystack: %s", tx_status)
        raise HTTPException(status_code=400, detail="Transaction not successful")

    # Validate reference matches (trust Paystack's returned reference)
    # Ensure the amount matches expected (compare integers in minor unit)
    expected_minor = int(round(payload.amountGhs * 100))
    tx_amount_int = int(tx_amount) if tx_amount is not None else None

    # Some Paystack integrations may produce amounts scaled differently; log both and continue only if matching
    if tx_amount_int is None:
        logger.warning("Paystack returned no amount field")
    else:
        logger.info("Comparing amounts: expected=%s got=%s (both minor units)", expected_minor, tx_amount_int)
        if tx_amount_int != expected_minor:
            logger.warning("Amount mismatch! expected %s but Paystack returned %s", expected_minor, tx_amount_int)
            # _not_ failing — depending on policy you may FAIL here. For safety, fail:
            raise HTTPException(status_code=400, detail="Amount mismatch with Paystack transaction")

    if tx_currency and tx_currency.upper() != "GHS":
        logger.warning("Currency mismatch: %s", tx_currency)
        raise HTTPException(status_code=400, detail="Currency mismatch")

    # 2) Update Firestore
    try:
        now = datetime.utcnow()
        months_to_add = 12 if "12" in payload.planId else 1
        # best-effort end date: add months (approx 30 days per month)
        end_date = now + timedelta(days=30 * months_to_add)

        user_ref = db.collection("users").document(payload.uid)
        user_ref.set({
            "subscriptionStatus": "active",
            "subscriptionPlan": payload.planId,
            "subscriptionStart": now,
            "subscriptionEnd": end_date,
            "lastPayment": {
                "amount": float(payload.amountGhs),
                "currency": "GHS",
                "reference": payload.reference,
                "verified_at": now
            }
        }, merge=True)

        logger.info("Firestore updated for uid=%s", payload.uid)
        return {"status": "success", "message": "Subscription activated"}
    except Exception as e:
        logger.exception("Failed to update Firestore: %s", e)
        raise HTTPException(status_code=500, detail="Database update failed")

@app.get("/")
def home():
    return {"message": "Payment Server is Running"}
