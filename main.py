# server.py
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
import firebase_admin
from firebase_admin import credentials, auth as fb_auth, firestore
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("paystack-verifier")

# ---------- Config from ENV ----------
# CRITICAL: This must be your LIVE Secret Key (sk_live_...) on Render
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
FIREBASE_JSON_STR = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")

if not PAYSTACK_SECRET_KEY:
    logger.error("PAYSTACK_SECRET_KEY is not set in environment")
if not FIREBASE_JSON_STR:
    logger.error("FIREBASE_SERVICE_ACCOUNT_JSON is not set in environment")

# ---------- Initialize Firebase Admin ----------
if not firebase_admin._apps:
    if FIREBASE_JSON_STR:
        cred_info = json.loads(FIREBASE_JSON_STR)
        cred = credentials.Certificate(cred_info)
        firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin initialized from ENV JSON.")
    elif os.path.exists("serviceAccountKey.json"):
        cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin initialized from local file.")
    else:
        logger.error("No Firebase credentials found. Exiting.")
        raise RuntimeError("No Firebase credentials available.")

db = firestore.client()

# ---------- FastAPI ----------
app = FastAPI(title="Paystack Verifier")

# Allow CORS - Restrict this to your domain in strict production if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Request Models ----------
class PaymentRequest(BaseModel):
    reference: str
    uid: str
    planId: Optional[str] = "unknown"
    amountGhs: Optional[float] = None

class InitPaymentRequest(BaseModel):
    email: str
    amount: int  # Amount in kobo/pesewas (e.g. 100 = 1 GHS)
    reference: str

# ---------- Helpers ----------
async def verify_paystack_transaction(reference: str) -> dict:
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.get(url, headers=headers)
    if r.status_code != 200:
        logger.warning("Paystack verify returned non-200: %s %s", r.status_code, r.text)
        raise HTTPException(status_code=502, detail="Failed to contact Paystack")
    data = r.json()
    logger.info("Paystack response: %s", data)
    return data

def compute_end_date(months: int) -> datetime:
    now = datetime.utcnow()
    return now + timedelta(days=30 * months)

# ---------- NEW ENDPOINT: Initialize Payment ----------
@app.post("/initialize-payment")
async def initialize_payment(req: InitPaymentRequest):
    """
    Called by Flutter app to get the Secure Payment URL.
    Uses the Server-Side Secret Key so the App doesn't need it.
    """
    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    # Payload for Paystack
    payload = {
        "email": req.email,
        "amount": req.amount,
        "reference": req.reference,
        "currency": "GHS",
        "channels": ["mobile_money", "card"],
        # The URL that triggers the app to close
        "callback_url": "https://standard.paystack.co/close" 
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            
        if response.status_code == 200:
            res_data = response.json()
            if res_data['status'] is True:
                return {
                    "status": True,
                    "data": {
                        "authorization_url": res_data['data']['authorization_url'],
                        "reference": res_data['data']['reference']
                    }
                }
            else:
                raise HTTPException(status_code=400, detail=res_data.get('message', 'Initialization failed'))
        else:
            logger.error(f"Paystack Init Error: {response.text}")
            raise HTTPException(status_code=response.status_code, detail="Failed to initialize with Paystack")
            
    except httpx.RequestError as exc:
        logger.error(f"Connection error to Paystack: {exc}")
        raise HTTPException(status_code=503, detail="Service unavailable")

# ---------- EXISTING ENDPOINT: Verify Payment ----------
@app.post("/verify-payment")
async def verify_payment(req: PaymentRequest, authorization: str | None = Header(None)):
    logger.info("Incoming verify-payment request: reference=%s uid=%s plan=%s amount=%s",
                req.reference, req.uid, req.planId, req.amountGhs)

    # 1) Authorization header check
    if not authorization:
        logger.warning("Missing Authorization header")
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    if not authorization.lower().startswith("bearer "):
        logger.warning("Malformed Authorization header")
        raise HTTPException(status_code=401, detail="Invalid Authorization header")

    id_token = authorization.split(" ", 1)[1].strip()

    # 2) Verify Firebase ID token
    try:
        decoded = fb_auth.verify_id_token(id_token)
        token_uid = decoded.get("uid")
        if token_uid != req.uid:
            logger.warning("UID mismatch: token_uid=%s payload_uid=%s", token_uid, req.uid)
            raise HTTPException(status_code=403, detail="Token UID does not match provided uid")
    except Exception as e:
        logger.exception("Firebase token verification failed: %s", e)
        raise HTTPException(status_code=401, detail="Invalid Firebase ID token")

    # 3) Verify with Paystack
    paystack_data = await verify_paystack_transaction(req.reference)

    if not paystack_data.get("status"):
        raise HTTPException(status_code=400, detail="Paystack did not return success status")

    pdata = paystack_data.get("data", {})
    if pdata.get("status") != "success":
        raise HTTPException(status_code=400, detail="Transaction not successful")

    # 4) Optional: confirm amount
    if req.amountGhs is not None:
        expected_minor = int(round(req.amountGhs * 100))
        received_minor = int(pdata.get("amount", 0))
        # Allow small floating point margin or exact match
        if abs(received_minor - expected_minor) > 5: 
            logger.warning("Amount mismatch: expected %s got %s", expected_minor, received_minor)
            raise HTTPException(status_code=400, detail="Paid amount does not match expected amount")

    # 5) Update Firestore
    try:
        months = 12 if ("12" in (req.planId or "").lower()) else 1
        now = datetime.utcnow()
        end_date = compute_end_date(months)

        user_ref = db.collection("users").document(req.uid)
        update_payload = {
            "subscriptionStatus": "active",
            "subscriptionPlan": req.planId,
            "subscriptionStart": now,
            "subscriptionEnd": end_date,
            "lastPayment": {
                "amount": float(req.amountGhs or (pdata.get("amount", 0) / 100.0)),
                "currency": pdata.get("currency", "GHS"),
                "reference": req.reference,
                "paystack_data": pdata,
                "timestamp": now,
            },
        }
        user_ref.set(update_payload, merge=True)
        logger.info("Firestore updated for uid=%s", req.uid)
        return {"status": "success", "message": "Subscription activated"}
    except Exception as e:
        logger.exception("Failed updating Firestore: %s", e)
        raise HTTPException(status_code=500, detail="Database update failed")

@app.get("/")
def home():
    return {"message": "Paystack Secure Server Running"}
