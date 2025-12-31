import os
import json
import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
from datetime import datetime, timedelta

# --- CONFIGURATION ---
# We get these from the server's settings (Environment Variables)
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")

# --- SETUP FIREBASE ---
# We expect the entire content of serviceAccountKey.json to be stored in an ENV variable
firebase_json_str = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")

if not firebase_admin._apps:
    if firebase_json_str:
        # Production: Load from Environment Variable string
        cred_info = json.loads(firebase_json_str)
        cred = credentials.Certificate(cred_info)
        firebase_admin.initialize_app(cred)
    else:
        # Local Development: Fallback to local file if ENV not found
        # Make sure you have this file locally, but NEVER commit it to GitHub
        if os.path.exists("serviceAccountKey.json"):
            cred = credentials.Certificate("serviceAccountKey.json")
            firebase_admin.initialize_app(cred)
        else:
            print("Warning: No Firebase credentials found.")

db = firestore.client()
app = FastAPI()

# --- DATA MODEL ---
class PaymentRequest(BaseModel):
    reference: str
    uid: str
    planId: str
    amountGhs: float

@app.post("/verify-payment")
async def verify_payment(data: PaymentRequest):
    if not PAYSTACK_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Server misconfiguration: Missing Paystack Key")

    # 1. Verify with Paystack
    url = f"https://api.paystack.co/transaction/verify/{data.reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to connect to Paystack")
    
    paystack_data = response.json()
    
    if not paystack_data.get('status') or paystack_data['data']['status'] != 'success':
        raise HTTPException(status_code=400, detail="Payment verification failed")

    # 2. Update Firestore
    try:
        now = datetime.utcnow()
        months_to_add = 12 if "12" in data.planId else 1
        end_date = now + timedelta(days=30 * months_to_add)

        user_ref = db.collection('users').document(data.uid)
        user_ref.set({
            "subscriptionStatus": "active",
            "subscriptionPlan": data.planId,
            "subscriptionStart": now,
            "subscriptionEnd": end_date,
            "lastPayment": {
                "amount": data.amountGhs,
                "currency": "GHS",
                "reference": data.reference,
                "timestamp": now
            }
        }, merge=True)
        
        return {"status": "success", "message": "Subscription activated"}
        
    except Exception as e:
        print(f"Firestore Error: {e}")
        raise HTTPException(status_code=500, detail="Database update failed")

@app.get("/")
def home():
    return {"message": "Payment Server is Running"}