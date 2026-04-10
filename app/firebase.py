import base64
import json
from datetime import datetime, timedelta, timezone

import firebase_admin
from firebase_admin import credentials, firestore
from flask import current_app

_app = None

PLAN_LIMITS = {
    "free": 10,
    "basic": 50,
    "pro": 250,
}


def _init_firebase():
    global _app
    if _app:
        return

    b64 = current_app.config.get("FIREBASE_SERVICE_ACCOUNT", "")
    if not b64:
        raise RuntimeError("FIREBASE_SERVICE_ACCOUNT env var not set")

    sa_json = json.loads(base64.b64decode(b64))
    cred = credentials.Certificate(sa_json)
    _app = firebase_admin.initialize_app(cred)


def get_firestore_client():
    _init_firebase()
    return firestore.client()


def update_user_plan(uid: str, plan_type: str, stripe_customer_id: str, payment_id: str):
    db = get_firestore_client()
    doc_ref = db.document(f"users/{uid}/apps/phishbuster")

    daily_limit = PLAN_LIMITS.get(plan_type, 10)

    # For renewals: extend from current expiry if it's still in the future
    now = datetime.now(timezone.utc)
    doc = doc_ref.get()
    if doc.exists:
        current_expiry_str = doc.to_dict().get("planExpiresAt", "")
        # Check idempotency
        if doc.to_dict().get("lastPaymentId") == payment_id:
            return
        if current_expiry_str:
            try:
                current_expiry = datetime.fromisoformat(current_expiry_str.replace("Z", "+00:00"))
                if current_expiry > now:
                    now = current_expiry
            except ValueError:
                pass

    expires_at = now + timedelta(days=30)

    doc_ref.update({
        "planType": plan_type,
        "dailyLimit": daily_limit,
        "planExpiresAt": expires_at.isoformat(),
        "stripeCustomerId": stripe_customer_id,
        "lastPaymentId": payment_id,
    })
