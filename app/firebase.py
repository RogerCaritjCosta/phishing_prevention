import base64
import json
from datetime import datetime, timedelta, timezone

import requests as http_requests
import firebase_admin
from firebase_admin import auth as firebase_auth, credentials, firestore
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


def generate_verification_link(email: str) -> str:
    _init_firebase()
    return firebase_auth.generate_email_verification_link(email)


def send_verification_email(email: str, language: str = "en"):
    link = generate_verification_link(email)
    api_key = current_app.config.get("RESEND_API_KEY", "")
    from_email = current_app.config.get("RESEND_FROM_EMAIL", "PhishBuster <onboarding@resend.dev>")

    if not api_key:
        raise RuntimeError("RESEND_API_KEY not configured")

    subjects = {
        "en": "Welcome to PhishBuster — Verify your email",
        "es": "Bienvenido a PhishBuster — Verifica tu email",
        "ca": "Benvingut a PhishBuster — Verifica el teu email",
    }
    subject = subjects.get(language, subjects["en"])
    html = _build_verification_html(email, link, language)

    resp = http_requests.post(
        "https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "from": from_email,
            "to": [email],
            "subject": subject,
            "html": html,
        },
        timeout=10,
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Email send failed: {resp.text}")


def _build_verification_html(email: str, link: str, lang: str) -> str:
    texts = {
        "en": {
            "hi": "Welcome to PhishBuster!",
            "body": "Thanks for signing up. To start protecting your inbox from phishing, please verify your email address.",
            "btn": "Verify my email",
            "footer": "If you didn't create an account, you can safely ignore this email.",
            "alt": "Or copy and paste this link in your browser:",
        },
        "es": {
            "hi": "\u00A1Bienvenido a PhishBuster!",
            "body": "Gracias por registrarte. Para empezar a proteger tu bandeja de entrada contra el phishing, verifica tu email.",
            "btn": "Verificar mi email",
            "footer": "Si no creaste una cuenta, puedes ignorar este email.",
            "alt": "O copia y pega este enlace en tu navegador:",
        },
        "ca": {
            "hi": "Benvingut a PhishBuster!",
            "body": "Gr\u00E0cies per registrar-te. Per comen\u00E7ar a protegir la teva safata d'entrada contra el phishing, verifica el teu email.",
            "btn": "Verificar el meu email",
            "footer": "Si no has creat un compte, pots ignorar aquest email.",
            "alt": "O copia i enganxa aquest enlla\u00E7 al teu navegador:",
        },
    }
    t = texts.get(lang, texts["en"])

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
        <tr>
          <td style="background:#3b82f6;padding:28px 32px;text-align:center;">
            <span style="font-size:28px;color:#fff;font-weight:700;">&#x1F6E1; PhishBuster</span>
          </td>
        </tr>
        <tr>
          <td style="padding:32px;">
            <h1 style="margin:0 0 12px;font-size:22px;color:#1e293b;">{t['hi']}</h1>
            <p style="margin:0 0 24px;font-size:15px;color:#475569;line-height:1.6;">{t['body']}</p>
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr><td align="center">
                <a href="{link}" style="display:inline-block;padding:14px 36px;background:#3b82f6;color:#fff;font-size:16px;font-weight:600;text-decoration:none;border-radius:8px;">{t['btn']}</a>
              </td></tr>
            </table>
            <p style="margin:24px 0 0;font-size:12px;color:#94a3b8;line-height:1.5;">{t['alt']}<br>
              <a href="{link}" style="color:#3b82f6;word-break:break-all;">{link}</a>
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 32px;background:#f8fafc;border-top:1px solid #e2e8f0;">
            <p style="margin:0;font-size:12px;color:#94a3b8;text-align:center;">{t['footer']}</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


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
