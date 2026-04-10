import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"

    # External APIs
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")

    # Stripe
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    STRIPE_PRICE_BASIC = os.getenv("STRIPE_PRICE_BASIC", "")
    STRIPE_PRICE_PRO = os.getenv("STRIPE_PRICE_PRO", "")
    STRIPE_PRICE_BASIC_SUB = os.getenv("STRIPE_PRICE_BASIC_SUB", "")
    STRIPE_PRICE_PRO_SUB = os.getenv("STRIPE_PRICE_PRO_SUB", "")

    # Firebase Admin (base64-encoded service account JSON)
    FIREBASE_SERVICE_ACCOUNT = os.getenv("FIREBASE_SERVICE_ACCOUNT", "")

    # Rate limiting
    VIRUSTOTAL_REQUESTS_PER_MINUTE = 4
