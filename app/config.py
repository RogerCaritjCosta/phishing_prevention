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

    # Rate limiting
    VIRUSTOTAL_REQUESTS_PER_MINUTE = 4
