import json
import time
import jwt
import requests
from functools import wraps
from flask import request, jsonify

FIREBASE_PROJECT_ID = "phishbuster-5d57b"
GOOGLE_CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

_certs_cache = {"certs": None, "expires": 0}


def _get_google_certs():
    """Fetch and cache Google's public certificates for Firebase token verification."""
    now = time.time()
    if _certs_cache["certs"] and now < _certs_cache["expires"]:
        return _certs_cache["certs"]

    resp = requests.get(GOOGLE_CERTS_URL, timeout=10)
    resp.raise_for_status()
    _certs_cache["certs"] = resp.json()
    # Cache for 1 hour
    _certs_cache["expires"] = now + 3600
    return _certs_cache["certs"]


def verify_firebase_token(id_token):
    """Verify a Firebase ID token and return the decoded claims."""
    certs = _get_google_certs()

    # Decode header to find the key ID
    header = jwt.get_unverified_header(id_token)
    kid = header.get("kid")
    if not kid or kid not in certs:
        raise ValueError("Invalid token: unknown key ID")

    cert = certs[kid]

    decoded = jwt.decode(
        id_token,
        public_key,
        algorithms=["RS256"],
        audience=FIREBASE_PROJECT_ID,
        issuer=f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}",
    )

    # Check that sub (user ID) is present and non-empty
    if not decoded.get("sub"):
        raise ValueError("Invalid token: missing subject")

    return decoded


def require_auth(f):
    """Decorator that requires a valid Firebase ID token in the Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization required"}), 401

        token = auth_header[7:]
        try:
            decoded = verify_firebase_token(token)
            request.firebase_user = decoded
        except Exception as e:
            return jsonify({"error": f"Invalid token: {str(e)}"}), 401

        return f(*args, **kwargs)
    return decorated
