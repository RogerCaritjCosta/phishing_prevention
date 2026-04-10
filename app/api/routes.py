import time
import stripe
from flask import request, jsonify, current_app
from app.api import api_bp
from app.auth import require_auth


@api_bp.route("/health", methods=["GET"])
def health():
    config = current_app.config
    apis = {
        "virustotal": bool(config.get("VIRUSTOTAL_API_KEY")),
        "google_safe_browsing": bool(config.get("GOOGLE_SAFE_BROWSING_API_KEY")),
        "phishtank": bool(config.get("PHISHTANK_API_KEY")),
    }
    return jsonify({
        "status": "ok",
        "apis_configured": apis,
    })


@api_bp.route("/analyze/text", methods=["POST"])
@require_auth
def analyze_text():
    data = request.get_json()
    if not data or not data.get("text", "").strip():
        return jsonify({"success": False, "error": "No text provided"}), 400

    text = data["text"]
    language = data.get("language", "en")

    from app.parsers.text_parser import TextParser
    from app.analyzers import run_analysis

    start = time.time()
    parsed = TextParser.parse(text)
    result = run_analysis(parsed, language)
    elapsed_ms = int((time.time() - start) * 1000)
    result["metadata"]["analysis_time_ms"] = elapsed_ms

    return jsonify(result)


@api_bp.route("/analyze/eml", methods=["POST"])
@require_auth
def analyze_eml():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename or not file.filename.lower().endswith(".eml"):
        return jsonify({"success": False, "error": "File must be .eml"}), 400

    language = request.form.get("language", "en")

    from app.parsers.email_parser import EmailParser
    from app.analyzers import run_analysis

    start = time.time()
    raw = file.read()
    parsed = EmailParser.parse(raw)
    result = run_analysis(parsed, language)
    elapsed_ms = int((time.time() - start) * 1000)
    result["metadata"]["analysis_time_ms"] = elapsed_ms

    return jsonify(result)


@api_bp.route("/translations/<lang>", methods=["GET"])
def translations(lang):
    from app.i18n import load_translations
    data = load_translations(lang)
    if data is None:
        return jsonify({"error": f"Language '{lang}' not supported"}), 404
    return jsonify(data)


# ── Payments ─────────────────────────────────────────────

VALID_PLANS = ("basic", "pro")


@api_bp.route("/checkout", methods=["POST"])
@require_auth
def create_checkout():
    config = current_app.config
    stripe.api_key = config.get("STRIPE_SECRET_KEY")
    if not stripe.api_key:
        return jsonify({"error": "Payments not configured"}), 503

    data = request.get_json()
    plan = data.get("plan") if data else None
    if plan not in VALID_PLANS:
        return jsonify({"error": "Invalid plan. Choose 'basic' or 'pro'"}), 400

    price_id = config.get(f"STRIPE_PRICE_{plan.upper()}")
    if not price_id:
        return jsonify({"error": f"Price not configured for plan '{plan}'"}), 503

    uid = request.firebase_user.get("sub", "")
    email = request.firebase_user.get("email", "")

    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{"price": price_id, "quantity": 1}],
        customer_email=email,
        metadata={"uid": uid, "plan": plan},
        success_url=config.get("STRIPE_SUCCESS_URL",
                               "https://phishing-prevention-1-vqvj.onrender.com/payment?result=success"),
        cancel_url=config.get("STRIPE_CANCEL_URL",
                              "https://phishing-prevention-1-vqvj.onrender.com/payment?result=cancelled"),
    )

    return jsonify({"url": session.url})


@api_bp.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    config = current_app.config
    stripe.api_key = config.get("STRIPE_SECRET_KEY")
    webhook_secret = config.get("STRIPE_WEBHOOK_SECRET")

    payload = request.data
    sig = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig, webhook_secret)
    except (ValueError, stripe.error.SignatureVerificationError):
        return jsonify({"error": "Invalid signature"}), 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        uid = session.get("metadata", {}).get("uid")
        plan = session.get("metadata", {}).get("plan")
        customer_id = session.get("customer", "")
        payment_id = session.get("id", "")

        if uid and plan in VALID_PLANS:
            from app.firebase import update_user_plan
            update_user_plan(uid, plan, customer_id, payment_id)

    return jsonify({"received": True})
