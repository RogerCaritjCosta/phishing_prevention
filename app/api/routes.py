import time
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
