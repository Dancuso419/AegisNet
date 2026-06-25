import json
from urllib.parse import urlparse
from flask import request, jsonify, render_template, session
from flask_login import login_required, current_user
from app import db
from app.models import ScanResult
from app.scanner import scanner_bp
from app.scanner.extractor import extract_features
from app.scanner.predictor import predict
from app.scanner import assistant


@scanner_bp.route("/")
def landing():
    return render_template("landing.html")


@scanner_bp.route("/scanner")
def index():
    return render_template("index.html")


@scanner_bp.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return jsonify({"error": "Invalid URL"}), 400

    features = extract_features(url)
    result = predict(features)

    scan_context = {
        "url": url,
        "verdict": result["verdict"],
        "confidence": result["confidence"],
        "top_features": result["top_features"],
    }
    session["scan_context"] = scan_context
    session["chat_history"] = []

    user_id = current_user.id if current_user.is_authenticated else None
    scan_record = ScanResult(
        url=url,
        verdict=result["verdict"],
        confidence=result["confidence"],
        top_features=json.dumps(result["top_features"]),
        user_id=user_id,
    )
    try:
        db.session.add(scan_record)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Database error"}), 500

    explanation = assistant.get_explanation(scan_context)
    session["chat_history"] = [{"role": "assistant", "content": explanation}]

    return jsonify({
        "url": url,
        "verdict": result["verdict"],
        "confidence": result["confidence"],
        "features": features,
        "top_features": result["top_features"],
        "assistant_message": explanation,
    })


@scanner_bp.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    scan_context = session.get("scan_context")
    history = session.get("chat_history", [])

    history.append({"role": "user", "content": user_message})
    response_text = assistant.chat(user_message, scan_context)
    history.append({"role": "assistant", "content": response_text})

    session["chat_history"] = history

    return jsonify({"response": response_text})


@scanner_bp.route("/dashboard")
@login_required
def dashboard():
    total = ScanResult.query.count()
    phishing = ScanResult.query.filter_by(verdict="Phishing").count()
    legit = ScanResult.query.filter_by(verdict="Legitimate").count()
    threat_rate = round((phishing / total * 100) if total > 0 else 0, 1)
    security_score = round(100 - threat_rate)
    recent = ScanResult.query.order_by(ScanResult.timestamp.desc()).limit(8).all()
    return render_template("dashboard.html",
        total_scans=total,
        phishing_count=phishing,
        legit_count=legit,
        threat_rate=threat_rate,
        security_score=security_score,
        recent_scans=recent,
    )


@scanner_bp.route("/history")
@login_required
def history():
    scans = (
        ScanResult.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanResult.timestamp.desc())
        .limit(100)
        .all()
    )
    return render_template("history.html", scans=scans)
