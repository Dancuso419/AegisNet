import os
import joblib
import shap
import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "url_length", "hostname_length", "num_dots", "num_hyphens",
    "num_underscores", "num_slashes", "num_question_marks", "num_equals",
    "num_at", "num_ampersands", "has_ip", "has_https", "num_subdomains",
    "is_shortened", "has_suspicious_keyword", "has_port", "longest_word_length",
    "num_digits", "digit_ratio", "has_double_slash_path", "suspicious_tld",
    "domain_age_days", "domain_registration_length", "whois_success",
    "has_brand_impersonation",
]

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "model.pkl")

_model = None
_explainer = None


def _load():
    global _model, _explainer
    if _model is not None:
        return

    if not os.path.exists(MODEL_PATH):
        raise RuntimeError(
            "Model file not found at ml/model.pkl. "
            "Please run `python ml/train.py` first to train the model."
        )

    _model = joblib.load(MODEL_PATH)
    _explainer = shap.TreeExplainer(_model)


def predict(features: dict) -> dict:
    _load()

    df = pd.DataFrame([features], columns=FEATURE_COLUMNS).fillna(-1)
    proba = _model.predict_proba(df)[0]
    phishing_prob = float(proba[1])
    verdict = "Phishing" if phishing_prob >= 0.5 else "Legitimate"
    confidence = round(phishing_prob * 100 if verdict == "Phishing" else (1 - phishing_prob) * 100, 2)

    shap_values = _explainer.shap_values(df)

    if isinstance(shap_values, list):
        vals = shap_values[1][0]
    else:
        vals = shap_values[0] if shap_values.ndim == 3 else shap_values[0]
        if vals.ndim > 1:
            vals = vals[:, 1]

    shap_pairs = sorted(
        zip(FEATURE_COLUMNS, vals),
        key=lambda x: abs(x[1]),
        reverse=True
    )
    top_features = [
        {"feature": name, "shap_value": round(float(val), 4)}
        for name, val in shap_pairs[:3]
    ]

    return {
        "verdict": verdict,
        "confidence": confidence,
        "phishing_probability": phishing_prob,
        "top_features": top_features,
    }
