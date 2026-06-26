import os
import logging
import google.generativeai as genai
from flask import current_app

logger = logging.getLogger(__name__)

# Bound every Gemini call so a slow or rate-limited request falls back
# quickly instead of hanging the /scan request for 20-30s. A plain
# timeout caps the total call (including the SDK's internal retries).
_REQUEST_OPTIONS = {"timeout": 12}

# Keep auto-explanations concise so responses come back quickly.
_GEN_CONFIG = {"max_output_tokens": 600, "temperature": 0.6}

SYSTEM_PROMPT = (
    "You are AegisNet Assistant, a cybersecurity AI embedded in the AegisNet "
    "phishing link detection platform. Your job is to help users understand "
    "phishing threats, explain URL scan results in plain language, and answer "
    "cybersecurity questions. Always be clear, concise, and friendly. Avoid "
    "technical jargon unless the user specifically asks for technical detail. "
    "Never make up scan results — only explain results that are explicitly "
    "provided to you in the scan context below."
)

# Generic message used only when even the local fallback has nothing to work
# with (e.g. a free-form chat question while the AI service is unavailable).
FALLBACK = (
    "The AI assistant is temporarily unavailable, but your scan results above "
    "are still accurate. Please try chatting again in a moment."
)

# Human-readable, plain-English meaning for each feature when it points toward
# a phishing verdict. Used to build a local explanation when Gemini is down.
_FEATURE_PHRASES = {
    "has_brand_impersonation": "the address looks like it is imitating a well-known brand (a common trick where letters are swapped for look-alike characters)",
    "has_https": "the link does not use a secure HTTPS connection",
    "has_ip": "the link uses a raw IP address instead of a normal domain name",
    "is_shortened": "the link uses a URL shortener that hides the real destination",
    "suspicious_tld": "the domain ends in an extension often abused by scammers",
    "has_suspicious_keyword": "the address contains alarming words like 'login', 'verify' or 'secure' that scammers use as bait",
    "has_port": "the link points to an unusual network port",
    "num_at": "the address contains an '@' symbol, which can disguise the true destination",
    "has_double_slash_path": "the link path contains a suspicious double slash",
    "url_length": "the address is unusually long, which is common in phishing links",
    "num_subdomains": "the address stacks several subdomains together to look legitimate",
    "num_dots": "the address contains an unusually high number of dots",
    "num_hyphens": "the address contains many hyphens, often used to mimic real brands",
    "digit_ratio": "the address contains an unusually high number of digits",
    "num_digits": "the address contains an unusually high number of digits",
    "domain_age_days": "the domain is very newly registered, which is typical of phishing sites",
}


def _configure():
    # Read the key from config first, then fall back to the env var names the
    # Google SDK itself recognises. Strip whitespace in case it was pasted with
    # a trailing newline/space in the hosting dashboard.
    key = (
        current_app.config.get("GEMINI_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or os.environ.get("GOOGLE_API_KEY")
        or ""
    ).strip()

    if not key:
        raise RuntimeError(
            "GEMINI_API_KEY is empty. Set it in your host's Environment "
            "settings (the value must be the actual key from "
            "https://aistudio.google.com/apikey), then redeploy."
        )

    genai.configure(api_key=key)
    return genai.GenerativeModel(current_app.config["GEMINI_MODEL"])


def _format_scan(scan_context: dict) -> str:
    return (
        f"URL: {scan_context.get('url')}\n"
        f"Verdict: {scan_context.get('verdict')}\n"
        f"Confidence: {scan_context.get('confidence')}%\n"
        f"Top contributing features: {scan_context.get('top_features')}"
    )


def _local_explanation(scan_context: dict) -> str:
    """Build a plain-English explanation directly from the scan result.

    This runs entirely offline so the user always gets a meaningful
    explanation even when the Gemini API is unavailable or rate-limited.
    """
    verdict = scan_context.get("verdict", "Legitimate")
    confidence = scan_context.get("confidence", 0)
    top = scan_context.get("top_features", []) or []

    # Collect the human-readable reasons that point toward phishing.
    reasons = []
    for f in top:
        name = f.get("feature")
        shap = f.get("shap_value", 0)
        # A positive SHAP value pushes the prediction toward phishing.
        if shap > 0 and name in _FEATURE_PHRASES:
            reasons.append(_FEATURE_PHRASES[name])

    if verdict == "Phishing":
        intro = (
            f"This URL was flagged as a likely phishing link with {confidence}% confidence. "
        )
        if reasons:
            if len(reasons) == 1:
                body = f"The main warning sign is that {reasons[0]}. "
            else:
                joined = "; ".join(reasons[:3])
                body = f"The main warning signs are that {joined}. "
        else:
            body = "Several characteristics of the address matched patterns commonly seen in phishing links. "
        advice = (
            "Do not enter any passwords, card details, or personal information on this site, "
            "and avoid clicking it if you received it unexpectedly."
        )
        return intro + body + advice

    # Legitimate verdict
    intro = (
        f"This URL appears to be legitimate, with {confidence}% confidence. "
    )
    body = (
        "Its structure matches the patterns of safe, well-established websites — "
        "it uses a normal domain name and does not show the common warning signs of phishing. "
    )
    advice = (
        "As always, still double-check the spelling of the domain before entering "
        "sensitive information, since no automated check is perfect."
    )
    return intro + body + advice


def _build_prompt(user_message: str, scan_context: dict | None,
                  reference_only: bool = False) -> str:
    """Build the Gemini prompt.

    reference_only=False  -> the scan IS the subject (used for the auto
                             explanation generated right after a scan).
    reference_only=True   -> the scan is optional background; only use it
                             if the user's question is about that URL. This
                             stops general questions from being forced
                             through the last scan result.
    """
    parts = [SYSTEM_PROMPT]

    if scan_context:
        if reference_only:
            parts.append(
                "\n\nThe user's most recent scan is provided below for REFERENCE ONLY. "
                "Use it only if the user's question is clearly about this specific URL or "
                "its result. If the user asks a general cybersecurity or phishing question, "
                "answer it directly and do not steer the answer back to this scan.\n"
                "Recent scan (reference):\n" + _format_scan(scan_context)
            )
        else:
            parts.append("\n\nScan Context:\n" + _format_scan(scan_context))

    parts.append(f"\n\nUser: {user_message}")
    return "\n".join(parts)


def get_explanation(scan_context: dict) -> str:
    """Explain a scan result. Tries Gemini, falls back to a local explanation
    so the user always sees a meaningful message after every scan."""
    try:
        model = _configure()
        prompt = _build_prompt(
            "Please explain this scan result to me in plain English, in 3-4 short sentences.",
            scan_context
        )
        response = model.generate_content(
            prompt,
            generation_config=_GEN_CONFIG,
            request_options=_REQUEST_OPTIONS,
        )
        return response.text
    except Exception as e:
        logger.warning("Gemini unavailable, using local explanation: %s", e)
        return _local_explanation(scan_context)


def chat(user_message: str, scan_context: dict | None) -> str:
    try:
        model = _configure()
        prompt = _build_prompt(user_message, scan_context, reference_only=True)
        response = model.generate_content(
            prompt,
            generation_config=_GEN_CONFIG,
            request_options=_REQUEST_OPTIONS,
        )
        return response.text
    except Exception as e:
        logger.warning("Gemini chat unavailable: %s", e)
        # If the user is clearly asking about their last scan, explain it
        # locally instead of showing a generic error.
        if scan_context and any(
            w in user_message.lower()
            for w in ("this", "result", "verdict", "url", "link", "scan", "why", "safe", "phishing")
        ):
            return _local_explanation(scan_context)
        return FALLBACK
