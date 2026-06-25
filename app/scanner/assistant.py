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

FALLBACK = "I am having trouble connecting right now. Please try again in a moment."


def _configure():
    genai.configure(api_key=current_app.config["GEMINI_API_KEY"])
    return genai.GenerativeModel(current_app.config["GEMINI_MODEL"])


def _format_scan(scan_context: dict) -> str:
    return (
        f"URL: {scan_context.get('url')}\n"
        f"Verdict: {scan_context.get('verdict')}\n"
        f"Confidence: {scan_context.get('confidence')}%\n"
        f"Top contributing features: {scan_context.get('top_features')}"
    )


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
        logger.error("Gemini get_explanation failed: %s", e, exc_info=True)
        return FALLBACK


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
        logger.error("Gemini chat failed: %s", e, exc_info=True)
        return FALLBACK
