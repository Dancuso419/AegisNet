import re
import socket
from urllib.parse import urlparse
import whois
from datetime import datetime, timezone

SHORTENER_LIST = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "adf.ly"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "banking", "confirm", "password", "signin", "webscr"
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
    ".top", ".club", ".online", ".site", ".icu"
]


def _is_ip(hostname: str) -> int:
    try:
        socket.inet_aton(hostname)
        return 1
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, hostname)
        return 1
    except (socket.error, OSError):
        return 0


def _whois_info(domain: str):
    try:
        import threading
        result = [None]
        exc = [None]

        def _do_whois():
            try:
                result[0] = whois.whois(domain)
            except Exception as e:
                exc[0] = e

        t = threading.Thread(target=_do_whois, daemon=True)
        t.start()
        t.join(timeout=2)

        if t.is_alive() or exc[0] is not None:
            return -1, -1, 0

        w = result[0]

        creation = w.creation_date
        expiration = w.expiration_date

        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiration, list):
            expiration = expiration[0]

        now = datetime.now(timezone.utc)

        if creation and hasattr(creation, 'year'):
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (now - creation).days
        else:
            age_days = -1

        if creation and expiration and hasattr(expiration, 'year'):
            if expiration.tzinfo is None:
                expiration = expiration.replace(tzinfo=timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            reg_length = (expiration - creation).days
        else:
            reg_length = -1

        return age_days, reg_length, 1

    except Exception:
        return -1, -1, 0


def extract_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_url = url.lower()

    url_length = len(url)
    hostname_length = len(hostname)
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_underscores = url.count("_")
    num_slashes = url.count("/")
    num_question_marks = url.count("?")
    num_equals = url.count("=")
    num_at = url.count("@")
    num_ampersands = url.count("&")

    has_ip = _is_ip(hostname)
    has_https = 1 if parsed.scheme == "https" else 0

    parts = hostname.split(".")
    num_subdomains = max(len(parts) - 2, 0) if len(parts) > 2 else 0

    is_shortened = 1 if any(s in hostname for s in SHORTENER_LIST) else 0
    has_suspicious_keyword = 1 if any(kw in full_url for kw in SUSPICIOUS_KEYWORDS) else 0
    has_port = 1 if parsed.port is not None else 0

    words = re.split(r"[\W_]+", url)
    words = [w for w in words if w]
    longest_word_length = max((len(w) for w in words), default=0)

    num_digits = sum(c.isdigit() for c in url)
    digit_ratio = num_digits / url_length if url_length > 0 else 0

    has_double_slash_path = 1 if "//" in path else 0

    suspicious_tld = 1 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    domain_age_days, domain_registration_length, whois_success = _whois_info(domain)

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_question_marks": num_question_marks,
        "num_equals": num_equals,
        "num_at": num_at,
        "num_ampersands": num_ampersands,
        "has_ip": has_ip,
        "has_https": has_https,
        "num_subdomains": num_subdomains,
        "is_shortened": is_shortened,
        "has_suspicious_keyword": has_suspicious_keyword,
        "has_port": has_port,
        "longest_word_length": longest_word_length,
        "num_digits": num_digits,
        "digit_ratio": digit_ratio,
        "has_double_slash_path": has_double_slash_path,
        "suspicious_tld": suspicious_tld,
        "domain_age_days": domain_age_days,
        "domain_registration_length": domain_registration_length,
        "whois_success": whois_success,
    }
