"""
Run this script once to train and save the Random Forest model.
Usage: python ml/train.py
"""
import sys
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.scanner.extractor import extract_features

FEATURE_COLUMNS = [
    "url_length", "hostname_length", "num_dots", "num_hyphens",
    "num_underscores", "num_slashes", "num_question_marks", "num_equals",
    "num_at", "num_ampersands", "has_ip", "has_https", "num_subdomains",
    "is_shortened", "has_suspicious_keyword", "has_port", "longest_word_length",
    "num_digits", "digit_ratio", "has_double_slash_path", "suspicious_tld",
    "domain_age_days", "domain_registration_length", "whois_success",
    "has_brand_impersonation",
]

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")


def load_dataset():
    csv_files = [f for f in os.listdir(DATASET_DIR) if f.endswith(".csv")]
    if not csv_files:
        print("No CSV files found in ml/dataset/. Generating synthetic data for demo...")
        return _generate_synthetic_data()

    frames = []
    for fname in csv_files:
        path = os.path.join(DATASET_DIR, fname)
        try:
            df = pd.read_csv(path)
            frames.append(df)
            print(f"  Loaded {len(df)} rows from {fname}")
        except Exception as e:
            print(f"  Skipping {fname}: {e}")

    if not frames:
        return _generate_synthetic_data()

    return pd.concat(frames, ignore_index=True)


def _generate_synthetic_data():
    """
    Generates a diverse synthetic dataset covering a wide range of phishing
    patterns including homoglyph attacks, brand impersonation, subdomain abuse,
    suspicious TLDs, IP-based URLs, and URL shorteners.
    """
    np.random.seed(42)

    legit_urls = [
        # Major tech
        "https://www.google.com/search?q=python+tutorial",
        "https://www.google.com/maps/place/Lagos",
        "https://mail.google.com/mail/u/0/",
        "https://drive.google.com/drive/my-drive",
        "https://github.com/torvalds/linux",
        "https://github.com/python/cpython/issues",
        "https://stackoverflow.com/questions/11227809",
        "https://stackoverflow.com/tags/python",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
        "https://docs.python.org/3/library/re.html",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://en.wikipedia.org/wiki/Machine_learning",
        # Social / media
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.youtube.com/results?search_query=flask+tutorial",
        "https://www.reddit.com/r/learnpython/",
        "https://www.reddit.com/r/netsec/",
        "https://twitter.com/home",
        "https://www.linkedin.com/in/sample-profile/",
        "https://www.instagram.com/explore/",
        # E-commerce
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://www.amazon.com/s?k=laptop",
        "https://www.ebay.com/itm/123456789",
        "https://www.ebay.com/sch/i.html?_nkw=headphones",
        # Banking / finance (legit)
        "https://www.chase.com/personal/banking",
        "https://www.wellsfargo.com/mortgage/",
        "https://www.paypal.com/myaccount/summary",
        "https://www.paypal.com/us/webapps/mpp/home",
        # News / info
        "https://www.bbc.com/news/technology",
        "https://www.reuters.com/technology/",
        "https://techcrunch.com/category/security/",
        # Developer tools
        "https://www.npmjs.com/package/express",
        "https://pypi.org/project/flask/",
        "https://hub.docker.com/_/python",
        "https://docs.aws.amazon.com/ec2/",
        # African domains (relevant to your context)
        "https://www.gtbank.com/personal-banking",
        "https://www.zenithbank.com/personal-banking/",
        "https://www.accessbankplc.com/",
        "https://www.uba.africa/",
    ]

    phish_urls = [
        # Homoglyph / typosquatting attacks
        "https://www.faceb0ok.com/login",
        "https://www.faceb00k.com/verify",
        "https://www.facebook-login.com/signin",
        "https://www.paypa1.com/signin",
        "https://www.paypa1-secure.com/account/verify",
        "https://www.paypalsecure-login.com/webscr",
        "https://www.g00gle.com/account/login",
        "https://www.googie.com/signin",
        "https://www.amaz0n.com/signin",
        "https://www.amazon-secure.com/account/update",
        "https://www.arnazon.com/login",
        "https://www.rn icrosoft.com/login".replace(" ", ""),
        "https://www.micros0ft.com/verify",
        "https://www.app1e.com/account/signin",
        "https://www.apple-id-verify.com/account",
        "https://www.netfl1x.com/login",
        "https://www.netflix-billing.com/account/update",
        # Subdomain spoofing
        "http://paypal.secure-login.com/signin",
        "http://amazon.account-update.com/verify",
        "http://apple.id-verify.com/account",
        "http://google.accounts-signin.com/auth",
        "http://chase.bank-secure.com/login",
        "http://wellsfargo.account-alert.com/verify",
        # Suspicious TLDs
        "http://secure-banking-update.tk/signin?user=123",
        "http://login-verify-account.ml/confirm",
        "http://account-suspended.ga/reactivate",
        "http://free-gift-claim.cf/win?user=victim",
        "http://paypal-refund.gq/claim",
        "http://amazon-prize.xyz/claim?id=12345",
        "http://verify-account.top/login",
        "http://bank-alert.club/secure",
        "http://update-billing.online/paypal",
        "http://account-verify.site/login",
        "http://win-prize.icu/claim",
        # IP-based URLs
        "http://192.168.1.1/login/verify/account",
        "http://10.0.0.1/banking/signin",
        "http://185.220.101.45/paypal/login",
        "http://193.238.46.120/apple/verify",
        "http://45.142.212.100/amazon/account",
        # URL shorteners leading to phishing
        "http://bit.ly/3xAbCdE",
        "http://tinyurl.com/phishlink",
        "http://t.co/fakeredirect",
        "http://ow.ly/scamlink",
        "http://is.gd/phish123",
        # Long suspicious URLs with many parameters
        "http://paypa1-confirm-account.xyz/webscr?cmd=login&dispatch=5885d80a13c0db1f8e263663d3faee8d&locale=en_US",
        "http://login.verify.secure-account.ml/password?redirect=https://paypal.com&token=abc123",
        "http://secure.amazon-account-alert.com/gp/signin?openid=1&siteState=clientContext&pageId=usflex",
        "http://appleid.apple.com.verify-account.ml/signin?returnUrl=https://apple.com",
        "http://signin.ebay.com.account-update.tk/ws/eBayISAPI.dll?SignIn&ru=https%3A%2F%2Fwww.ebay.com",
        # Suspicious keywords + bad structure
        "http://secure-login-verify.com/banking/update?account=true",
        "http://confirm-your-account.com/password/reset?token=xyz",
        "http://update-payment-info.com/signin?redirect=paypal",
        "http://verify-identity-now.com/account/banking",
        "http://account-suspended-action.com/login?user=target",
        # Custom port phishing
        "http://paypal.com.phishing.com:8080/login",
        "http://secure-banking.com:9090/signin",
        "http://account-verify.com:8443/banking",
        # African bank impersonation (contextually relevant)
        "http://gtb-alert-verify.tk/login",
        "http://zenith-bank-secure.xyz/signin",
        "http://access-bank-update.ml/verify",
        "http://uba-account-alert.ga/confirm",
        "http://firstbank-secure-login.top/account",
    ]

    _cache = {}

    def _cached_extract(url):
        if url not in _cache:
            _cache[url] = extract_features(url)
        return _cache[url]

    rows = []

    # Generate 1500 legitimate samples with variation
    for i in range(1500):
        url = legit_urls[i % len(legit_urls)]
        feats = dict(_cached_extract(url))
        feats["label"] = 0
        rows.append(feats)

    # Generate 1500 phishing samples with variation
    for i in range(1500):
        url = phish_urls[i % len(phish_urls)]
        feats = dict(_cached_extract(url))
        feats["label"] = 1
        rows.append(feats)

    return pd.DataFrame(rows)


def train():
    print("Loading dataset...")
    df = load_dataset()

    label_col = None
    for candidate in ["label", "phishing", "status", "Result", "class"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        raise ValueError(
            "Could not find a label column. "
            "Expected one of: label, phishing, status, Result, class"
        )

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        print(f"  Columns not in dataset, will extract from URL column: {missing}")
        if "url" not in df.columns and "URL" not in df.columns:
            raise ValueError("Dataset has no 'url' column to extract features from.")

        url_col = "url" if "url" in df.columns else "URL"
        print(f"  Extracting features from '{url_col}' column...")
        extracted = df[url_col].apply(lambda u: pd.Series(extract_features(str(u))))
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = extracted[col]

    X = df[FEATURE_COLUMNS].fillna(-1)
    y = df[label_col].astype(int)

    print(f"  Dataset size: {len(X)} rows | Phishing: {y.sum()} | Legit: {(y==0).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    print("Training RandomForestClassifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
