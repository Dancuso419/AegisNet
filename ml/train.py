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
    Generates a minimal synthetic dataset when no real CSV is available.
    Replace with a real dataset (e.g. PhishTank, ISCX-URL-2016) for production.
    """
    np.random.seed(42)
    n = 2000

    legit_urls = [
        "https://www.google.com/search?q=hello",
        "https://github.com/user/repo",
        "https://stackoverflow.com/questions/12345",
        "https://en.wikipedia.org/wiki/Python",
        "https://docs.python.org/3/library/urllib.html",
    ]
    phish_urls = [
        "http://192.168.1.1/login/verify/account",
        "http://secure-banking-update.tk/signin?user=123",
        "http://bit.ly/3xAbCdE",
        "http://paypa1-confirm-account.xyz/webscr",
        "http://login.verify.secure-account.ml/password",
    ]

    # Extract features once per unique URL, then replicate rows
    _cache = {}
    def _cached_extract(url):
        if url not in _cache:
            _cache[url] = extract_features(url)
        return _cache[url]

    rows = []
    for _ in range(n // 2):
        url = legit_urls[np.random.randint(len(legit_urls))]
        feats = dict(_cached_extract(url))
        feats["label"] = 0
        rows.append(feats)

    for _ in range(n // 2):
        url = phish_urls[np.random.randint(len(phish_urls))]
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
