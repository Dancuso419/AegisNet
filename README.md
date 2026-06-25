# AegisNet — AI-Based Phishing Link Detection System

> A full-stack web application that classifies URLs as phishing or legitimate using a trained machine learning model, explains results with SHAP feature attribution, and provides a Gemini-powered conversational assistant for cybersecurity guidance.

**Author:** Ezenduka Johncollins  
**Institution:** Chukwuemeka Odumegwu Ojukwu University, Uli  
**Academic Level:** Final Year Project

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Tech Stack](#tech-stack)
4. [Feature Extraction Engine](#feature-extraction-engine)
5. [Machine Learning Model](#machine-learning-model)
6. [Database Schema](#database-schema)
7. [API Routes](#api-routes)
8. [Security Implementation](#security-implementation)
9. [Project Structure](#project-structure)
10. [Setup & Installation](#setup--installation)
11. [Environment Variables](#environment-variables)
12. [Training the Model](#training-the-model)
13. [Running the Application](#running-the-application)

---

## Project Overview

AegisNet is designed to detect phishing URLs in real time. A user submits a URL through the web interface; the system extracts 24 structural and domain-level features, passes them through a trained Random Forest classifier, and returns a verdict (Phishing / Legitimate) along with a confidence score and an explanation of which URL features drove the decision. A Gemini AI assistant then explains the result in plain language and answers follow-up cybersecurity questions.

---

## System Architecture

```
Browser (HTML/CSS/JS)
        │
        │  fetch() JSON API calls
        ▼
Flask Backend (Python)
  ├── Auth Blueprint    → /login  /register  /logout
  └── Scanner Blueprint → /scan   /chat      /history
            │
            ├── extractor.py  →  24 URL features (structural + WHOIS)
            ├── predictor.py  →  RandomForest + SHAP explanations
            └── assistant.py  →  Gemini AI (server-side only)
                        │
                        ├── SQLite Database  (users, scan_results)
                        └── ml/model.pkl     (trained Random Forest)
```

---

## Tech Stack

### Backend

| Technology | Version | Role | Reason for Choice |
|---|---|---|---|
| **Python** | 3.10+ | Runtime language | Industry-standard for ML/AI; rich ecosystem for both web and data science |
| **Flask** | 3.1.1 | Web framework | Lightweight, unopinionated micro-framework; ideal for a project where the ML pipeline is the core concern, not the web layer |
| **Flask-SQLAlchemy** | 3.1.1 | ORM / database abstraction | Prevents SQL injection by design; maps Python classes directly to database tables; no raw SQL strings |
| **Flask-Login** | 0.6.3 | Session-based authentication | Handles user session lifecycle (`login_user`, `logout_user`, `@login_required`) cleanly without boilerplate |
| **Flask-Bcrypt** | 1.0.1 | Password hashing | bcrypt is the recommended algorithm for password storage; computationally expensive by design, resistant to brute-force |
| **Flask-WTF** | 1.2.2 | CSRF protection | Generates and validates CSRF tokens on all state-changing requests; prevents cross-site request forgery attacks |
| **python-dotenv** | 1.0.1 | Environment variable loading | Separates secrets from source code; `.env` is git-ignored so keys are never committed |

### Machine Learning

| Technology | Version | Role | Reason for Choice |
|---|---|---|---|
| **scikit-learn** | 1.9.0 | ML framework | `RandomForestClassifier` is well-suited for tabular, mixed-type feature data; robust to outliers; no feature scaling required |
| **SHAP** | ≥0.46.0 | Model explainability | `TreeExplainer` computes exact Shapley values for tree-based models; shows *which* URL features drove each prediction — critical for user trust and interpretability |
| **pandas** | ≥2.2.0 | Data manipulation | Standard tool for loading CSV datasets and constructing feature DataFrames during training |
| **numpy** | ≥2.0.0 | Numerical operations | Required by scikit-learn and SHAP; used for array operations during feature construction |
| **joblib** | ≥1.4.0 | Model serialisation | Efficiently serialises scikit-learn estimators to `.pkl` format; supports memory-mapped loading |
| **python-whois** | 0.9.5 | Domain age lookup | Queries the WHOIS registry to retrieve domain creation and expiration dates — features that strongly indicate phishing (newly registered domains) |

### AI Assistant

| Technology | Version | Role | Reason for Choice |
|---|---|---|---|
| **google-generativeai** | 0.8.4 | Gemini API SDK | Official Python client for Google's Gemini family of LLMs; provides a clean interface for prompt-based generation |
| **Gemini Flash Lite** | `gemini-flash-lite-latest` | Language model | Chosen for its low latency (~0.9 s), separate quota pool (avoids rate limits), and sufficient capability for explanation and Q&A tasks |

### Frontend

| Technology | Role | Reason for Choice |
|---|---|---|
| **HTML5** | Page structure and semantic markup | Native browser standard; no build step required |
| **CSS3** | Styling, layout, animations | Flexbox and Grid used for all layouts; CSS custom properties for the design token system; CSS 3D transforms for the landing page hero |
| **Vanilla JavaScript** | API calls, DOM manipulation, UI state | `fetch()` API for all JSON communication; no framework dependency means the frontend is fast to load and trivial to maintain |
| **Outfit (Google Fonts)** | Primary typeface | Clean, modern grotesque; legible at small sizes for data-dense UI |
| **JetBrains Mono** | URL and code display | Monospace font prevents variable-width characters from distorting URL readability |

### Database

| Technology | Role | Reason for Choice |
|---|---|---|
| **SQLite** | Persistent storage for users and scan history | Zero-configuration, file-based; appropriate for a single-server academic project; no separate database process required; trivially portable |

---

## Feature Extraction Engine

`app/scanner/extractor.py` extracts exactly **24 features** from every submitted URL in this fixed order (order must match training column order):

| # | Feature | Type | Description |
|---|---|---|---|
| 1 | `url_length` | Integer | Total character length of the URL |
| 2 | `hostname_length` | Integer | Length of the domain/hostname portion |
| 3 | `num_dots` | Integer | Count of `.` characters |
| 4 | `num_hyphens` | Integer | Count of `-` characters |
| 5 | `num_underscores` | Integer | Count of `_` characters |
| 6 | `num_slashes` | Integer | Count of `/` characters |
| 7 | `num_question_marks` | Integer | Count of `?` characters |
| 8 | `num_equals` | Integer | Count of `=` characters |
| 9 | `num_at` | Integer | Count of `@` characters (phishing indicator) |
| 10 | `num_ampersands` | Integer | Count of `&` characters |
| 11 | `has_ip` | Binary | 1 if hostname is an IP address (IPv4 or IPv6), else 0 |
| 12 | `has_https` | Binary | 1 if scheme is `https`, else 0 |
| 13 | `num_subdomains` | Integer | Number of subdomain levels above the root domain |
| 14 | `is_shortened` | Binary | 1 if hostname matches a known URL shortener |
| 15 | `has_suspicious_keyword` | Binary | 1 if URL contains any of: `login verify secure account update banking confirm password signin webscr` |
| 16 | `has_port` | Binary | 1 if a non-standard port is explicitly specified |
| 17 | `longest_word_length` | Integer | Character length of the longest alphanumeric token |
| 18 | `num_digits` | Integer | Total digit characters in the URL |
| 19 | `digit_ratio` | Float | `num_digits / url_length` |
| 20 | `has_double_slash_path` | Binary | 1 if the URL path contains `//` |
| 21 | `suspicious_tld` | Binary | 1 if TLD is in: `.tk .ml .ga .cf .gq .xyz .top .club .online .site .icu` |
| 22 | `domain_age_days` | Integer | Days since domain was first registered (WHOIS); -1 if unavailable |
| 23 | `domain_registration_length` | Integer | Days between domain creation and expiry (WHOIS); -1 if unavailable |
| 24 | `whois_success` | Binary | 1 if WHOIS lookup succeeded, else 0 |

**WHOIS timeout handling:** On Windows, `signal.SIGALRM` is unavailable. WHOIS lookups run in a daemon `threading.Thread` with a 2-second `join(timeout=2)`. If the thread is still alive after 2 seconds, features 22–24 are set to `-1, -1, 0` and the scan continues uninterrupted.

---

## Machine Learning Model

| Parameter | Value |
|---|---|
| Algorithm | `RandomForestClassifier` |
| Estimators | 100 decision trees |
| Train/test split | 80% / 20%, stratified |
| Random state | 42 (reproducible) |
| Phishing threshold | `proba[1] >= 0.5` |
| Explainability | SHAP `TreeExplainer` — top 3 features by absolute SHAP value |
| Model file | `ml/model.pkl` (serialised with joblib) |
| Load strategy | Loaded **once at app startup** (`app/__init__.py`), not per request |

**Why Random Forest?**  
Random Forest is an ensemble of decision trees that votes on a prediction. For URL classification, it handles mixed feature types (binary flags, counts, floats) without requiring feature scaling, is resistant to overfitting through bagging, and provides native probability outputs (`predict_proba`) for the confidence score. SHAP `TreeExplainer` computes exact (not approximate) Shapley values for tree ensembles, making the explanations mathematically rigorous.

---

## Database Schema

Two tables managed through Flask-SQLAlchemy ORM. No raw SQL is used anywhere in the codebase.

**`users`**

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | Integer | Primary key | Auto-increment |
| `email` | String(150) | Unique, Not Null | Used as login identifier |
| `password_hash` | String(255) | Not Null | bcrypt hash — plaintext never stored |
| `created_at` | DateTime | Default: now | Account creation timestamp |

**`scan_results`**

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | Integer | Primary key | Auto-increment |
| `url` | Text | Not Null | Full submitted URL |
| `verdict` | String(20) | Not Null | `"Phishing"` or `"Legitimate"` |
| `confidence` | Float | Not Null | Model probability × 100 |
| `top_features` | Text | Nullable | JSON-serialised top 3 SHAP features |
| `timestamp` | DateTime | Default: now | Scan time |
| `user_id` | Integer | FK → users.id, Nullable | Null for unauthenticated scans |

---

## API Routes

| Method | Route | Auth Required | Description |
|---|---|---|---|
| `GET` | `/` | No | Landing page |
| `GET` | `/scanner` | No | URL scanner interface |
| `GET` | `/dashboard` | Yes | Analytics dashboard |
| `POST` | `/scan` | No | Submit URL; returns verdict, confidence, features, SHAP, AI explanation |
| `POST` | `/chat` | No | Send message to Gemini assistant |
| `GET` | `/history` | Yes | Last 100 scans for current user |
| `GET` | `/login` | No | Login page |
| `POST` | `/login` | No | Authenticate user |
| `GET` | `/register` | No | Registration page |
| `POST` | `/register` | No | Create account |
| `POST` | `/logout` | Yes | End session (POST-only to prevent CSRF via `<img>` tags) |

**`POST /scan` — Request/Response**

```json
// Request
{ "url": "http://secure-banking-update.tk/signin?user=123" }

// Response
{
  "url": "http://secure-banking-update.tk/signin?user=123",
  "verdict": "Phishing",
  "confidence": 94.0,
  "features": { "url_length": 47, "has_https": 0, ... },
  "top_features": [
    { "feature": "suspicious_tld", "shap_value": 0.312 },
    { "feature": "has_suspicious_keyword", "shap_value": 0.287 },
    { "feature": "has_https", "shap_value": -0.201 }
  ],
  "assistant_message": "This URL was flagged as phishing. The domain uses a .tk TLD..."
}
```

---

## Security Implementation

| Threat | Mitigation |
|---|---|
| Hardcoded secrets | All secrets in `.env`; loaded via `python-dotenv`; `.env` is git-ignored |
| CSRF attacks | Flask-WTF `CSRFProtect` globally enabled; forms carry hidden `csrf_token`; fetch calls include `X-CSRFToken` header |
| SQL injection | SQLAlchemy ORM used exclusively; parameterised queries by design; no raw SQL string formatting |
| Password exposure | bcrypt hashing (cost factor 12) before storage; plaintext never persisted |
| Session hijacking | `SESSION_COOKIE_HTTPONLY=True`; `SESSION_COOKIE_SAMESITE=Lax`; `SESSION_COOKIE_SECURE=True` in production |
| API key exposure | Gemini API called server-side only; key never returned in any HTTP response or rendered in any template |
| Unauthorised access | `@login_required` on dashboard and history routes |
| WHOIS DoS | 2-second threading timeout; failure returns safe defaults, never crashes the request |
| URL injection | `urllib.parse.urlparse` validates structure before any processing; returns HTTP 400 on invalid input |

---

## Project Structure

```
AegisNet/
├── app/
│   ├── __init__.py          # App factory, extensions (db, login, csrf, bcrypt)
│   ├── models.py            # SQLAlchemy models: User, ScanResult
│   ├── auth/
│   │   ├── __init__.py
│   │   └── routes.py        # /login, /register, /logout
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── routes.py        # /scan, /chat, /history, /dashboard, /
│   │   ├── extractor.py     # 24-feature URL extraction engine
│   │   ├── predictor.py     # Model loader + SHAP inference
│   │   └── assistant.py     # Gemini API integration
│   ├── static/
│   │   ├── css/
│   │   │   ├── main.css     # App UI (scanner, dashboard, history)
│   │   │   └── landing.css  # Landing page styles + 3D animations
│   │   └── js/
│   │       ├── main.js      # Scanner UI, chat, drawer, result rendering
│   │       └── landing.js   # Parallax, scroll reveals, stat counters
│   └── templates/
│       ├── base.html        # Shared layout: sidebar, topbar, flash messages
│       ├── landing.html     # Public landing page
│       ├── index.html       # URL scanner (infographic results panel)
│       ├── dashboard.html   # Analytics: donut chart, live feed
│       ├── history.html     # Scan history table
│       ├── login.html
│       └── register.html
├── ml/
│   ├── train.py             # Training script: loads dataset, trains, saves model.pkl
│   ├── dataset/             # Place CSV datasets here before training
│   └── model.pkl            # Serialised trained model (git-ignored)
├── .env                     # Secret keys (git-ignored)
├── .gitignore
├── config.py                # Flask config class (reads from environment)
├── requirements.txt
└── run.py                   # Entry point
```

---

## Setup & Installation

### Prerequisites

- Python 3.10 or higher
- pip

### 1. Clone the repository

```bash
git clone https://github.com/Dancuso419/AegisNet.git
cd AegisNet
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install --prefer-binary -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```env
SECRET_KEY=your_random_secret_key_here
DATABASE_URL=sqlite:///aegisnet.db
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-flash-lite-latest
FLASK_DEBUG=1
```

Get a free Gemini API key at: https://aistudio.google.com/apikey

---

## Training the Model

```bash
python ml/train.py
```

This will:
1. Look for CSV files in `ml/dataset/`
2. If none are found, generate a minimal synthetic dataset (sufficient for a demo)
3. Train a `RandomForestClassifier` on 80% of the data
4. Print accuracy and a classification report on the 20% test split
5. Save the model to `ml/model.pkl`

For production accuracy, download a real phishing dataset (e.g. PhishTank, ISCX-URL-2016) and place the CSV in `ml/dataset/` before running the training script.

---

## Running the Application

```bash
python run.py
```

Open `http://127.0.0.1:5000` in your browser.

The application will:
- Load `ml/model.pkl` and the SHAP explainer once at startup
- Create the SQLite database and tables automatically on first run
- Be ready to accept URL scans immediately

---

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Flask session signing key — use a long random string |
| `DATABASE_URL` | No | SQLAlchemy database URI (default: `sqlite:///aegisnet.db`) |
| `GEMINI_API_KEY` | Yes | Google Gemini API key |
| `GEMINI_MODEL` | No | Gemini model ID (default: `gemini-flash-lite-latest`) |
| `FLASK_DEBUG` | No | Set to `1` for development hot-reload; `0` for production |
