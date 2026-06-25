\# Technical Requirements Document (TRD)  
\#\# AegisNet: AI-Based Phishing Link Detection System with Intelligent Assistant

\*\*Version:\*\* 1.0  
\*\*Author:\*\* Ezenduka Johncollins  
\*\*Date:\*\* April 2026  
\*\*Institution:\*\* Chukwuemeka Odumegwu Ojukwu University, Uli

\---

\#\# 1\. System Architecture Overview

AegisNet follows a three-tier architecture:

\- \*\*Presentation Tier:\*\* HTML5/CSS3/JavaScript frontend served by Flask  
\- \*\*Application Tier:\*\* Flask backend handling routing, feature extraction, ML inference, and Gemini API communication  
\- \*\*Data Tier:\*\* SQLite database storing users and scan results, plus a joblib .pkl file for the trained model

All tiers run on a single server process for this academic deployment.

\---

\#\# 2\. Project Structure

aegisnet/ ├── app/ │ ├── **init**.py │ ├── models.py │ ├── auth/ │ │ ├── **init**.py │ │ └── routes.py │ ├── scanner/ │ │ ├── **init**.py │ │ ├── routes.py │ │ ├── extractor.py │ │ ├── predictor.py │ │ └── assistant.py │ ├── static/ │ │ ├── css/ │ │ │ └── main.css │ │ └── js/ │ │ └── main.js │ └── templates/ │ ├── base.html │ ├── index.html │ ├── history.html │ ├── login.html │ └── register.html ├── ml/ │ ├── train.py │ ├── dataset/ │ └── model.pkl ├── .env ├── config.py ├── requirements.txt └── run.py

\---

\#\# 3\. Environment Setup

\#\#\# 3.1 Python Version  
Python 3.10 or higher required.

\#\#\# 3.2 Dependencies — requirements.txt

flask flask-login flask-bcrypt flask-sqlalchemy python-dotenv scikit-learn shap pandas numpy joblib python-whois google-generativeai

\#\#\# 3.3 Environment Variables — .env

SECRET\_KEY=your\_flask\_secret\_key\_here DATABASE\_URL=sqlite:///aegisnet.db GEMINI\_API\_KEY=your\_gemini\_api\_key\_here GEMINI\_MODEL=gemini-1.5-flash

\---

\#\# 4\. Configuration — config.py

\`\`\`python  
import os  
from dotenv import load\_dotenv

load\_dotenv()

class Config:  
    SECRET\_KEY \= os.getenv("SECRET\_KEY", "fallback-secret-key")  
    SQLALCHEMY\_DATABASE\_URI \= os.getenv("DATABASE\_URL", "sqlite:///aegisnet.db")  
    SQLALCHEMY\_TRACK\_MODIFICATIONS \= False  
    GEMINI\_API\_KEY \= os.getenv("GEMINI\_API\_KEY")  
    GEMINI\_MODEL \= os.getenv("GEMINI\_MODEL", "gemini-1.5-flash")

---

## **5\. Database Models — app/models.py**

from app import db  
from flask\_login import UserMixin  
from datetime import datetime

class User(UserMixin, db.Model):  
    \_\_tablename\_\_ \= "users"  
    id \= db.Column(db.Integer, primary\_key=True)  
    email \= db.Column(db.String(150), unique=True, nullable=False)  
    password\_hash \= db.Column(db.String(255), nullable=False)  
    created\_at \= db.Column(db.DateTime, default=datetime.utcnow)  
    scans \= db.relationship("ScanResult", backref="user", lazy=True)

class ScanResult(db.Model):  
    \_\_tablename\_\_ \= "scan\_results"  
    id \= db.Column(db.Integer, primary\_key=True)  
    user\_id \= db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  
    url \= db.Column(db.String(2048), nullable=False)  
    verdict \= db.Column(db.String(20), nullable=False)  
    confidence \= db.Column(db.Float, nullable=False)  
    features\_json \= db.Column(db.Text, nullable=False)  
    shap\_json \= db.Column(db.Text, nullable=False)  
    timestamp \= db.Column(db.DateTime, default=datetime.utcnow)

---

## **6\. Feature Extraction — app/scanner/extractor.py**

### **6.1 Responsibilities**

* Accept a raw URL string as input  
* Compute all required features  
* Return a Python dict in model-ready feature order

### **6.2 Feature List and Extraction Logic**

| Feature | Type | Extraction Method |
| ----- | ----- | ----- |
| url\_length | int | len(url) |
| hostname\_length | int | len(parsed.hostname) |
| num\_dots | int | url.count('.') |
| num\_hyphens | int | url.count('-') |
| num\_underscores | int | url.count('\_') |
| num\_slashes | int | url.count('/') |
| num\_question\_marks | int | url.count('?') |
| num\_equals | int | url.count('=') |
| num\_at | int | url.count('@') |
| num\_ampersands | int | url.count('&') |
| has\_ip | binary | regex match on hostname for IP pattern |
| has\_https | binary | 1 if scheme \== https else 0 |
| num\_subdomains | int | count dots in hostname minus 1 |
| is\_shortened | binary | hostname in SHORTENER\_LIST |
| has\_suspicious\_keyword | binary | any keyword found in url.lower() |
| has\_port | binary | 1 if parsed.port else 0 |
| longest\_word\_length | int | max(len(w) for w in re.split on url) |
| num\_digits | int | sum(c.isdigit() for c in url) |
| digit\_ratio | float | num\_digits / url\_length |
| has\_double\_slash\_path | binary | // in parsed.path |
| suspicious\_tld | binary | tld in SUSPICIOUS\_TLD\_LIST |
| domain\_age\_days | int | days since domain creation via WHOIS; \-1 if unavailable |
| domain\_registration\_length | int | days between creation and expiry; \-1 if unavailable |
| whois\_success | binary | 1 if WHOIS returned data else 0 |

### **6.3 Constants**

SHORTENER\_LIST \= \[  
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",  
    "ow.ly", "is.gd", "buff.ly", "adf.ly"  
\]

SUSPICIOUS\_KEYWORDS \= \[  
    "login", "verify", "secure", "account", "update",  
    "banking", "confirm", "password", "signin", "webscr"  
\]

SUSPICIOUS\_TLDS \= \[  
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",  
    ".top", ".club", ".online", ".site", ".icu"  
\]

### **6.4 WHOIS Timeout Handling**

WHOIS lookups must be wrapped in a try/except with a 2-second timeout. If the lookup fails or times out, domain\_age\_days and domain\_registration\_length default to \-1 and whois\_success is set to 0\. The scan must never fail because of a WHOIS error.

### **6.5 Output Format**

def extract\_features(url: str) \-\> dict:  
    \# returns ordered dict of all 24 features  
    \# keys match exactly the column names used during model training

---

## **7\. ML Model — app/scanner/predictor.py**

### **7.1 Model Training — ml/train.py**

The training script must:

1. Load the dataset CSV  
2. Run the feature extractor on every URL in the dataset  
3. Split into 80% train / 20% test (stratified, random\_state=42)  
4. Train a RandomForestClassifier(n\_estimators=100, random\_state=42)  
5. Evaluate on the test set and print accuracy, precision, recall, F1-score  
6. Save the trained model using joblib.dump(model, "ml/model.pkl")

### **7.2 Model Loading**

import joblib

MODEL\_PATH \= "ml/model.pkl"  
model \= joblib.load(MODEL\_PATH)

The model is loaded once at application startup and reused for all requests.

### **7.3 Inference**

def predict(features: dict) \-\> dict:  
    feature\_vector \= \[features\[k\] for k in FEATURE\_ORDER\]  
    proba \= model.predict\_proba(\[feature\_vector\])\[0\]  
    verdict \= "Phishing" if proba\[1\] \>= 0.5 else "Legitimate"  
    confidence \= round(float(max(proba)) \* 100, 2\)  
    return {"verdict": verdict, "confidence": confidence}

### **7.4 SHAP Explanation**

import shap

explainer \= shap.TreeExplainer(model)

def get\_top\_shap\_features(features: dict, n=3) \-\> list:  
    feature\_vector \= \[features\[k\] for k in FEATURE\_ORDER\]  
    shap\_values \= explainer.shap\_values(\[feature\_vector\])  
    shap\_scores \= dict(zip(FEATURE\_ORDER, shap\_values\[1\]\[0\]))  
    top \= sorted(shap\_scores.items(), key=lambda x: abs(x\[1\]), reverse=True)\[:n\]  
    return \[{"feature": k, "value": features\[k\], "shap": v} for k, v in top\]

The SHAP explainer is loaded once at startup alongside the model.

---

## **8\. Gemini Assistant — app/scanner/assistant.py**

### **8.1 Initialisation**

import google.generativeai as genai  
from flask import current\_app

def get\_gemini\_model():  
    genai.configure(api\_key=current\_app.config\["GEMINI\_API\_KEY"\])  
    return genai.GenerativeModel(current\_app.config\["GEMINI\_MODEL"\])

### **8.2 System Prompt**

SYSTEM\_PROMPT \= """  
You are AegisNet Assistant, a cybersecurity AI embedded in the AegisNet  
phishing link detection platform. Your job is to help users understand  
phishing threats, explain URL scan results in plain language, and answer  
cybersecurity questions. Always be clear, concise, and friendly. Avoid  
technical jargon unless the user specifically asks for technical detail.  
Never make up scan results — only explain results that are explicitly  
provided to you in the scan context below.  
"""

### **8.3 Context Injection**

def build\_prompt(user\_message: str, scan\_context: dict \= None) \-\> str:  
    prompt \= SYSTEM\_PROMPT  
    if scan\_context:  
        prompt \+= f"""  
\[SCAN CONTEXT\]  
URL: {scan\_context\['url'\]}  
Verdict: {scan\_context\['verdict'\]}  
Confidence: {scan\_context\['confidence'\]}%  
Top contributing features:  
1\. {scan\_context\['top\_features'\]\[0\]\['feature'\]}: {scan\_context\['top\_features'\]\[0\]\['value'\]}  
2\. {scan\_context\['top\_features'\]\[1\]\['feature'\]}: {scan\_context\['top\_features'\]\[1\]\['value'\]}  
3\. {scan\_context\['top\_features'\]\[2\]\['feature'\]}: {scan\_context\['top\_features'\]\[2\]\['value'\]}  
"""  
    prompt \+= f"\\nUser: {user\_message}"  
    return prompt

### **8.4 API Call**

def chat(user\_message: str, scan\_context: dict \= None) \-\> str:  
    try:  
        model \= get\_gemini\_model()  
        prompt \= build\_prompt(user\_message, scan\_context)  
        response \= model.generate\_content(prompt)  
        return response.text  
    except Exception as e:  
        return "I am having trouble connecting right now. Please try again in a moment."

### **8.5 Session History**

Chat history is stored in the Flask session as a list of dicts with role and text keys. The frontend renders this history on every page load and appends new messages via JavaScript without a page reload.

---

## **9\. Routes — app/scanner/routes.py**

### **9.1 POST /scan**

**Request:** JSON {"url": "https://example.com"}

**Process:**

1. Validate URL format using urllib.parse  
2. Run extract\_features(url)  
3. Run predict(features)  
4. Run get\_top\_shap\_features(features)  
5. Save ScanResult to database (user\_id nullable)  
6. Store scan context in Flask session  
7. Auto-trigger assistant explanation by calling chat("Explain this scan result.", scan\_context)

**Response:**

{  
  "url": "https://example.com",  
  "verdict": "Legitimate",  
  "confidence": 94.3,  
  "features": {},  
  "top\_features": \[\],  
  "assistant\_message": "This URL appears to be legitimate because..."  
}

### **9.2 POST /chat**

**Request:** JSON {"message": "What is phishing?"}

**Process:**

1. Retrieve scan context from Flask session if it exists  
2. Call chat(message, scan\_context)  
3. Append user message and assistant response to session history

**Response:**

{  
  "response": "Phishing is a type of cyberattack where..."  
}

### **9.3 GET /history**

* Requires login  
* Queries last 100 ScanResult records for current user ordered by timestamp desc  
* Renders history.html with results

---

## **10\. Auth Routes — app/auth/routes.py**

### **10.1 POST /register**

* Validate email format and password minimum length of 8 characters  
* Check email does not already exist in database  
* Hash password with bcrypt  
* Create User record  
* Redirect to login

### **10.2 POST /login**

* Look up user by email  
* Verify password hash with bcrypt  
* Create Flask-Login session  
* Redirect to home

### **10.3 GET /logout**

* Clear Flask-Login session  
* Redirect to home

---

## **11\. Frontend — app/static/js/main.js**

### **11.1 Scan Flow**

1. User enters URL and clicks Scan  
2. JavaScript sends POST /scan with JSON body via fetch API  
3. Loading spinner shown on scan button  
4. On response: render verdict badge, confidence score, feature table  
5. Assistant message from response automatically appended to chat panel  
6. Loading spinner removed

### **11.2 Chat Flow**

1. User types message and clicks Send or presses Enter  
2. User message bubble immediately appended to chat panel  
3. JavaScript sends POST /chat with JSON body via fetch API  
4. Typing indicator shown in chat panel  
5. On response: assistant message bubble appended  
6. Typing indicator removed  
7. Chat panel scrolls to bottom

### **11.3 Verdict Badge Logic**

if (verdict \=== "Phishing") {  
    badge.classList.add("badge-danger");  
    badge.textContent \= "PHISHING DETECTED";  
} else {  
    badge.classList.add("badge-safe");  
    badge.textContent \= "LEGITIMATE";  
}

---

## **12\. UI Design Specifications**

* **Color Palette:**

  * Background: \#0d1117  
  * Surface: \#161b22  
  * Primary accent: \#00d4aa  
  * Danger: \#ff4444  
  * Safe: \#00cc66  
  * Text primary: \#e6edf3  
  * Text secondary: \#8b949e  
* **Layout:** Two-column on desktop — scanner panel left (60%), chat panel right (40%). Single column stacked on mobile.

* **Font:** Inter or system-sans-serif

* **Chat bubbles:** User messages right-aligned, assistant messages left-aligned

* **Verdict badge:** Large, centered, bold, color-coded

---

## **13\. Application Entry Point — run.py**

from app import create\_app

app \= create\_app()

if \_\_name\_\_ \== "\_\_main\_\_":  
    app.run(debug=True)

---

## **14\. App Factory — app/init.py**

from flask import Flask  
from flask\_sqlalchemy import SQLAlchemy  
from flask\_login import LoginManager  
from flask\_bcrypt import Bcrypt  
from config import Config

db \= SQLAlchemy()  
login\_manager \= LoginManager()  
bcrypt \= Bcrypt()

def create\_app():  
    app \= Flask(\_\_name\_\_)  
    app.config.from\_object(Config)

    db.init\_app(app)  
    login\_manager.init\_app(app)  
    bcrypt.init\_app(app)

    login\_manager.login\_view \= "auth.login"

    from app.auth.routes import auth  
    from app.scanner.routes import scanner  
    app.register\_blueprint(auth)  
    app.register\_blueprint(scanner)

    with app.app\_context():  
        db.create\_all()

    return app

---

## **15\. Testing Requirements**

| Test | Method | Pass Criteria |
| ----- | ----- | ----- |
| Feature extraction | Unit test each feature against known URLs | Correct binary/numeric values returned |
| Model accuracy | Evaluate on 20% test split | Accuracy \>= 96% |
| /scan endpoint | Send known phishing and legitimate URLs | Correct verdict returned |
| /chat endpoint | Send messages with and without scan context | Valid Gemini response returned |
| Auth flow | Register, login, logout sequence | Session created and destroyed correctly |
| History isolation | Two users scan different URLs | Each sees only their own history |
| WHOIS failure | Scan URL with unavailable WHOIS | Scan completes, domain\_age\_days \= \-1 |
| Invalid URL | Submit malformed string | 400 error returned, no crash |

---

## **16\. Security Checklist**

* GEMINI\_API\_KEY never returned in any API response or rendered in any template  
* All database queries use SQLAlchemy ORM with no raw SQL string interpolation  
* Passwords stored as bcrypt hashes only  
* Flask SECRET\_KEY loaded from environment and never hardcoded  
* User scan history protected by login\_required decorator  
* URL input sanitised before processing

