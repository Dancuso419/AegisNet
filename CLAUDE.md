# **CLAUDE.md**

## **AegisNet — Coding Agent Instructions**

**Version:** 1.0 **Project:** AegisNet: AI-Based Phishing Link Detection System with Intelligent Assistant **Author:** Ezenduka Johncollins **Institution:** Chukwuemeka Odumegwu Ojukwu University, Uli

---

## **1\. What You Are Building**

AegisNet is a web-based phishing link detection system. It accepts a URL, extracts structural features from it, classifies it as phishing or legitimate using a trained Random Forest machine learning model, and presents the result through a Gemini-powered conversational assistant that explains the verdict in plain English.

You are responsible for building the entire system end to end — from the ML training script to the Flask backend to the HTML/CSS/JS frontend. Follow every instruction in this file exactly. Do not deviate from the architecture, file structure, tech stack, or design specifications defined here.

---

## **2\. Project Structure**

Create the project exactly as shown below. Do not add extra folders or files unless explicitly required by a dependency.

aegisnet/  
├── app/  
│   ├── \_\_init\_\_.py  
│   ├── models.py  
│   ├── auth/  
│   │   ├── \_\_init\_\_.py  
│   │   └── routes.py  
│   ├── scanner/  
│   │   ├── \_\_init\_\_.py  
│   │   ├── routes.py  
│   │   ├── extractor.py  
│   │   ├── predictor.py  
│   │   └── assistant.py  
│   ├── static/  
│   │   ├── css/  
│   │   │   └── main.css  
│   │   └── js/  
│   │       └── main.js  
│   └── templates/  
│       ├── base.html  
│       ├── index.html  
│       ├── history.html  
│       ├── login.html  
│       └── register.html  
├── ml/  
│   ├── train.py  
│   ├── dataset/  
│   └── model.pkl  
├── .env  
├── config.py  
├── requirements.txt  
└── run.py

---

## **3\. Tech Stack**

Do not substitute any technology in this list.

| Layer | Technology |
| ----- | ----- |
| Backend | Python 3.10+, Flask |
| ML | scikit-learn, SHAP, pandas, numpy, joblib |
| WHOIS | python-whois |
| AI Assistant | Google Gemini API, google-generativeai Python SDK |
| Frontend | HTML5, CSS3, vanilla JavaScript only — no React, no Vue, no jQuery |
| Database | SQLite via Flask-SQLAlchemy |
| Auth | Flask-Login, Flask-Bcrypt |
| Environment | python-dotenv |
| Model Storage | joblib .pkl file |

---

## **4\. Environment Variables**

Create a .env file in the project root with these keys. Never hardcode any of these values anywhere in the codebase.

SECRET\_KEY=your\_flask\_secret\_key\_here  
DATABASE\_URL=sqlite:///aegisnet.db  
GEMINI\_API\_KEY=your\_gemini\_api\_key\_here  
GEMINI\_MODEL=gemini-1.5-flash

---

## **5\. Build Order**

Build the system in this exact order. Do not skip steps.

1. config.py  
2. requirements.txt  
3. app/**init**.py (app factory)  
4. app/models.py (User and ScanResult)  
5. app/auth/**init**.py and app/auth/routes.py  
6. app/scanner/extractor.py (feature extraction engine)  
7. ml/train.py (model training script)  
8. app/scanner/predictor.py (model loader and SHAP inference)  
9. app/scanner/assistant.py (Gemini integration)  
10. app/scanner/routes.py (/scan, /chat, /history)  
11. app/templates/ (all HTML templates)  
12. app/static/css/main.css  
13. app/static/js/main.js  
14. run.py

---

## **6\. Feature Extraction Rules**

Implement exactly these 24 features in extractor.py in exactly this order. The order must match the column order used during model training.

1\.  url\_length  
2\.  hostname\_length  
3\.  num\_dots  
4\.  num\_hyphens  
5\.  num\_underscores  
6\.  num\_slashes  
7\.  num\_question\_marks  
8\.  num\_equals  
9\.  num\_at  
10\. num\_ampersands  
11\. has\_ip  
12\. has\_https  
13\. num\_subdomains  
14\. is\_shortened  
15\. has\_suspicious\_keyword  
16\. has\_port  
17\. longest\_word\_length  
18\. num\_digits  
19\. digit\_ratio  
20\. has\_double\_slash\_path  
21\. suspicious\_tld  
22\. domain\_age\_days  
23\. domain\_registration\_length  
24\. whois\_success

WHOIS lookups must be wrapped in try/except with a 2-second timeout. If WHOIS fails, set domain\_age\_days \= \-1, domain\_registration\_length \= \-1, whois\_success \= 0\. Never let a WHOIS failure crash the scan.

Use these exact constants:

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

---

## **7\. ML Model Rules**

* Algorithm: RandomForestClassifier(n\_estimators=100, random\_state=42)  
* Train/test split: 80/20, stratified, random\_state=42  
* Save model with: joblib.dump(model, "ml/model.pkl")  
* Load model once at app startup, not on every request  
* Load SHAP TreeExplainer once at app startup, not on every request  
* Phishing threshold: proba\[1\] \>= 0.5  
* Always return top 3 SHAP features sorted by absolute SHAP value descending

---

## **8\. Gemini Integration Rules**

* Initialise Gemini using: genai.configure(api\_key=current\_app.config\["GEMINI\_API\_KEY"\])  
* Use model: current\_app.config\["GEMINI\_MODEL"\]  
* Always include the system prompt in every API call  
* Always inject scan context into the prompt when a scan result exists in session  
* Wrap every Gemini API call in try/except  
* On Gemini API failure return: "I am having trouble connecting right now. Please try again in a moment."  
* Never expose GEMINI\_API\_KEY to the frontend under any circumstance  
* The /chat route must call Gemini server-side only

The system prompt to use verbatim:

You are AegisNet Assistant, a cybersecurity AI embedded in the AegisNet  
phishing link detection platform. Your job is to help users understand  
phishing threats, explain URL scan results in plain language, and answer  
cybersecurity questions. Always be clear, concise, and friendly. Avoid  
technical jargon unless the user specifically asks for technical detail.  
Never make up scan results — only explain results that are explicitly  
provided to you in the scan context below.

---

## **9\. Route Specifications**

### **POST /scan**

* Accept JSON: {"url": "https://example.com"}  
* Validate URL with urllib.parse before processing  
* Return 400 JSON error if URL is invalid  
* Run feature extraction, model inference, SHAP explanation  
* Save ScanResult to database (user\_id is nullable for unauthenticated users)  
* Store scan context in Flask session  
* Call Gemini to auto-generate an explanation and include it in the response  
* Return JSON with: url, verdict, confidence, features, top\_features, assistant\_message

### **POST /chat**

* Accept JSON: {"message": "user message here"}  
* Retrieve scan context from Flask session if it exists  
* Call Gemini with message and scan context  
* Append both user message and assistant response to session chat history  
* Return JSON with: response

### **GET /history**

* Requires @login\_required  
* Return last 100 scans for current user ordered by timestamp descending  
* Render history.html

### **POST /register**

* Validate email format  
* Validate password minimum 8 characters  
* Check email uniqueness  
* Hash password with bcrypt before saving  
* Redirect to /login on success

### **POST /login**

* Look up user by email  
* Check password with bcrypt  
* Create login session  
* Redirect to / on success

### **GET /logout**

* Clear session  
* Redirect to /

---

## **10\. Frontend Rules**

* Use only vanilla JavaScript. No external JS libraries or frameworks.  
* All API calls from the frontend use the fetch API with JSON bodies and JSON responses.  
* The scan result panel updates without a page reload.  
* The chat panel updates without a page reload.  
* Show a loading spinner on the Scan button while /scan is processing.  
* Show a typing indicator in the chat panel while /chat is processing.  
* Auto-scroll the chat panel to the bottom after every new message.  
* Render the assistant's auto-explanation in the chat panel immediately after a scan completes.

---

## **11\. UI Design Rules**

Apply these design rules in main.css. Do not use any CSS framework.

Background color:     \#0d1117  
Surface color:        \#161b22  
Primary accent:       \#00d4aa  
Danger color:         \#ff4444  
Safe color:           \#00cc66  
Text primary:         \#e6edf3  
Text secondary:       \#8b949e  
Font:                 Inter, system-ui, sans-serif

Layout rules:

* Desktop: two-column layout, scanner panel 60% left, chat panel 40% right  
* Mobile: single column, scanner panel on top, chat panel below  
* Use CSS flexbox or grid for layout  
* Verdict badge must be large, bold, centered, and color-coded (red for Phishing, green for Legitimate)  
* User chat bubbles are right-aligned with accent background  
* Assistant chat bubbles are left-aligned with surface background

---

## **12\. Security Rules**

These rules are non-negotiable. Violating any of them is a critical error.

* Never hardcode SECRET\_KEY, GEMINI\_API\_KEY, or DATABASE\_URL anywhere in source code  
* Never return GEMINI\_API\_KEY in any HTTP response  
* Never render GEMINI\_API\_KEY in any HTML template  
* Use SQLAlchemy ORM for all database operations — no raw SQL string formatting  
* Hash all passwords with bcrypt before storing — never store plaintext passwords  
* Protect all user-specific routes with @login\_required  
* Sanitise URL input before passing to extractor

---

## **13\. Error Handling Rules**

* Invalid URL submitted to /scan: return HTTP 400 with JSON {"error": "Invalid URL"}  
* WHOIS lookup failure: silently use default values, do not return an error to the user  
* Gemini API failure: return the fallback message string, do not crash the request  
* Model file not found at startup: raise a clear RuntimeError with instructions to run ml/train.py first  
* Database error: return HTTP 500 with JSON {"error": "Database error"}

---

## **14\. What Not To Do**

* Do not use React, Vue, Angular, or any JavaScript framework  
* Do not use Bootstrap, Tailwind, or any CSS framework  
* Do not call the Gemini API from the frontend JavaScript  
* Do not store the Gemini API key in any JavaScript file or HTML template  
* Do not use raw SQL queries  
* Do not store plaintext passwords  
* Do not load the ML model or SHAP explainer on every request — load once at startup  
* Do not let WHOIS failures crash or block scans  
* Do not add features, pages, or routes not defined in this document  
* Do not use any database other than SQLite for this project

