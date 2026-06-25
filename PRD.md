\# Product Requirements Document (PRD)  
\#\# AegisNet: AI-Based Phishing Link Detection System with Intelligent Assistant

\*\*Version:\*\* 1.0  
\*\*Author:\*\* Ezenduka Johncollins  
\*\*Date:\*\* April 2026  
\*\*Institution:\*\* Chukwuemeka Odumegwu Ojukwu University, Uli

\---

\#\# 1\. Product Overview

AegisNet is a web-based application that accepts a URL as input, classifies it as phishing or legitimate using a trained machine learning model, and presents the result through a conversational intelligent assistant powered by the Gemini API. The assistant explains the verdict in plain English, answers cybersecurity questions, and guides users through understanding phishing threats. AegisNet serves both as a real-time threat detection tool and a cybersecurity education platform.

\---

\#\# 2\. Goals

\- Detect phishing URLs in real time with high accuracy using AI/ML  
\- Explain detection results in plain language through a Gemini-powered conversational assistant  
\- Provide a chat interface accessible to non-technical users  
\- Store scan history per registered user  
\- Run entirely on open-source, low-cost infrastructure

\---

\#\# 3\. Users

\*\*Primary:\*\* Individual internet users who want to verify a suspicious link before clicking it.

\*\*Secondary:\*\* Students and staff at educational institutions seeking cybersecurity awareness.

\*\*Tertiary:\*\* Small organisations without enterprise security tooling.

\---

\#\# 4\. Features and Requirements

\#\#\# 4.1 Authentication

\- Users can register with email and password  
\- Users can log in and log out  
\- Passwords are hashed before storage  
\- Unauthenticated users can still scan URLs but their history is not saved  
\- Session management via Flask sessions

\#\#\# 4.2 URL Submission

\- A text input field on the main page accepts a full URL  
\- User clicks a Scan button or types the URL into the chat interface  
\- The system validates that the input is a properly formatted URL before processing  
\- Both http and https URLs are accepted

\#\#\# 4.3 Feature Extraction Engine

The system must extract the following features from every submitted URL:

\*\*URL Lexical Features:\*\*  
\- URL length (total character count)  
\- Hostname length  
\- Number of dots in the URL  
\- Number of hyphens in the URL  
\- Number of underscores  
\- Number of slashes  
\- Number of question marks  
\- Number of equals signs  
\- Number of at (@) symbols  
\- Number of ampersands  
\- Presence of IP address instead of domain name (binary)  
\- Presence of HTTPS (binary)  
\- Number of subdomains  
\- Presence of URL shortening service (binary) — check against a known list: bit.ly, tinyurl.com, t.co, goo.gl, ow.ly, is.gd  
\- Presence of suspicious keywords in URL: login, verify, secure, account, update, banking, confirm, password, signin, webscr  
\- URL contains port number (binary)  
\- Length of longest word in URL  
\- Number of digits in URL  
\- Ratio of digits to total URL length  
\- Presence of double slash (//) in URL path  
\- TLD is suspicious (binary) — check against a list of commonly abused TLDs

\*\*Domain-Based Features:\*\*  
\- Domain age in days (via WHOIS lookup; default to \-1 if unavailable)  
\- Domain registration length in days  
\- WHOIS lookup success (binary) — indicates if domain info is publicly available

All features must be returned as a numeric vector compatible with the trained scikit-learn model.

\#\#\# 4.4 ML Classification Engine

\- Algorithm: Random Forest Classifier (scikit-learn)  
\- Training dataset: Hannousse and Yahiouche (2021) or equivalent publicly available labelled phishing dataset with minimum 50,000 samples  
\- The model outputs: class label (phishing / legitimate) and confidence score (probability)  
\- The trained model is saved as a .pkl file and loaded at application startup  
\- SHAP values are computed per prediction to identify the top contributing features  
\- The top 3 SHAP-contributing features for each prediction are passed to the Gemini assistant as context

\#\#\# 4.5 Intelligent Assistant (Gemini-Powered)

\- A chat-style interface on the right panel of the main screen  
\- Powered by the Google Gemini API using the google-generativeai Python SDK  
\- The model string is set as a configurable environment variable: GEMINI\_MODEL (default: gemini-1.5-flash)  
\- The Gemini API key is stored in a .env file as GEMINI\_API\_KEY

\*\*System Prompt:\*\*  
Every Gemini API call includes a system prompt that establishes the assistant identity and behaviour:

\> You are AegisNet Assistant, a cybersecurity AI embedded in the AegisNet phishing detection platform. Your job is to help users understand phishing threats, explain URL scan results in plain language, and answer cybersecurity questions. Always be clear, concise, and friendly. Avoid technical jargon unless the user specifically asks for technical detail. Never make up scan results — only explain results that are explicitly provided to you in context.

\*\*Context Injection:\*\*  
When a URL has been scanned, the scan result is injected into every subsequent Gemini message as part of the conversation context:

\[SCAN CONTEXT\] URL: \<scanned\_url\> Verdict: \<Phishing | Legitimate\> Confidence: \<percentage\> Top contributing features:

1. \<feature\_name\>: \<value\>  
2. \<feature\_name\>: \<value\>  
3. \<feature\_name\>: \<value\>

\*\*Assistant Capabilities:\*\*  
\- Explain the scan result for the current URL in plain language  
\- Answer general questions about phishing (what it is, how to spot it, what to do if you clicked a phishing link)  
\- Explain how AegisNet works  
\- Respond to greetings and general conversation naturally  
\- Handle any out-of-scope question gracefully by redirecting the user to cybersecurity topics

\- The assistant panel shows full message history within the session  
\- Each user message and assistant response is rendered as a chat bubble  
\- A loading indicator is shown while waiting for the Gemini API response

\#\#\# 4.6 Result Display

\- After scanning, the main panel updates to show:  
  \- The scanned URL  
  \- A large verdict badge: green for Legitimate, red for Phishing  
  \- Confidence score as a percentage  
  \- A feature breakdown table showing the top extracted features and their values  
  \- The assistant automatically sends an explanation of the result in the chat panel  
\- Results render without full page reload (fetch API / AJAX)

\#\#\# 4.7 Scan History

\- Registered and logged-in users have a History page  
\- The page lists all past scans: URL, verdict, confidence, timestamp  
\- Maximum of 100 most recent scans stored per user  
\- Users can click a past scan to view its full result

\#\#\# 4.8 Dashboard (Home Page)

\- A clean landing page with:  
  \- AegisNet name and tagline  
  \- URL input field prominently placed  
  \- Brief explanation of what the system does  
  \- Global scan statistics: total scans performed, total phishing detected  
\- Navigation: Home, History (logged-in only), Login/Register, Logout

\---

\#\# 5\. Non-Functional Requirements

\- \*\*Performance:\*\* URL scan (feature extraction \+ model inference) must complete in under 3 seconds. WHOIS lookup failures must not block the scan and must time out gracefully within 2 seconds.  
\- \*\*Accuracy:\*\* The trained model must achieve minimum 95% accuracy on the test split of the training dataset.  
\- \*\*Availability:\*\* The system runs as a local Flask development server. No uptime SLA is required for this academic version.  
\- \*\*Security:\*\* Passwords stored as bcrypt hashes. No plaintext credentials in the database. User scan data is isolated per account. The Gemini API key is never exposed to the frontend.  
\- \*\*Usability:\*\* The interface must be usable without any technical knowledge. No jargon in assistant responses unless requested.  
\- \*\*Browser Support:\*\* Chrome, Firefox, and Edge (latest versions).  
\- \*\*Responsiveness:\*\* The UI must be usable on both desktop and mobile screens.

\---

\#\# 6\. Tech Stack

| Layer | Technology |  
|---|---|  
| Backend | Python 3.10+, Flask |  
| ML | scikit-learn, SHAP, pandas, numpy, joblib |  
| WHOIS | python-whois |  
| AI Assistant | Google Gemini API, google-generativeai Python SDK |  
| Frontend | HTML5, CSS3, vanilla JavaScript |  
| Database | SQLite via SQLAlchemy |  
| Auth | Flask-Login, Flask-Bcrypt |  
| Environment Variables | python-dotenv |  
| Model Storage | joblib .pkl file |

\---

\#\# 7\. Pages and Routes

| Route | Page | Access |  
|---|---|---|  
| / | Home / Scanner | Public |  
| /scan | POST — returns JSON scan result | Public |  
| /chat | POST — sends message to Gemini, returns response | Public |  
| /history | Scan history list | Logged-in only |  
| /login | Login form | Public |  
| /register | Registration form | Public |  
| /logout | Logout action | Logged-in only |

\---

\#\# 8\. Data Model

\*\*User\*\*  
\- id, email, password\_hash, created\_at

\*\*ScanResult\*\*  
\- id, user\_id (nullable), url, verdict, confidence, features\_json, shap\_json, timestamp

\---

\#\# 9\. Environment Variables

| Variable | Description |  
|---|---|  
| GEMINI\_API\_KEY | Google Gemini API key |  
| GEMINI\_MODEL | Gemini model string (default: gemini-1.5-flash) |  
| SECRET\_KEY | Flask session secret key |  
| DATABASE\_URL | SQLite database path |

\---

\#\# 10\. Out of Scope

\- Email content analysis  
\- Mobile native app  
\- SMS or voice phishing detection  
\- Live website content crawling  
\- Third-party API integrations (VirusTotal, etc.)  
\- Multilingual support  
\- Real-time collaborative features

\---

\#\# 11\. Success Criteria

\- Model accuracy \>= 96% on test set  
\- Gemini assistant responds correctly to all defined capability areas  
\- Scan completes in under 3 seconds for 95% of URLs  
\- All pages render correctly on Chrome and Firefox  
\- Scan history correctly isolated per user account  
\- System passes functional testing for all routes  
\- GEMINI\_API\_KEY is never exposed to the client side

\---  
\---

---

---

