# AegisNet — Project Presentation Guide

> A plain-language explanation of what AegisNet is, what it does, and how to explain it to a lecturer or supervisor.

**Author:** Ezenduka Johncollins  
**Institution:** Chukwuemeka Odumegwu Ojukwu University, Uli

---

## What Is AegisNet? (The One-Sentence Answer)

AegisNet is a website that can look at any web link you give it, use artificial intelligence to decide whether that link is a phishing attack or a safe website, and then explain its reasoning to you in plain English through a chat assistant.

---

## What Problem Does It Solve?

Phishing is one of the most common ways cybercriminals steal passwords, banking details, and personal information. They create fake websites that look exactly like real ones — a bank, a government portal, an email login page — and trick people into typing in their credentials.

The problem is that most people cannot tell a phishing link from a real one just by looking at it. AegisNet gives anyone — technical or not — a tool to check a suspicious link before clicking it.

---

## How Does It Work? (Step by Step)

### Step 1 — You paste a URL

You copy any web link — for example, from a suspicious email or WhatsApp message — and paste it into AegisNet's scanner.

### Step 2 — The system breaks the URL apart

AegisNet extracts 24 measurable characteristics from the URL. These are called **features**. Examples:

- Is the website using a secure connection (`https`) or not?
- Does the web address contain words like "login", "verify", "banking", or "password"?
- Is the domain name very new (newly registered domains are often used for phishing)?
- Does the link use an IP address instead of a real domain name?
- Is the link from a known URL-shortener service (like bit.ly)?
- Does the web address use a suspicious domain ending like `.tk`, `.xyz`, or `.ml`?

None of these individual signals are definitive on their own — but taken together as a set of 24 measurements, they paint a clear picture.

### Step 3 — A machine learning model makes the decision

The 24 measurements are fed into a **Random Forest** — a type of machine learning model. Think of it as a panel of 100 expert judges, each one independently examining the evidence and voting. The majority vote determines the verdict: **Phishing** or **Legitimate**. The system also reports how confident it is as a percentage.

### Step 4 — The system explains which features mattered most

AegisNet uses a mathematical technique called **SHAP** (SHapley Additive exPlanations) to show which of the 24 features had the biggest influence on the decision. So instead of just saying "this is phishing", it can say "this was flagged primarily because it uses a suspicious TLD, contains the word 'signin', and has no HTTPS encryption."

### Step 5 — An AI assistant explains it in plain language

The result is sent to **Google Gemini** (a large language model, similar to ChatGPT but made by Google). Gemini reads the verdict and the feature evidence, and writes a plain-English explanation in the chat panel — something a non-technical user can understand. You can also continue chatting with it to ask follow-up cybersecurity questions.

---

## What Makes This Different From a Simple Blocklist?

Most basic phishing detection tools work by maintaining a list of known bad websites. If your link is on the list, it is blocked. If it is not on the list, it is allowed through — even if it was created five minutes ago to steal passwords.

AegisNet uses **structural analysis** instead. It does not need to have seen a URL before. It examines the anatomy of the URL itself, so it can flag a brand-new phishing domain the moment it is submitted, even if no one has ever seen it before.

---

## The Technologies Used (Plain Language)

| Component | Technology Used | What It Does In Simple Terms |
|---|---|---|
| **Website framework** | Flask (Python) | The engine that runs the website and handles all the requests |
| **Machine learning** | scikit-learn (Random Forest) | The AI model that decides if a URL is phishing or safe |
| **Explainability** | SHAP | The maths that explains *why* the AI made its decision |
| **AI chat assistant** | Google Gemini | The conversational AI that explains results and answers questions |
| **Domain lookups** | WHOIS | Checks how old a domain is (newly created domains are suspicious) |
| **User accounts** | Flask-Login + bcrypt | Lets users register, log in, and see their scan history securely |
| **Database** | SQLite | Stores user accounts and scan history |
| **Security** | Flask-WTF (CSRF) | Protects the website from a common attack called cross-site request forgery |
| **Frontend** | HTML, CSS, JavaScript | The visual interface the user sees and interacts with |

---

## How Are Passwords Stored?

Passwords are **never** stored in the database. When you create an account, your password is passed through an algorithm called **bcrypt** that converts it into a scrambled string of characters (called a hash). Only that hash is saved. When you log in, the system hashes what you typed and compares it to the stored hash — it never decrypts or looks at the actual password.

---

## How Are API Keys and Secrets Kept Safe?

The Gemini AI requires an API key — like a password that grants access to Google's service. This key is stored in a file called `.env` on the server. This file is:

- Never committed to GitHub (it is in the `.gitignore` exclusion list)
- Never sent to the browser or included in any webpage
- Only ever read by the server-side Python code, never by the JavaScript the user downloads

---

## What Does the Dashboard Show?

The dashboard (visible after logging in) shows:

- **Total scans performed** across all users
- **How many were phishing** vs. legitimate
- **Threat rate** — the percentage of scanned URLs that were phishing
- **Security score** — an inverse of the threat rate; a simple health indicator
- **Recent scans** — a live feed of the most recently analysed URLs

---

## What Is Stored in the Database?

Two types of data:

1. **User accounts** — email address and a bcrypt password hash. Nothing else.
2. **Scan results** — the URL that was scanned, the verdict, the confidence score, the top contributing features, and the timestamp. If you were logged in when you scanned, the result is linked to your account so you can view it in history.

---

## Can It Be Used Without an Account?

Yes. The URL scanner works for anyone without requiring registration. An account is only needed to access scan history and the analytics dashboard.

---

## What Happens If the AI (Gemini) Is Unavailable?

If the Gemini API fails — due to a network error, rate limit, or outage — the system returns a graceful fallback message:

> "I am having trouble connecting right now. Please try again in a moment."

The scan result (verdict and confidence score) is still shown. The AI chat is a complementary layer, not a dependency for the core detection function.

---

## Summary — What Was Built

| Layer | What Was Delivered |
|---|---|
| **Data layer** | A 24-feature URL extraction engine and a trained Random Forest classifier |
| **Explainability layer** | SHAP-based top-feature attribution for every prediction |
| **AI layer** | Gemini-powered assistant that explains verdicts and answers cybersecurity questions |
| **Web layer** | Full Flask web application with user authentication, scan history, and analytics |
| **Security layer** | CSRF protection, bcrypt passwords, secret management, cookie hardening |
| **Frontend** | Responsive web interface with a scanner, infographic results, chat panel, and landing page |

---

## How to Run the Project Locally (For Your Lecturer)

1. Install Python 3.10 or higher
2. Clone the repository: `git clone https://github.com/Dancuso419/AegisNet.git`
3. Install dependencies: `pip install --prefer-binary -r requirements.txt`
4. Create a `.env` file with your Gemini API key (see `README.md` for the template)
5. Train the model: `python ml/train.py`
6. Start the server: `python run.py`
7. Open `http://127.0.0.1:5000` in a browser
