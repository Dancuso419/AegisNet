"use strict";

// CSRF token (rendered into the page <head> by Flask-WTF).
const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || "";

// ── Mobile sidebar drawer ────────────────────────────────
(() => {
  const toggle  = document.getElementById("drawer-toggle");
  const overlay = document.getElementById("drawer-overlay");
  if (!toggle) return;
  const setDrawer = (open) => {
    document.body.classList.toggle("drawer-open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  };
  toggle.addEventListener("click", () =>
    setDrawer(!document.body.classList.contains("drawer-open"))
  );
  overlay?.addEventListener("click", () => setDrawer(false));
  // Close after tapping a nav link, and on Escape
  document.querySelectorAll(".sidebar .nav-item").forEach((a) =>
    a.addEventListener("click", () => setDrawer(false))
  );
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") setDrawer(false);
  });
})();

// ── DOM refs ─────────────────────────────────────────────
const scanForm        = document.getElementById("scan-form");
const urlInput        = document.getElementById("url-input");
const urlError        = document.getElementById("url-error");
const scanBtn         = document.getElementById("scan-btn");
const resultPanel     = document.getElementById("result-panel");
const emptyState      = document.getElementById("empty-state");
const verdictBadge    = document.getElementById("verdict-badge");
const verdictSummary  = document.getElementById("verdict-summary");
const scannedUrl      = document.getElementById("scanned-url");
const gaugeFill       = document.getElementById("gauge-fill");
const gaugeValue      = document.getElementById("gauge-value");
const riskSignals     = document.getElementById("risk-signals");
const urlStats        = document.getElementById("url-stats");
const topList         = document.getElementById("top-features-list");
const allList         = document.getElementById("all-features-list");

const GAUGE_CIRC = 2 * Math.PI * 52; // ≈ 326.7

// Risk signal checks — each returns whether the feature is a risk.
const RISK_CHECKS = [
  { key: "has_https",              label: "HTTPS",       risk: (v) => v === 0 },
  { key: "has_ip",                 label: "IP Address",  risk: (v) => v === 1 },
  { key: "is_shortened",           label: "Shortened",   risk: (v) => v === 1 },
  { key: "suspicious_tld",         label: "Suspicious TLD",     risk: (v) => v === 1 },
  { key: "has_suspicious_keyword", label: "Phishing Keyword",   risk: (v) => v === 1 },
  { key: "has_port",               label: "Custom Port", risk: (v) => v === 1 },
  { key: "num_at",                 label: "@ Symbol",    risk: (v) => v > 0 },
  { key: "has_double_slash_path",  label: "Double Slash", risk: (v) => v === 1 },
];

const STAT_TILES = [
  { key: "url_length",      label: "URL Length" },
  { key: "hostname_length", label: "Hostname Len" },
  { key: "num_subdomains",  label: "Subdomains" },
  { key: "num_dots",        label: "Dots" },
  { key: "num_digits",      label: "Digits" },
  { key: "digit_ratio",     label: "Digit Ratio", fmt: (v) => (v * 100).toFixed(0) + "%" },
];

// Human-readable name + plain-English meaning for each model feature.
// Used to make the "Top Contributing Signals" section explanatory.
const FEATURE_META = {
  url_length:                 { name: "URL Length",          desc: "How long the full web address is. Very long links often hide their true destination." },
  hostname_length:            { name: "Hostname Length",     desc: "Length of the domain name. Unusually long hostnames are common in phishing." },
  num_dots:                   { name: "Dot Count",           desc: "Number of dots in the address. Many dots can signal stacked fake subdomains." },
  num_hyphens:                { name: "Hyphen Count",        desc: "Number of hyphens. Scammers use these to mimic real brand names." },
  num_underscores:            { name: "Underscore Count",    desc: "Number of underscores in the address." },
  num_slashes:                { name: "Slash Count",         desc: "Number of slashes. Deeply nested paths can be a red flag." },
  num_question_marks:         { name: "Query Markers",       desc: "Number of '?' query markers used to pass hidden parameters." },
  num_equals:                 { name: "Equals Signs",        desc: "Number of '=' signs, often used to carry tracking or redirect data." },
  num_at:                     { name: "@ Symbol",            desc: "An '@' in a link can disguise the real destination from the visible text." },
  num_ampersands:             { name: "Ampersands",          desc: "Number of '&' signs chaining multiple URL parameters together." },
  has_ip:                     { name: "Raw IP Address",      desc: "The link uses a numeric IP instead of a normal domain — a strong phishing sign." },
  has_https:                  { name: "HTTPS Security",      desc: "Whether the connection is encrypted. Missing HTTPS lowers trust." },
  num_subdomains:             { name: "Subdomain Depth",     desc: "How many subdomains are stacked, e.g. login.secure.fake.com." },
  is_shortened:               { name: "URL Shortener",       desc: "The link uses a shortener that hides where it really leads." },
  has_suspicious_keyword:     { name: "Bait Keywords",       desc: "Contains alarming words like 'login', 'verify' or 'secure' used as bait." },
  has_port:                   { name: "Custom Port",         desc: "Points to an unusual network port, which legitimate sites rarely expose." },
  longest_word_length:        { name: "Longest Token",       desc: "Length of the longest word in the address. Long random tokens are suspicious." },
  num_digits:                 { name: "Digit Count",         desc: "Total digits in the address. Lots of numbers can indicate auto-generated links." },
  digit_ratio:                { name: "Digit Ratio",         desc: "Share of the address made up of digits. A high ratio is unusual for real sites." },
  has_double_slash_path:      { name: "Double Slash",        desc: "A '//' inside the path can be used to redirect to another site." },
  suspicious_tld:             { name: "Risky Domain Ending", desc: "Ends in an extension (.tk, .xyz, .ml…) frequently abused by scammers." },
  domain_age_days:            { name: "Domain Age",          desc: "How old the domain is. Brand-new domains are typical of phishing campaigns." },
  domain_registration_length: { name: "Registration Span",  desc: "How long the domain is registered for. Scam domains are usually short-term." },
  whois_success:              { name: "Registry Lookup",     desc: "Whether public registration data could be found for the domain." },
  has_brand_impersonation:    { name: "Brand Impersonation", desc: "The address imitates a known brand, often by swapping letters for look-alikes." },
};

const chatForm        = document.getElementById("chat-form");
const chatInput       = document.getElementById("chat-input");
const chatMessages    = document.getElementById("chat-messages");
const typingIndicator = document.getElementById("typing-indicator");

// ── Scan ─────────────────────────────────────────────────
scanForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  urlError.textContent = "";

  const url = urlInput.value.trim();
  if (!url) {
    urlError.textContent = "Please enter a URL.";
    return;
  }

  setScanLoading(true);

  try {
    const res  = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": CSRF_TOKEN },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();

    if (!res.ok) {
      urlError.textContent = data.error || "Scan failed. Please try again.";
      return;
    }

    renderResult(data);
    appendAssistantBubble(data.assistant_message);

  } catch {
    urlError.textContent = "Network error. Check your connection and try again.";
  } finally {
    setScanLoading(false);
  }
});

function setScanLoading(loading) {
  scanBtn.disabled = loading;
  scanBtn.classList.toggle("btn--loading", loading);
}

function renderResult(data) {
  const isPhishing = data.verdict === "Phishing";
  const features = data.features || {};
  const accentClass = isPhishing ? "danger" : "safe";

  // ── Verdict + summary ──
  verdictBadge.textContent = data.verdict;
  verdictBadge.className = "verdict-badge " +
    (isPhishing ? "verdict-badge--phishing" : "verdict-badge--legitimate");

  verdictSummary.textContent = isPhishing
    ? "This URL shows strong signs of a phishing attempt."
    : "This URL appears safe with no major red flags.";
  verdictSummary.className = "verdict-summary verdict-summary--" + accentClass;

  scannedUrl.textContent = data.url;

  // ── Confidence gauge ──
  const conf = Number(data.confidence) || 0;
  gaugeValue.textContent = `${conf}%`;
  gaugeFill.classList.remove("gauge-fill--danger", "gauge-fill--safe");
  gaugeFill.classList.add("gauge-fill--" + accentClass);
  // Animate from empty to the target value.
  gaugeFill.style.strokeDashoffset = GAUGE_CIRC;
  requestAnimationFrame(() => {
    gaugeFill.style.strokeDashoffset = GAUGE_CIRC * (1 - conf / 100);
  });

  // ── Risk signal chips ──
  riskSignals.innerHTML = "";
  RISK_CHECKS.forEach((check) => {
    const val = features[check.key];
    const isRisk = check.risk(val);
    const chip = document.createElement("div");
    chip.className = "risk-chip risk-chip--" + (isRisk ? "bad" : "good");
    chip.innerHTML = `
      <span class="risk-icon">${isRisk ? ICON_WARN : ICON_CHECK}</span>
      <span class="risk-label">${check.label}</span>`;
    riskSignals.appendChild(chip);
  });

  // ── Top contributing signals as explanatory cards ──
  const tops = data.top_features || [];
  const maxAbs = Math.max(...tops.map((f) => Math.abs(f.shap_value)), 0.0001);
  topList.innerHTML = "";
  tops.forEach((f, i) => {
    const pos = f.shap_value > 0;                 // pushes toward phishing
    const pct = Math.max(10, (Math.abs(f.shap_value) / maxAbs) * 100);
    const meta = FEATURE_META[f.feature] || { name: formatFeatureName(f.feature), desc: "" };
    const dir = pos ? "pos" : "neg";
    const tagLabel = pos ? "Raises risk" : "Lowers risk";
    const icon = pos ? ICON_WARN : ICON_CHECK;

    const li = document.createElement("li");
    li.className = "shap-card shap-card--" + dir;
    li.innerHTML = `
      <span class="shap-card-icon shap-card-icon--${dir}">${icon}</span>
      <div class="shap-card-body">
        <div class="shap-card-top">
          <span class="shap-card-name">${meta.name}</span>
          <span class="shap-card-tag shap-card-tag--${dir}">${tagLabel}</span>
        </div>
        <p class="shap-card-desc">${meta.desc}</p>
        <div class="shap-card-meter">
          <div class="shap-card-track">
            <div class="shap-card-fill shap-card-fill--${dir}" style="width:0%"></div>
          </div>
          <span class="shap-card-val shap-card-val--${dir}">${pos ? "+" : ""}${f.shap_value.toFixed(3)}</span>
        </div>
      </div>`;
    topList.appendChild(li);
    const fill = li.querySelector(".shap-card-fill");
    requestAnimationFrame(() => {
      setTimeout(() => { fill.style.width = pct + "%"; }, i * 90);
    });
  });

  // ── URL anatomy stat tiles ──
  urlStats.innerHTML = "";
  STAT_TILES.forEach((tile) => {
    const raw = features[tile.key];
    const display = tile.fmt ? tile.fmt(raw) : formatFeatureValue(raw);
    const el = document.createElement("div");
    el.className = "stat-tile";
    el.innerHTML = `
      <span class="stat-tile-value">${display}</span>
      <span class="stat-tile-label">${tile.label}</span>`;
    urlStats.appendChild(el);
  });

  // ── All 24 features (collapsible) ──
  allList.innerHTML = "";
  Object.entries(features).forEach(([key, val]) => {
    const li = document.createElement("li");
    li.className = "feature-item";
    li.innerHTML = `
      <span class="feature-name">${formatFeatureName(key)}</span>
      <span class="feature-value">${formatFeatureValue(val)}</span>`;
    allList.appendChild(li);
  });

  emptyState.hidden = true;
  resultPanel.hidden = false;
}

const ICON_CHECK = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
const ICON_WARN  = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="13"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>';

function formatFeatureName(key) {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatFeatureValue(val) {
  if (typeof val === "number") {
    return Number.isInteger(val) ? val : val.toFixed(4);
  }
  return val;
}

// ── Chat ─────────────────────────────────────────────────
chatForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const message = chatInput.value.trim();
  if (!message) return;

  chatInput.value = "";
  appendUserBubble(message);
  showTyping(true);

  try {
    const res  = await fetch("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": CSRF_TOKEN },
      body: JSON.stringify({ message }),
    });
    const data = await res.json();
    appendAssistantBubble(data.response || "Sorry, I could not get a response.");
  } catch {
    appendAssistantBubble("I am having trouble connecting right now. Please try again in a moment.");
  } finally {
    showTyping(false);
  }
});

function appendUserBubble(text) {
  const div = document.createElement("div");
  div.className = "chat-bubble chat-bubble--user";
  div.textContent = text;
  chatMessages.appendChild(div);
  scrollChat();
}

function appendAssistantBubble(text) {
  const div = document.createElement("div");
  div.className = "chat-bubble chat-bubble--assistant";
  div.innerHTML = `
    <div class="bubble-icon" aria-hidden="true">
      <svg width="16" height="16" viewBox="0 0 48 48" fill="none">
        <path d="M24 4L42 11V25C42 36 34 43 24 46C14 43 6 36 6 25V11L24 4Z" fill="rgba(244,121,32,0.1)" stroke="#f47920" stroke-width="2" stroke-linejoin="round"/>
        <circle cx="24" cy="26" r="9" stroke="#f47920" stroke-width="2"/>
        <circle cx="24" cy="26" r="3" fill="#f47920"/>
      </svg>
    </div>
    <p>${escapeHtml(text)}</p>`;
  chatMessages.appendChild(div);
  scrollChat();
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showTyping(visible) {
  typingIndicator.hidden = !visible;
  if (visible) scrollChat();
}

function scrollChat() {
  chatMessages.scrollTop = chatMessages.scrollHeight;
}
