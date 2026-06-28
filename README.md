# 🛡️ WebAdviser – Website Security Checker

A web-based security assessment tool built with Python & Flask as part of a Summer Training Project 2026 (Cyber Security domain).

## 📌 About
WebAdviser analyzes any website and generates a detailed security report covering HTTPS status, SSL certificate validity, security headers, and an overall security score with actionable recommendations.

## ✨ Features
- 🔒 **HTTPS Verification** — Checks if the site enforces secure communication
- 📜 **SSL Certificate Validation** — Displays issuer, expiry date, and days remaining
- 🧱 **Security Header Analysis** — Checks for 7 critical headers including CSP, HSTS, X-Frame-Options, and more
- 📊 **Security Score** — Calculates a score out of 100 with risk rating (Secure / Moderate / Needs Improvement)
- 💡 **Recommendations** — Actionable fixes for every missing or misconfigured header
- 📄 **PDF Report Generation** — Download a full security report as PDF

## 🧰 Tech Stack
| Layer | Technology |
|-------|-----------|
| Language | Python 3.x |
| Backend | Flask |
| Frontend | HTML, CSS, JavaScript |
| PDF Reports | ReportLab |
| SSL Inspection | Python `ssl` & `socket` modules |

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/webadviser.git
cd webadviser
```

### 2. Create a virtual environment
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # macOS/Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the app
```bash
py app.py
```

### 5. Open in browser
http://127.0.0.1:5000

## 🖥️ How to Use

**Step 1 — Enter a website**
Type any domain or URL into the search bar on the homepage.
Examples:

- google.com
- example.com

**Step 2 — Click "Scan Now"**
Press the **Scan Now** button or hit **Enter**. The tool will automatically:
- Check if HTTPS is enabled
- Validate the SSL certificate
- Analyze all security headers
- Calculate the security score

**Step 3 — View the Results**
The results appear in a two-panel dashboard:
- **Left panel** — Security Score (with animated ring), score breakdown, and SSL certificate details
- **Right panel** — Security headers status (Present / Missing) and detailed recommendations

**Step 4 — Read the Recommendations**
Each missing or misconfigured header shows:
- Severity level: `Critical` / `High` / `Medium`
- What the risk is
- Exact fix to implement

**Step 5 — Download the Report**
Click **Download PDF** at the top of the right panel to save a full security report including:
- Scan date and URL
- HTTPS and SSL details
- Full headers table
- All recommendations

## 📋 Security Headers Checked
| Header | Purpose |
|--------|---------|
| Strict-Transport-Security | Forces HTTPS communication |
| Content-Security-Policy | Protects against XSS attacks |
| Content-Security-Policy-Report-Only | Reports CSP violations without enforcing |
| X-Frame-Options | Prevents Clickjacking |
| X-Content-Type-Options | Prevents MIME sniffing |
| Referrer-Policy | Controls referrer leakage |
| Permissions-Policy | Restricts browser feature access |

## 🏆 Scoring System
| Check | Points |
|-------|--------|
| HTTPS Enabled | 20 |
| Valid SSL Certificate | 20 |
| Strict-Transport-Security | 10 |
| Content-Security-Policy | 15 |
| Content-Security-Policy-Report-Only | 5 |
| X-Frame-Options | 10 |
| X-Content-Type-Options | 10 |
| Referrer-Policy | 10 |
| Permissions-Policy | 5 |
| **Total** | **105** |

## 🔢 Risk Rating
| Score | Rating |
|-------|--------|
| 80–105 | ✅ Secure |
| 60–79 | ⚠️ Moderate |
| Below 60 | ❌ Needs Improvement |
