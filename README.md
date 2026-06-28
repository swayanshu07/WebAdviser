🛡️ WebAdviser – Website Security Checker
A web-based security assessment tool built with Python & Flask as part of a Summer Training Project 2026 (Cyber Security domain).

📌 About
WebAdviser analyzes any website and generates a detailed security report covering HTTPS status, SSL certificate validity, security headers, and an overall security score with actionable recommendations.

✨ Features
🔒 HTTPS Verification — Checks if the site enforces secure communication
📜 SSL Certificate Validation — Displays issuer, expiry date, and days remaining
🧱 Security Header Analysis — Checks for 7 critical headers including CSP, HSTS, X-Frame-Options, and more
📊 Security Score — Calculates a score out of 100 with risk rating (Secure / Moderate / Needs Improvement)
💡 Recommendations — Actionable fixes for every missing or misconfigured header
📄 PDF Report Generation — Download a full security report as PDF
🧰 Tech Stack
Layer	Technology
Language	Python 3.x
Backend	Flask
Frontend	HTML, CSS, JavaScript
PDF Reports	ReportLab
SSL Inspection	Python ssl & socket modules
🚀 Getting Started
1. Clone the repository
git clone https://github.com/yourusername/webadviser.git
cd webadviser
2. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # macOS/Linux
3. Install dependencies
pip install -r requirements.txt
4. Run the app
py app.py
5. Open in browser
