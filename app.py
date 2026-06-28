from flask import Flask, render_template, request, jsonify, send_file
import requests
import ssl
import socket
from datetime import datetime
import json
import os
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

app = Flask(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "purpose": "Forces HTTPS communication",
        "points": 10,
        "risk": "Man-in-the-middle attacks possible",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS."
    },
    "Content-Security-Policy": {
        "purpose": "Protects against Cross-Site Scripting (XSS)",
        "points": 10,
        "risk": "XSS and data injection attacks possible",
        "recommendation": "Implement a strict CSP header to restrict resource loading: \"Content-Security-Policy: default-src 'self'\"."
    },
    "Content-Security-Policy-Report-Only": {
        "purpose": "Reports CSP violations without enforcing them (used for testing CSP rules)",
        "points": 5,
        "risk": "CSP rules are not enforced; violations are only reported, not blocked",
        "recommendation": "Use 'Content-Security-Policy-Report-Only' during CSP testing, then switch to enforcing 'Content-Security-Policy' in production."
    },
    "X-Frame-Options": {
        "purpose": "Prevents Clickjacking attacks",
        "points": 10,
        "risk": "Clickjacking vulnerability",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent embedding in iframes."
    },
    "X-Content-Type-Options": {
        "purpose": "Prevents MIME-type attacks",
        "points": 10,
        "risk": "MIME sniffing attacks possible",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing."
    },
    "Referrer-Policy": {
        "purpose": "Controls referrer information leakage",
        "points": 10,
        "risk": "Sensitive URL data may leak via Referer header",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer data."
    },
    "Permissions-Policy": {
        "purpose": "Restricts browser features",
        "points": 5,
        "risk": "Browser features may be misused",
        "recommendation": "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()' to restrict feature access."
    }
}


def normalize_url(url):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


def get_domain(url):
    url = url.replace("https://", "").replace("http://", "")
    return url.split("/")[0].split("?")[0]


def check_https(url):
    domain = get_domain(url)
    result = {
        "url": url,
        "https_enabled": False,
        "risk_level": "High",
        "recommendation": "Enable HTTPS using a valid SSL certificate."
    }
    try:
        r = requests.get("https://" + domain, timeout=10, allow_redirects=True)
        if r.url.startswith("https://"):
            result["https_enabled"] = True
            result["risk_level"] = "Low"
            result["recommendation"] = "HTTPS is properly enabled."
    except Exception:
        pass
    return result


def check_ssl(domain):
    result = {
        "issuer": "N/A",
        "valid_from": "N/A",
        "expiry_date": "N/A",
        "days_remaining": 0,
        "status": "Invalid",
        "error": None
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()

        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown"))

        valid_from = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry - datetime.utcnow()).days

        result["valid_from"] = valid_from.strftime("%Y-%m-%d")
        result["expiry_date"] = expiry.strftime("%Y-%m-%d")
        result["days_remaining"] = days_remaining
        result["status"] = "Valid" if days_remaining > 0 else "Expired"
    except ssl.SSLCertVerificationError:
        result["error"] = "Certificate verification failed"
        result["status"] = "Invalid"
    except Exception as e:
        result["error"] = str(e)
        result["status"] = "Unable to retrieve"
    return result


def check_headers(url):
    results = {}
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        for header, info in SECURITY_HEADERS.items():
            present = header.lower() in headers
            results[header] = {
                "present": present,
                "status": "Present" if present else "Missing",
                "purpose": info["purpose"],
                "points": info["points"],
                "risk": info["risk"],
                "recommendation": info["recommendation"],
                "value": headers.get(header.lower(), "")
            }
    except Exception:
        for header, info in SECURITY_HEADERS.items():
            results[header] = {
                "present": False,
                "status": "Error",
                "purpose": info["purpose"],
                "points": info["points"],
                "risk": info["risk"],
                "recommendation": info["recommendation"],
                "value": ""
            }
    return results


def calculate_score(https_result, ssl_result, headers_result):
    score = 0
    breakdown = []

    if https_result["https_enabled"]:
        score += 20
        breakdown.append({"item": "HTTPS Enabled", "points": 20, "earned": 20, "status": "pass"})
    else:
        breakdown.append({"item": "HTTPS Enabled", "points": 20, "earned": 0, "status": "fail"})

    ssl_valid = ssl_result["status"] == "Valid"
    if ssl_valid:
        score += 20
        breakdown.append({"item": "Valid SSL Certificate", "points": 20, "earned": 20, "status": "pass"})
    else:
        breakdown.append({"item": "Valid SSL Certificate", "points": 20, "earned": 0, "status": "fail"})

    for header, info in headers_result.items():
        pts = SECURITY_HEADERS[header]["points"]
        if info["present"]:
            score += pts
            breakdown.append({"item": header, "points": pts, "earned": pts, "status": "pass"})
        else:
            breakdown.append({"item": header, "points": pts, "earned": 0, "status": "fail"})

    if score >= 80:
        rating = "Secure"
        rating_class = "secure"
    elif score >= 60:
        rating = "Moderate"
        rating_class = "moderate"
    else:
        rating = "Needs Improvement"
        rating_class = "poor"

    return {"score": score, "total": 100, "rating": rating, "rating_class": rating_class, "breakdown": breakdown}


def generate_recommendations(https_result, ssl_result, headers_result):
    recs = []
    if not https_result["https_enabled"]:
        recs.append({
            "severity": "Critical",
            "issue": "HTTPS Not Enabled",
            "detail": "Your site is served over HTTP, exposing data in transit.",
            "fix": "Obtain an SSL/TLS certificate (e.g., from Let's Encrypt) and configure your server to redirect all HTTP traffic to HTTPS."
        })

    if ssl_result["status"] != "Valid":
        recs.append({
            "severity": "Critical",
            "issue": "SSL Certificate Issue",
            "detail": f"Certificate status: {ssl_result['status']}. {ssl_result.get('error', '')}",
            "fix": "Renew or obtain a valid SSL certificate from a trusted Certificate Authority."
        })
    elif ssl_result["days_remaining"] < 30:
        recs.append({
            "severity": "High",
            "issue": "SSL Certificate Expiring Soon",
            "detail": f"Certificate expires in {ssl_result['days_remaining']} days.",
            "fix": "Renew your SSL certificate before it expires to avoid service disruption."
        })

    for header, info in headers_result.items():
        if not info["present"]:
            severity = "High" if SECURITY_HEADERS[header]["points"] >= 15 else "Medium"
            recs.append({
                "severity": severity,
                "issue": f"Missing Header: {header}",
                "detail": f"Risk: {info['risk']}",
                "fix": info["recommendation"]
            })

    return recs


def generate_pdf_report(d, buf):
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=20, textColor=colors.HexColor('#00d4ff'), spaceAfter=4)
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#1e40af'), spaceBefore=14, spaceAfter=6)
    normal = ParagraphStyle('Normal', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#1a1a2e'), spaceAfter=4)
    muted = ParagraphStyle('Muted', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#64748b'))

    story.append(Paragraph("Website Security Assessment Report", title_style))
    story.append(Paragraph(f"Scan Date: {d.get('scan_date')}  |  URL: {d.get('url')}", muted))
    story.append(Spacer(1, 12))

    score = d['score']['score']
    score_color = '#10b981' if score >= 80 else '#f59e0b' if score >= 60 else '#ef4444'
    story.append(Paragraph("Security Score", h2_style))
    story.append(Paragraph(f"<font color='{score_color}' size='24'><b>{score}/100</b></font> &nbsp; {d['score']['rating']}", normal))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Score Breakdown", h2_style))
    bd_data = [["Check", "Earned", "Max"]]
    for b in d['score']['breakdown']:
        bd_data.append([b['item'], str(b['earned']), str(b['points'])])
    bd_table = Table(bd_data, colWidths=[3.5*inch, 1*inch, 1*inch])
    bd_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f1829')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#00d4ff')),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(bd_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("HTTPS & SSL Certificate", h2_style))
    ssl = d['ssl']
    ssl_data = [
        ["HTTPS Enabled", "Yes" if d['https']['https_enabled'] else "No"],
        ["SSL Issuer", ssl['issuer']],
        ["Valid From", ssl['valid_from']],
        ["Expiry Date", ssl['expiry_date']],
        ["Days Remaining", str(ssl['days_remaining'])],
        ["Status", ssl['status']],
    ]
    ssl_table = Table(ssl_data, colWidths=[2.5*inch, 3*inch])
    ssl_table.setStyle(TableStyle([
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#64748b')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(ssl_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Security Headers", h2_style))
    hdr_data = [["Header", "Status", "Purpose"]]
    for hname, info in d['headers'].items():
        hdr_data.append([hname, info['status'], info['purpose']])
    hdr_table = Table(hdr_data, colWidths=[2.2*inch, 0.8*inch, 2.5*inch])
    hdr_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f1829')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#00d4ff')),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(hdr_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Recommendations", h2_style))
    sev_colors = {'Critical': '#ef4444', 'High': '#f97316', 'Medium': '#f59e0b'}
    for r in d['recommendations']:
        c = sev_colors.get(r['severity'], '#64748b')
        story.append(Paragraph(f"<font color='{c}'><b>[{r['severity']}] {r['issue']}</b></font>", normal))
        story.append(Paragraph(r['detail'], muted))
        story.append(Paragraph(f"<b>Fix:</b> {r['fix']}", normal))
        story.append(Spacer(1, 6))

    doc.build(story)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    raw_url = data.get("url", "").strip()
    if not raw_url:
        return jsonify({"error": "No URL provided"}), 400

    url = normalize_url(raw_url)
    domain = get_domain(url)
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    https_result = check_https(url)
    ssl_result = check_ssl(domain)
    headers_result = check_headers(url)
    score_result = calculate_score(https_result, ssl_result, headers_result)
    recommendations = generate_recommendations(https_result, ssl_result, headers_result)

    result = {
        "scan_date": scan_date,
        "url": url,
        "domain": domain,
        "https": https_result,
        "ssl": ssl_result,
        "headers": headers_result,
        "score": score_result,
        "recommendations": recommendations
    }
    return jsonify(result)


@app.route("/report/pdf", methods=["POST"])
def report_pdf():
    data = request.get_json()
    buf = io.BytesIO()
    generate_pdf_report(data, buf)
    buf.seek(0)
    filename = f"security_report_{data.get('domain', 'site').replace('.', '_')}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
