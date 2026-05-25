from flask import Flask, render_template, request, send_file
import requests, warnings, os, time,builtwith
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter

warnings.filterwarnings("ignore")

app = Flask(__name__)

HEADERS = {
    "User-Agent":"Mozilla/5.0"
}

SECURITY_HEADERS = {
    "Content-Security-Policy":"High",
    "X-Frame-Options":"Medium",
    "X-Content-Type-Options":"Medium",
    "Strict-Transport-Security":"High"
}

DIRECTORIES = [
    "/admin",
    "/backup",
    "/uploads",
    "/test",
    "/.env"
]

# ── Scanner ───────────────────────────────────
def scan_website(url):

    start = time.time()

    findings = []

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=10,
            verify=False
        )

        # Website Status
        findings.append([
            "Website Status",
            f"HTTP {response.status_code}",
            "Info"
        ])

        # ── Security Headers ──────────────────
        for header, risk in SECURITY_HEADERS.items():

            if header in response.headers:

                findings.append([
                    header,
                    "Present",
                    "Safe"
                ])

            else:

                findings.append([
                    header,
                    "Missing",
                    risk
                ])

        # ── Open Directories ──────────────────
        for path in DIRECTORIES:

            target = urljoin(url, path)

            try:

                r = requests.get(
                    target,
                    headers=HEADERS,
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )

                if (
                    r.status_code in [200,301,302,403]
                    and "404" not in r.text.lower()
                ):

                    findings.append([
                        f"Directory: {path}",
                        f"FOUND ({r.status_code})",
                        "Medium"
                    ])

                else:

                    findings.append([
                        f"Directory: {path}",
                        "Not Found",
                        "Safe"
                    ])

            except:

                findings.append([
                    f"Directory: {path}",
                    "Error",
                    "Info"
                ])

                        # ── Technology Detection ──────────────────

        try:

            tech = builtwith.parse(url)

            if tech:

                for key, values in tech.items():

                    findings.append([

                        key.title(),

                        ", ".join(values),

                        "Info"
                    ])

            else:

                findings.append([

                    "Technology Detection",

                    "No Technology Detected",

                    "Info"
                ])

        except:

            findings.append([

                "Technology Detection",

                "Detection Failed",

                "Info"
            ])

        # ── Broken Link Finder ────────────────

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        links = soup.find_all("a", href=True)[:15]

        broken_found = False

        for link in links:

            href = link["href"]

            # Skip useless links
            if (
                href.startswith("#")
                or href.startswith("javascript")
                or href.startswith("mailto")
            ):
                continue

            full_url = urljoin(url, href)

            try:

                check = requests.get(
                    full_url,
                    headers=HEADERS,
                    timeout=5,
                    verify=False
                )

                if check.status_code >= 400:

                    findings.append([
                        "Broken Link",
                        full_url[:60],
                        "Low"
                    ])

                    broken_found = True

            except:

                findings.append([
                    "Broken Link",
                    full_url[:60],
                    "Low"
                ])

                broken_found = True

        if not broken_found:

            findings.append([
                "Broken Links",
                "No Broken Links Found",
                "Safe"
            ])

        # ── Generate PDF ──────────────────────
        pdf_path = generate_pdf(
            url,
            findings
        )

    except Exception as e:

        findings.append([
            "Error",
            str(e),
            "High"
        ])

        pdf_path = ""

    scan_time = round(
        time.time() - start,
        2
    )

    return findings, pdf_path, scan_time

# ── PDF Generator ─────────────────────────────
def generate_pdf(url, findings):

    os.makedirs("reports", exist_ok=True)

    domain = urlparse(url).netloc.replace(
        "www.",
        ""
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"reports/{domain}_{timestamp}.pdf"
    )

    pdf = SimpleDocTemplate(
        filename,
        pagesize=letter
    )

    styles = getSampleStyleSheet()

    elements = []

    title = Paragraph(
        "<b>WebXRay Security Report</b>",
        styles["Title"]
    )

    elements.append(title)

    elements.append(Spacer(1,12))

    target = Paragraph(
        f"<b>Target URL:</b> {url}",
        styles["Normal"]
    )

    elements.append(target)

    elements.append(Spacer(1,20))

    data = [
        ["Check","Status","Risk"]
    ] + findings

    table = Table(
        data,
        colWidths=[250,150,80]
    )

    table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),
        colors.HexColor("#38bdf8")),

        ("TEXTCOLOR",(0,0),(-1,0),
        colors.white),

        ("GRID",(0,0),(-1,-1),
        1,colors.grey),

        ("FONTNAME",(0,0),(-1,0),
        "Helvetica-Bold"),

    ]))

    elements.append(table)

    elements.append(Spacer(1,20))

    recommendations = """
    <b>Recommendations</b><br/><br/>

    • Add missing security headers
    (CSP, HSTS, X-Frame-Options).<br/><br/>

    • Restrict sensitive directories
    (/admin, /backup, etc.).<br/><br/>

    • Fix broken links found.<br/><br/>

    • Use HTTPS and valid SSL certificate.
    """

    rec = Paragraph(
        recommendations,
        styles["Normal"]
    )

    elements.append(rec)

    pdf.build(elements)

    return filename

# ── Home ──────────────────────────────────────
@app.route("/", methods=["GET","POST"])

def home():

    findings = []

    target = ""

    high = medium = safe = 0

    report_name = ""

    pdf_path = ""

    scan_time = 0

    if request.method == "POST":

        target = request.form["url"]

        if not target.startswith("http"):

            target = "https://" + target

        findings, pdf_path, scan_time = scan_website(
            target
        )

        high = len([
            f for f in findings
            if f[2] == "High"
        ])

        medium = len([
            f for f in findings
            if f[2] == "Medium"
        ])

        safe = len([
            f for f in findings
            if f[2] == "Safe"
        ])

        if pdf_path:

            report_name = pdf_path.split("/")[-1]

    return render_template(

        "index.html",

        findings=findings,

        target=target,

        high=high,

        medium=medium,

        safe=safe,

        report_name=report_name,

        pdf_path=pdf_path,

        scan_time=scan_time
    )

# ── Download PDF ──────────────────────────────
@app.route("/download/<filename>")

def download_file(filename):

    path = os.path.join(
        "reports",
        filename
    )

    return send_file(
        path,
        as_attachment=True
    )

# ── Run Flask ─────────────────────────────────
if __name__ == "__main__":

    app.run(debug=True)