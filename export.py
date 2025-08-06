from reportlab.lib.pagesizes import letter
import io
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import textwrap

def append_to_report_pdf(results, filename="scan_report.pdf"):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica-Bold", 16)
    c.setFillColor(colors.black)
    c.drawString(50, height - 50, "URL Safety Scan Report")
    y = height - 80
    line_height = 16

    for res in results:
        if y < 100:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica-Bold", 16)
            c.setFillColor(colors.black)
            c.drawString(50, height - 50, "URL Safety Scan Report (cont.)")
            y = height - 80

        if res.get('safety') == "Safe":
            c.setFillColor(colors.green)
        elif res.get('safety') == "Suspicious":
            c.setFillColor(colors.orange)
        elif res.get('safety') == "Unsafe":
            c.setFillColor(colors.red)
        elif res.get('safety') == "Very Unsafe":
            c.setFillColor(colors.darkred)
        else:
            c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"URL: {res.get('url', 'N/A')}")
        y -= line_height

        c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, f"Scan Conclusion: {res.get('safety', 'N/A')}")
        y -= line_height

        c.setFont("Helvetica", 10)
        c.drawString(50, y, f"Status: {res.get('status', 'N/A')}")
        y -= line_height
        c.drawString(50, y, f"Suspicion Score: {res.get('score', 'N/A')}")
        y -= line_height

        reasons = res.get('reasons', 'N/A')
        for i, line in enumerate(textwrap.wrap(reasons, width=90)):
            prefix = "Reasons: " if i == 0 else ""
            c.drawString(50, y, f"{prefix}{line}")
            y -= line_height

        c.drawString(50, y, f"VirusTotal Malicious Count: {res.get('vt_malicious', 'N/A')}")
        y -= line_height
        c.drawString(50, y, f"NVD CVE Count: {res.get('nvd_cve', 'N/A')}")
        y -= line_height

        cve_list = res.get('nvd_cve_details', [])
        if len(cve_list) > 5:
            cve_display = ', '.join(cve_list[:5]) + ', ...'
        else:
            cve_display = ', '.join(cve_list)
        for i, line in enumerate(textwrap.wrap(cve_display, width=90)):
            prefix = "NVD CVEs: " if i == 0 else ""
            c.drawString(50, y, f"{prefix}{line}")
            y -= line_height

        c.drawString(50, y, f"Timestamp: {res.get('timestamp', 'N/A')}")
        y -= line_height

        c.setStrokeColor(colors.grey)
        c.line(40, y, width - 40, y)
        y -= line_height

    c.save()
    buffer.seek(0)
    with open(filename, "wb") as f:
        f.write(buffer.getvalue())
