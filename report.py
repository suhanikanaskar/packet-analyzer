from fpdf import FPDF
import time
from analyzer import get_findings

class SecurityReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 15)
        self.cell(0, 10, "Network Security Analysis Report", align="C", ln=True)
        self.set_font("Helvetica", "", 10)
        self.cell(0, 8, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", align="C", ln=True)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

def generate_report(findings, total_packets=0):
    pdf = SecurityReport()
    pdf.add_page()

    # Summary section
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_fill_color(30, 158, 117)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, "  Executive Summary", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    pdf.set_font("Helvetica", "", 11)
    high   = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    crit   = sum(1 for f in findings if f["severity"] == "CRITICAL")

    pdf.cell(0, 8, f"Total Packets Captured : {total_packets}", ln=True)
    pdf.cell(0, 8, f"Total Threats Detected : {len(findings)}", ln=True)
    pdf.cell(0, 8, f"Critical Threats       : {crit}", ln=True)
    pdf.cell(0, 8, f"High Threats           : {high}", ln=True)
    pdf.cell(0, 8, f"Medium Threats         : {medium}", ln=True)
    pdf.ln(5)

    # Threat findings section
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_fill_color(30, 158, 117)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, "  Threat Findings", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    if not findings:
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, "No threats detected during this capture session.", ln=True)
    else:
        for i, f in enumerate(findings, 1):
            # Color code by severity
            if f["severity"] == "CRITICAL":
                pdf.set_fill_color(226, 75, 74)
            elif f["severity"] == "HIGH":
                pdf.set_fill_color(239, 159, 39)
            else:
                pdf.set_fill_color(186, 117, 23)

            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(0, 8, f"  [{f['severity']}] {i}. {f['type']}", ln=True, fill=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 7, f"   Source IP : {f['src']}", ln=True)
            pdf.cell(0, 7, f"   Details   : {f['details']}", ln=True)
            pdf.cell(0, 7, f"   Time      : {f['time']}", ln=True)
            pdf.ln(3)

    # Recommendations section
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_fill_color(30, 158, 117)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, "  Recommendations", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    pdf.set_font("Helvetica", "", 11)
    recommendations = [
        "1. Block all suspicious source IPs at the firewall immediately.",
        "2. Enable HTTPS everywhere - disable plain HTTP (Port 80) traffic.",
        "3. Use a VPN to encrypt all network traffic.",
        "4. Enable IDS/IPS to automatically block detected threats.",
        "5. Regularly audit ARP tables to detect spoofing attempts.",
        "6. Change default passwords and disable unused network services.",
        "7. Keep all software and firmware updated with latest patches.",
    ]
    for r in recommendations:
        pdf.cell(0, 8, r, ln=True)

    # Save report
    filename = f"security_report_{time.strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    print(f"\n[*] Report saved as: {filename}")
    return filename

if __name__ == "__main__":
    findings = get_findings()
    generate_report(findings, total_packets=0)
    print("[*] Open the PDF file in your packet_analyzer folder!") 
