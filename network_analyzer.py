import nmap
import socket
import datetime
import psutil
from fpdf import FPDF
from port_vuln_db import port_vuln_db  

# Get local IP
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'
    finally:
        s.close()

# Perform the port scan
def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-sV')
    return scanner[ip]

# Create PDF report
def create_pdf_report(ip, scan_data, filename='network_report.pdf'):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_title(f"{ip} Network Report")

    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, txt=f"Network Report for {ip}", ln=True, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Scan Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)

    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, "Open Ports and Services", ln=True)
    pdf.set_font("Arial", size=12)

    for proto in scan_data.all_protocols():
        ports = scan_data[proto].keys()
        for port in sorted(ports):
            service = scan_data[proto][port]['name']
            version = scan_data[proto][port].get('version', 'unknown')
            line = f"Port {port}/{proto} - Service: {service}, Version: {version}"
            pdf.cell(200, 10, txt=line, ln=True)

            # Port-based vulnerability info from external DB
            port_info = port_vuln_db.get(port)
            if port_info:
                pdf.set_font("Arial", 'I', 11)
                pdf.multi_cell(0, 10, f"  -> Port {port} Risks: {port_info['attack']}\n  -> Port Precaution: {port_info['precaution']}")
                pdf.set_font("Arial", size=12)

    pdf.output(f"{ip}_network_report.pdf")

# Main execution
if __name__ == '__main__':
    print("[*] Getting local IP...")
    ip_address = get_local_ip()
    print(f"[*] Scanning IP: {ip_address}")

    try:
        scan_result = scan_ports(ip_address)
        print("[*] Scan complete. Generating PDF report...")
        create_pdf_report(ip_address, scan_result)
        print(f"[+] Report saved as {ip_address}_network_report.pdf")
    except Exception as e:
        print(f"[!] Error: {e}")
