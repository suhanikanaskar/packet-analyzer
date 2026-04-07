1.Network Packet Analyzer Tool

A cybersecurity project built with Python and Scapy to monitor 
and analyze network traffic for potential security threats.

2. Features
- Live packet capture using Scapy
- Threat detection (SYN Flood, Port Scan, ARP Spoofing, Cleartext Credentials)
- PDF security report generation
- Live web dashboard using Flask

3. Tools Used
- Python 3
- Scapy
- Flask
- fpdf2
- Npcap (Windows)

4. How to Run
1. Install requirements: pip install scapy flask fpdf2
2. Install Npcap from npcap.com
3. Run dashboard: python dashboard/app.py
4. Open browser: http://localhost:5000

5. Project Structure
- capture.py — packet capture module
- analyzer.py — threat detection engine
- report.py — PDF report generator
- dashboard/ — web dashboard
