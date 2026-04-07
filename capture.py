from scapy.all import sniff, IP, TCP, UDP
from analyzer import analyze_packet, get_findings
from report import generate_report

IFACE = "\\Device\\NPF_{6CF8E98B-01C9-40B0-BFEC-0D1EAE84B658}"
packet_count = 0

def packet_handler(packet):
    global packet_count
    if IP in packet:
        packet_count += 1
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
        port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
        print(f"[+] {src} → {dst} | {proto} | Port: {port}")
        analyze_packet(packet)

print("[*] Starting packet capture for 30 seconds...")
print("[*] Open your browser and visit websites NOW!\n")

# Automatically stops after 30 seconds!
sniff(iface=IFACE,
      prn=packet_handler,
      store=False,
      filter="ip",
      timeout=30)

print("\n[*] Capture complete!")
findings = get_findings()
print(f"[*] Packets captured : {packet_count}")
print(f"[*] Threats detected : {len(findings)}")
print("[*] Generating PDF report...")
generate_report(findings, total_packets=packet_count)
print("[*] Done! Check your packet_analyzer folder for the PDF!")