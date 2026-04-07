from scapy.all import IP, TCP, UDP, ARP, Raw
from collections import defaultdict
import time

# Storage for tracking suspicious activity
syn_count = defaultdict(int)
port_access = defaultdict(set)
arp_table = {}
findings = []

def log_threat(threat_type, src_ip, details, severity="HIGH"):
    threat = {
        "type": threat_type,
        "src": src_ip,
        "details": details,
        "severity": severity,
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    findings.append(threat)
    print(f"\n{'='*50}")
    print(f"[{severity} THREAT] {threat_type}")
    print(f"Source IP : {src_ip}")
    print(f"Details   : {details}")
    print(f"Time      : {threat['time']}")
    print(f"{'='*50}\n")

# ---- DETECTION RULE 1: SYN Flood ----
def detect_syn_flood(packet):
    if TCP in packet and packet[TCP].flags == "S":
        src = packet[IP].src
        syn_count[src] += 1
        if syn_count[src] == 10:
            log_threat(
                "SYN Flood Attack",
                src,
                f"Sent {syn_count[src]} SYN packets — possible DoS attack",
                "HIGH"
            )

# ---- DETECTION RULE 2: Port Scan ----
def detect_port_scan(packet):
    if IP in packet and TCP in packet:
        src = packet[IP].src
        dport = packet[TCP].dport
        port_access[src].add(dport)
        if len(port_access[src]) == 10:
            log_threat(
                "Port Scan Detected",
                src,
                f"Scanned {len(port_access[src])} ports — possible reconnaissance",
                "MEDIUM"
            )

# ---- DETECTION RULE 3: Cleartext Credentials ----
def detect_credentials(packet):
    if packet.haslayer(Raw):
        payload = str(packet[Raw].load).lower()
        keywords = ["password=", "pass=", "user=", "login=", "username="]
        for kw in keywords:
            if kw in payload:
                src = packet[IP].src if IP in packet else "unknown"
                log_threat(
                    "Cleartext Credentials",
                    src,
                    f"Keyword '{kw}' found in unencrypted traffic!",
                    "HIGH"
                )

# ---- DETECTION RULE 4: ARP Spoofing ----
def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        if ip in arp_table and arp_table[ip] != mac:
            log_threat(
                "ARP Spoofing Detected",
                ip,
                f"IP {ip} changed MAC from {arp_table[ip]} to {mac} — possible MITM!",
                "CRITICAL"
            )
        arp_table[ip] = mac

# ---- MAIN ANALYZE FUNCTION ----
def analyze_packet(packet):
    detect_syn_flood(packet)
    detect_port_scan(packet)
    detect_credentials(packet)
    detect_arp_spoof(packet)

def get_findings():
    return findings
