"""
modules/network_analysis.py — Network Analysis core logic for Obsidian Circuit
Parses .pcap files, detects port scans, DNS anomalies, data exfiltration
"""
import io
from collections import defaultdict, Counter
from datetime import datetime


# ---- Detection Thresholds ----
PORT_SCAN_THRESHOLD      = 15
DNS_TUNNEL_NAME_LEN      = 40
DNS_HIGH_RATE_THRESHOLD  = 30
EXFIL_BYTES_THRESHOLD    = 500_000
PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                    "172.29.", "172.30.", "172.31.", "127.", "::1", "fc", "fd")

# Known malicious / suspicious ports
SUSPICIOUS_PORTS = {
    4444:  "Metasploit default handler",
    1337:  "Common hacker/backdoor port",
    31337: "Back Orifice RAT",
    8080:  "Alternate HTTP (proxy/C2)",
    9090:  "Common C2/proxy port",
    6667:  "IRC (botnet C2)",
    6666:  "IRC / backdoor",
    1234:  "Common test/backdoor port",
    12345: "NetBus RAT",
    54321: "Common backdoor",
    5555:  "ADB / Android exploit",
    3389:  "RDP (brute-force target)",
    445:   "SMB (EternalBlue target)",
    135:   "DCOM / WMI exploit target",
    23:    "Telnet (cleartext, insecure)",
}


def is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def classify_ip(ip: str) -> str:
    if ip.startswith("10."):
        return "Private (Class A)"
    if ip.startswith("192.168."):
        return "Private (Class C)"
    if ip.startswith("172."):
        return "Private (Class B)"
    if ip.startswith("127."):
        return "Loopback"
    return "External / Public"


def analyze_pcap(file_bytes: bytes) -> dict:
    """Parse a .pcap file and return structured network analysis findings."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
    except ImportError:
        return {"error": "scapy not installed. Run: pip install scapy"}

    try:
        packets = rdpcap(io.BytesIO(file_bytes))
    except Exception as e:
        return {"error": f"Failed to parse pcap file: {str(e)}"}

    total_packets = len(packets)
    if total_packets == 0:
        return {"error": "PCAP file contains no packets."}

    # --- Aggregate data ---
    ip_pairs          = Counter()
    src_ports         = defaultdict(set)      # src_ip → set of dst_ports
    protocol_counts   = Counter()
    ip_bytes_out      = defaultdict(int)
    ip_bytes_in       = defaultdict(int)
    dns_queries       = defaultdict(list)
    dns_domains       = Counter()             # domain → count
    connections       = []
    timestamps        = []
    tcp_flags_count   = Counter()             # SYN, ACK, RST, FIN counts
    dst_port_counts   = Counter()             # destination port → packet count
    suspicious_port_hits = []                # list of (src_ip, dst_ip, port, label)
    ip_set            = set()

    for pkt in packets:
        try:
            ts = float(pkt.time)
            timestamps.append(ts)

            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                pkt_len = len(pkt)

                ip_set.add(src)
                ip_set.add(dst)
                ip_pairs[(src, dst)] += 1
                ip_bytes_out[src] += pkt_len
                ip_bytes_in[dst]  += pkt_len

                if pkt.haslayer(TCP):
                    protocol_counts["TCP"] += 1
                    dport = pkt[TCP].dport
                    sport = pkt[TCP].sport
                    flags = pkt[TCP].flags

                    src_ports[src].add(dport)
                    dst_port_counts[dport] += 1

                    # TCP flag breakdown
                    if flags & 0x02: tcp_flags_count["SYN"] += 1
                    if flags & 0x10: tcp_flags_count["ACK"] += 1
                    if flags & 0x04: tcp_flags_count["RST"] += 1
                    if flags & 0x01: tcp_flags_count["FIN"] += 1
                    if flags & 0x08: tcp_flags_count["PSH"] += 1

                    # Suspicious port detection
                    if dport in SUSPICIOUS_PORTS:
                        suspicious_port_hits.append({
                            "src_ip": src, "dst_ip": dst,
                            "port": dport,
                            "label": SUSPICIOUS_PORTS[dport],
                        })

                    connections.append({
                        "time": ts, "src": src, "dst": dst,
                        "proto": "TCP", "sport": sport, "dport": dport,
                        "size": pkt_len, "flags": str(pkt[TCP].flags)
                    })

                elif pkt.haslayer(UDP):
                    protocol_counts["UDP"] += 1
                    dport = pkt[UDP].dport
                    src_ports[src].add(dport)
                    dst_port_counts[dport] += 1
                    connections.append({
                        "time": ts, "src": src, "dst": dst,
                        "proto": "UDP", "sport": pkt[UDP].sport,
                        "dport": dport, "size": pkt_len, "flags": ""
                    })

                    # DNS extraction
                    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                        qname = pkt[DNSQR].qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="replace")
                        qname = qname.rstrip(".")
                        dns_queries[src].append(qname)
                        # Extract base domain (last 2 parts)
                        parts = qname.split(".")
                        base = ".".join(parts[-2:]) if len(parts) >= 2 else qname
                        dns_domains[base] += 1

                elif pkt.haslayer("ICMP"):
                    protocol_counts["ICMP"] += 1
                else:
                    protocol_counts["Other"] += 1
        except Exception:
            continue

    # --- Port Scan Detection ---
    port_scan_findings = []
    for src_ip, ports in src_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            severity = "CRITICAL" if len(ports) > 50 else "WARNING"
            port_scan_findings.append({
                "severity": severity,
                "src_ip": src_ip,
                "port_count": len(ports),
                "sample_ports": sorted(list(ports))[:20],
                "description": f"IP {src_ip} contacted {len(ports)} unique ports — likely port scanning activity.",
                "recommendation": "Block IP and investigate source. Review firewall rules.",
            })

    # --- DNS Anomaly Detection ---
    dns_findings = []
    for src_ip, queries in dns_queries.items():
        if len(queries) >= DNS_HIGH_RATE_THRESHOLD:
            dns_findings.append({
                "severity": "WARNING",
                "src_ip": src_ip,
                "query_count": len(queries),
                "description": f"IP {src_ip} made {len(queries)} DNS queries — suspicious DNS activity or potential beaconing.",
                "recommendation": "Analyze DNS query patterns. Check for domain generation algorithms (DGA).",
            })
        long_queries = [q for q in queries if len(q) > DNS_TUNNEL_NAME_LEN]
        if long_queries:
            dns_findings.append({
                "severity": "CRITICAL",
                "src_ip": src_ip,
                "query_count": len(long_queries),
                "example": long_queries[0][:80],
                "description": f"IP {src_ip} made {len(long_queries)} DNS queries with unusually long names — possible DNS tunneling.",
                "recommendation": "Inspect DNS traffic for encoded payloads. Block suspicious domains.",
            })

    # --- Data Exfiltration Detection ---
    exfil_findings = []
    for src_ip, total_bytes in ip_bytes_out.items():
        if total_bytes >= EXFIL_BYTES_THRESHOLD:
            external_dests = [d for (s, d) in ip_pairs if s == src_ip and not is_private(d)]
            if external_dests:
                severity = "CRITICAL" if total_bytes > 5_000_000 else "WARNING"
                exfil_findings.append({
                    "severity": severity,
                    "src_ip": src_ip,
                    "bytes_sent": total_bytes,
                    "external_dests": list(set(external_dests))[:5],
                    "description": f"IP {src_ip} sent {total_bytes / 1024:.1f} KB to external destinations — potential data exfiltration.",
                    "recommendation": "Capture and inspect payload contents. Verify if transfer is authorized.",
                })

    # --- Suspicious Port Findings ---
    susp_port_findings = []
    seen_susp = set()
    for hit in suspicious_port_hits:
        key = (hit["src_ip"], hit["port"])
        if key not in seen_susp:
            seen_susp.add(key)
            susp_port_findings.append({
                "severity": "WARNING",
                "src_ip": hit["src_ip"],
                "description": f"Connection to port {hit['port']} ({hit['label']}) from {hit['src_ip']} → {hit['dst_ip']}.",
                "recommendation": f"Verify if port {hit['port']} usage is legitimate. This port is associated with: {hit['label']}.",
                "port": hit["port"],
                "label": hit["label"],
            })

    # --- IP Classification Summary ---
    ip_classification = Counter(classify_ip(ip) for ip in ip_set)

    # --- Top Destination Ports ---
    top_dst_ports = dst_port_counts.most_common(15)

    # --- Top Talkers ---
    top_talkers = Counter(ip_bytes_out).most_common(10)

    # --- Timeline ---
    if timestamps:
        duration   = max(timestamps) - min(timestamps)
        start_time = datetime.fromtimestamp(min(timestamps)).strftime("%Y-%m-%d %H:%M:%S")
        end_time   = datetime.fromtimestamp(max(timestamps)).strftime("%Y-%m-%d %H:%M:%S")
    else:
        duration = 0
        start_time = end_time = "N/A"

    all_findings = port_scan_findings + dns_findings + exfil_findings + susp_port_findings
    if not all_findings:
        all_findings = [{
            "severity": "SAFE",
            "description": "No suspicious network patterns detected in this capture.",
            "recommendation": "Traffic appears normal, but manual review is always recommended.",
        }]

    overall_severity = "SAFE"
    if any(f["severity"] == "CRITICAL" for f in all_findings):
        overall_severity = "CRITICAL"
    elif any(f["severity"] == "WARNING" for f in all_findings):
        overall_severity = "WARNING"

    return {
        "total_packets":      total_packets,
        "protocol_counts":    dict(protocol_counts),
        "top_talkers":        top_talkers,
        "unique_ips":         len(ip_set),
        "start_time":         start_time,
        "end_time":           end_time,
        "duration_seconds":   round(duration, 2),
        "port_scan_findings": port_scan_findings,
        "dns_findings":       dns_findings,
        "exfil_findings":     exfil_findings,
        "susp_port_findings": susp_port_findings,
        "all_findings":       all_findings,
        "overall_severity":   overall_severity,
        "connections_sample": connections[:200],
        "dns_queries_total":  sum(len(v) for v in dns_queries.values()),
        "dns_top_domains":    dns_domains.most_common(15),
        "ip_bytes_out":       dict(ip_bytes_out),
        "ip_bytes_in":        dict(ip_bytes_in),
        "tcp_flags":          dict(tcp_flags_count),
        "top_dst_ports":      top_dst_ports,
        "ip_classification":  dict(ip_classification),
    }
