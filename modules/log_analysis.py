"""
modules/log_analysis.py — Log Analysis core logic for Obsidian Circuit
"""
import re
from collections import defaultdict, Counter
from datetime import datetime

# ---- Detection Thresholds ----
BRUTE_FORCE_THRESHOLD   = 5
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/.env", "/admin", "/wp-admin",
    "/config", "/.git", "/backup", "/phpMyAdmin", "/login",
    "/../", "/proc/", "cmd.exe", "shell.php", ".php?cmd=",
    "/phpmyadmin", "/.htaccess", "/.htpasswd", "/server-status",
    "/cgi-bin", "/etc/hosts",
]
SUSPICIOUS_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "python-requests",
    "curl/", "wget/", "dirbuster", "hydra", "metasploit", "burpsuite",
    "acunetix", "nessus", "openvas", "w3af", "havij",
]

# Windows Event ID descriptions
WIN_EVENT_IDS = {
    "4625": "Failed Logon",
    "4624": "Successful Logon",
    "4634": "Logoff",
    "4648": "Logon with Explicit Credentials",
    "4776": "Credential Validation",
    "4720": "Account Created",
    "4722": "Account Enabled",
    "4724": "Password Reset",
    "4728": "Member Added to Security Group",
    "4732": "Member Added to Local Group",
    "4756": "Member Added to Universal Group",
    "4698": "Scheduled Task Created",
    "4688": "New Process Created",
    "7045": "New Service Installed",
}

# ---- Log Patterns ----
AUTH_FAILED_RE  = re.compile(r"(Failed password|Invalid user|authentication failure|FAILED LOGIN)", re.I)
AUTH_SUCCESS_RE = re.compile(r"(Accepted password|session opened|Successful login|Accepted publickey)", re.I)
AUTH_IP_RE      = re.compile(r"from\s+([\d\.]+)\s+port|rhost=([\d\.]+)")
AUTH_USER_RE    = re.compile(r"for\s+(?:invalid user\s+)?(\w+)\s+from|user\s+(\w+)")
AUTH_DATE_RE    = re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})")
AUTH_PORT_RE    = re.compile(r"port\s+(\d+)")

APACHE_RE = re.compile(
    r'(?P<ip>[\d\.]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)
WIN_EVENT_RE = re.compile(r"4625|4624|4634|4648|4776|4720|4688|7045", re.I)


def _detect_log_type(lines: list) -> str:
    sample = "\n".join(lines[:20])
    if AUTH_FAILED_RE.search(sample) or "sshd" in sample or "su:" in sample:
        return "auth"
    if APACHE_RE.search(sample):
        return "apache"
    if "EventID" in sample or "Event ID" in sample or "4625" in sample:
        return "windows"
    return "generic"


def classify_ip(ip: str) -> str:
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return "Internal"
    if ip in ("unknown", "N/A", "-", ""):
        return "Unknown"
    return "External"


def analyze_log(content: str, log_type: str = "auto") -> dict:
    lines = content.splitlines()
    total_lines = len(lines)
    if log_type == "auto":
        log_type = _detect_log_type(lines)
    if log_type == "auth":
        return _analyze_auth_log(lines, total_lines)
    elif log_type == "apache":
        return _analyze_apache_log(lines, total_lines)
    elif log_type == "windows":
        return _analyze_windows_log(lines, total_lines)
    else:
        return _analyze_generic_log(lines, total_lines)


# ========== AUTH LOG ==========

def _analyze_auth_log(lines: list, total_lines: int) -> dict:
    failed_by_ip    = defaultdict(int)
    success_by_ip   = defaultdict(int)
    failed_users    = Counter()
    success_users   = Counter()
    source_ports    = defaultdict(list)   # ip → list of source ports used
    hour_counts     = Counter()           # hour → event count
    events          = []

    for line in lines:
        date_m    = AUTH_DATE_RE.match(line)
        timestamp = date_m.group(1) if date_m else "N/A"
        ip_m      = AUTH_IP_RE.search(line)
        ip        = (ip_m.group(1) or ip_m.group(2)) if ip_m else "unknown"
        user_m    = AUTH_USER_RE.search(line)
        user      = (user_m.group(1) or user_m.group(2)) if user_m else "unknown"
        port_m    = AUTH_PORT_RE.search(line)
        port      = port_m.group(1) if port_m else "-"

        # Hour tracking for timeline
        try:
            hour = re.search(r"(\d{2}):\d{2}:\d{2}", timestamp)
            if hour: hour_counts[int(hour.group(1))] += 1
        except Exception:
            pass

        if ip and port != "-":
            source_ports[ip].append(port)

        if AUTH_FAILED_RE.search(line):
            failed_by_ip[ip] += 1
            failed_users[user] += 1
            events.append({
                "timestamp": timestamp, "ip": ip, "user": user,
                "event": "Failed Login", "category": "AUTH_FAIL",
                "severity": "WARNING", "raw": line[:120], "port": port,
                "ip_class": classify_ip(ip),
            })
        elif AUTH_SUCCESS_RE.search(line):
            success_by_ip[ip] += 1
            success_users[user] += 1
            events.append({
                "timestamp": timestamp, "ip": ip, "user": user,
                "event": "Successful Login", "category": "AUTH_SUCCESS",
                "severity": "INFO", "raw": line[:120], "port": port,
                "ip_class": classify_ip(ip),
            })

    # Brute-force detection
    brute_force = []
    for ip, count in failed_by_ip.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            success = success_by_ip.get(ip, 0)
            severity = "CRITICAL" if success > 0 else "WARNING"
            brute_force.append({
                "severity": severity,
                "ip": ip,
                "failed_count": count,
                "success_count": success,
                "ip_class": classify_ip(ip),
                "unique_src_ports": len(set(source_ports.get(ip, []))),
                "description": (
                    f"IP {ip} ({classify_ip(ip)}) had {count} failed SSH login attempts" +
                    (f" followed by {success} successful login(s) — SUCCESSFUL BRUTE-FORCE!" if success else ".")
                ),
                "recommendation": "Block IP immediately. Review account for compromise. Enable MFA.",
            })

    unauthorized = []
    for ip, count in success_by_ip.items():
        fails = failed_by_ip.get(ip, 0)
        if fails == 0 and count > 1:
            unauthorized.append({
                "severity": "INFO",
                "ip": ip,
                "success_count": count,
                "ip_class": classify_ip(ip),
                "description": f"IP {ip} ({classify_ip(ip)}) logged in {count} times with no failures recorded.",
                "recommendation": "Verify this is an authorized access source.",
            })

    all_findings = brute_force + unauthorized
    if not all_findings:
        all_findings = [{"severity": "SAFE", "description": "No brute-force or suspicious login patterns detected.", "recommendation": "Log appears normal."}]

    return _build_result("auth", lines, total_lines, events, all_findings,
                        failed_by_ip, success_by_ip, failed_users,
                        extra={
                            "success_users": dict(success_users.most_common(10)),
                            "hour_counts": dict(hour_counts),
                            "source_ports": {ip: list(set(ports)) for ip, ports in source_ports.items()},
                        })


# ========== APACHE/NGINX LOG ==========

def _analyze_apache_log(lines: list, total_lines: int) -> dict:
    status_counts     = Counter()
    ip_requests       = Counter()
    ip_errors         = defaultdict(int)
    path_hits         = Counter()
    agent_counts      = Counter()
    method_counts     = Counter()
    hour_counts       = Counter()
    suspicious_paths  = []
    suspicious_agents = []
    large_uploads     = []
    events            = []
    total_bytes       = 0

    for line in lines:
        m = APACHE_RE.match(line)
        if not m:
            continue

        ip     = m.group("ip")
        dt     = m.group("time")
        method = m.group("method")
        path   = m.group("path")
        status = int(m.group("status"))
        size   = m.group("size")
        agent  = m.group("agent") or ""

        size_bytes = int(size) if size and size != "-" else 0
        total_bytes += size_bytes
        status_counts[status] += 1
        ip_requests[ip] += 1
        path_hits[path] += 1
        method_counts[method] += 1
        if agent:
            # Collapse to base agent name
            base_agent = agent.split("/")[0][:30]
            agent_counts[base_agent] += 1

        # Hour tracking
        try:
            hour_m = re.search(r":(\d{2}):\d{2}:\d{2}", dt)
            if hour_m: hour_counts[int(hour_m.group(1))] += 1
        except Exception:
            pass

        severity = "INFO"
        category = "ACCESS"
        if status >= 400:
            ip_errors[ip] += 1
            severity = "WARNING" if status == 403 else "INFO"
            category = "ERROR"

        for sp in SENSITIVE_PATHS:
            if sp.lower() in path.lower():
                severity = "CRITICAL"
                category = "SUSPICIOUS_PATH"
                suspicious_paths.append({
                    "severity": "CRITICAL", "ip": ip, "path": path, "status": status,
                    "description": f"IP {ip} accessed sensitive path '{path}' (HTTP {status}).",
                    "recommendation": "Block IP. Audit server configuration and access controls.",
                })
                break

        for sa in SUSPICIOUS_AGENTS:
            if sa.lower() in agent.lower():
                severity = "CRITICAL"
                category = "MALICIOUS_AGENT"
                suspicious_agents.append({
                    "severity": "CRITICAL", "ip": ip, "agent": agent[:80],
                    "description": f"IP {ip} used attack tool agent: '{agent[:60]}'.",
                    "recommendation": "Block IP. Review for injection/traversal/scanning attempts.",
                })
                break

        if method == "POST" and size_bytes > 100_000:
            large_uploads.append({
                "severity": "WARNING", "ip": ip, "path": path, "size_bytes": size_bytes,
                "description": f"IP {ip} made large POST to '{path}' ({size_bytes/1024:.1f} KB).",
                "recommendation": "Verify if upload is authorized. Check for file exfiltration.",
            })

        events.append({
            "timestamp": dt, "ip": ip, "user": "-",
            "event": f"{method} {path} → {status}",
            "category": category, "severity": severity,
            "raw": line[:120],
        })

    scanner_findings = []
    for ip, errors in ip_errors.items():
        if errors > 20:
            scanner_findings.append({
                "severity": "WARNING", "ip": ip, "error_count": errors,
                "description": f"IP {ip} generated {errors} HTTP error responses — vulnerability scanning behavior.",
                "recommendation": "Consider blocking. Review request types for specific attack patterns.",
            })

    all_findings = suspicious_paths + suspicious_agents + large_uploads + scanner_findings
    if not all_findings:
        all_findings = [{"severity": "SAFE", "description": "No suspicious web activity detected.", "recommendation": "Access log appears normal."}]

    return _build_result("apache", lines, total_lines, events, all_findings,
                        ip_requests, Counter(), Counter(),
                        extra={
                            "status_counts": dict(status_counts),
                            "top_paths": path_hits.most_common(10),
                            "agent_counts": dict(agent_counts.most_common(10)),
                            "method_counts": dict(method_counts),
                            "hour_counts": dict(hour_counts),
                            "total_bytes_served": total_bytes,
                        })


# ========== WINDOWS LOG ==========

def _analyze_windows_log(lines: list, total_lines: int) -> dict:
    events         = []
    failed_logins  = defaultdict(int)
    success_logins = defaultdict(int)
    event_id_counts = Counter()
    logon_types    = Counter()             # Logon Type 3=Network, 10=RemoteInteractive etc
    all_findings   = []
    hour_counts    = Counter()

    LOGON_TYPES = {
        "2": "Interactive (console)",
        "3": "Network (file share)",
        "4": "Batch",
        "5": "Service",
        "7": "Unlock",
        "8": "NetworkCleartext",
        "9": "NewCredentials",
        "10": "RemoteInteractive (RDP)",
        "11": "CachedInteractive",
    }

    for line in lines:
        parts = [p.strip() for p in line.split(",")]

        # Extract event ID
        eid = None
        for eid_candidate in WIN_EVENT_IDS:
            if eid_candidate in line:
                eid = eid_candidate
                event_id_counts[eid] += 1
                break

        # Extract IP — last valid dotted IP in line
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        ip = ips[-1] if ips else "unknown"

        # Extract logon type
        lt_m = re.search(r"Logon Type:\s*(\d+)|Type.*?(\d+)", line, re.I)
        logon_type_raw = (lt_m.group(1) or lt_m.group(2)) if lt_m else None
        logon_type_label = LOGON_TYPES.get(logon_type_raw, f"Type {logon_type_raw}") if logon_type_raw else "-"

        # Extract time from first field
        timestamp = parts[0] if parts else "N/A"
        try:
            hour_m = re.search(r"(\d{2}):\d{2}:\d{2}", timestamp)
            if hour_m: hour_counts[int(hour_m.group(1))] += 1
        except Exception:
            pass

        if eid == "4625":
            failed_logins[ip] += 1
            events.append({
                "timestamp": timestamp, "ip": ip, "user": "-",
                "event": f"Failed Logon (4625) via {logon_type_label}",
                "severity": "WARNING", "category": "AUTH_FAIL",
                "raw": line[:120], "ip_class": classify_ip(ip),
            })
        elif eid == "4624":
            success_logins[ip] += 1
            events.append({
                "timestamp": timestamp, "ip": ip, "user": "-",
                "event": f"Successful Logon (4624) via {logon_type_label}",
                "severity": "INFO", "category": "AUTH_SUCCESS",
                "raw": line[:120], "ip_class": classify_ip(ip),
            })
        elif eid == "4688":
            events.append({
                "timestamp": timestamp, "ip": ip, "user": "-",
                "event": "New Process Created (4688)",
                "severity": "INFO", "category": "PROCESS",
                "raw": line[:120], "ip_class": classify_ip(ip),
            })
        elif eid == "7045":
            events.append({
                "timestamp": timestamp, "ip": ip, "user": "-",
                "event": "New Service Installed (7045)",
                "severity": "WARNING", "category": "SERVICE",
                "raw": line[:120], "ip_class": classify_ip(ip),
            })
        elif eid:
            events.append({
                "timestamp": timestamp, "ip": ip, "user": "-",
                "event": f"{WIN_EVENT_IDS.get(eid, 'Event')} ({eid})",
                "severity": "INFO", "category": "WINDOWS_EVENT",
                "raw": line[:120], "ip_class": classify_ip(ip),
            })

        if logon_type_raw:
            logon_types[logon_type_label] += 1

    for ip, count in failed_logins.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            success = success_logins.get(ip, 0)
            all_findings.append({
                "severity": "CRITICAL" if success else "WARNING",
                "ip": ip, "failed_count": count, "success_count": success,
                "ip_class": classify_ip(ip),
                "description": (
                    f"IP {ip} ({classify_ip(ip)}): {count} failed Windows logon events" +
                    (f" + {success} successful logon(s) — ACCOUNT COMPROMISED!" if success else ".")
                ),
                "recommendation": "Review Security Event log. Enforce lockout policy. Enable MFA.",
            })

    if not all_findings:
        all_findings = [{"severity": "SAFE", "description": "No suspicious Windows logon events detected.", "recommendation": "Event log appears normal."}]

    return _build_result("windows", lines, total_lines, events, all_findings,
                        failed_logins, success_logins, Counter(),
                        extra={
                            "event_id_counts": dict(event_id_counts),
                            "logon_types": dict(logon_types),
                            "hour_counts": dict(hour_counts),
                        })


# ========== GENERIC LOG ==========

def _analyze_generic_log(lines: list, total_lines: int) -> dict:
    keywords = {
        "CRITICAL": ["critical", "fatal", "exploit", "attack", "malware", "ransomware",
                     "rootkit", "c2", "beacon", "exfiltration", "log4shell", "rce",
                     "injection", "shell", "compromise", "backdoor"],
        "WARNING":  ["error", "warning", "warn", "fail", "denied", "refused",
                     "blocked", "unauthorized", "invalid", "timeout", "brute"],
        "INFO":     ["info", "notice", "debug", "success", "completed"],
    }
    events          = []
    all_findings    = []
    keyword_counts  = Counter()
    source_ips      = Counter()
    hour_counts     = Counter()

    for line in lines:
        lower = line.lower()
        # Extract IPs from line
        found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        ip = found_ips[0] if found_ips else "N/A"
        if ip != "N/A":
            source_ips[ip] += 1

        # Hour extraction
        try:
            hour_m = re.search(r"T?(\d{2}):\d{2}:\d{2}", line)
            if hour_m: hour_counts[int(hour_m.group(1))] += 1
        except Exception:
            pass

        for sev, words in keywords.items():
            if any(w in lower for w in words):
                events.append({
                    "timestamp": "N/A", "ip": ip,
                    "event": line[:100], "category": "KEYWORD_MATCH",
                    "severity": sev, "raw": line[:120], "user": "-",
                })
                keyword_counts[sev] += 1
                break

    if keyword_counts.get("CRITICAL", 0) > 0:
        all_findings.append({
            "severity": "CRITICAL",
            "description": f"Found {keyword_counts['CRITICAL']} lines with CRITICAL-level keywords (exploit, attack, malware, C2 beacon etc.).",
            "recommendation": "Manually review all CRITICAL flagged lines immediately.",
        })
    if keyword_counts.get("WARNING", 0) > 0:
        all_findings.append({
            "severity": "WARNING",
            "description": f"Found {keyword_counts['WARNING']} lines with warning-level keywords (error, fail, denied, blocked).",
            "recommendation": "Review errors and access denials for signs of lateral movement.",
        })
    if not all_findings:
        all_findings = [{"severity": "SAFE", "description": "No critical keywords found in log.", "recommendation": "Log appears clean on surface-level scan."}]

    return _build_result("generic", lines, total_lines, events, all_findings,
                        Counter(), Counter(), Counter(),
                        extra={
                            "top_source_ips": dict(source_ips.most_common(10)),
                            "keyword_counts": dict(keyword_counts),
                            "hour_counts": dict(hour_counts),
                        })


def _build_result(log_type, lines, total_lines, events, all_findings,
                  failed_logins, success_logins, failed_users, extra=None) -> dict:
    overall_severity = "SAFE"
    if any(f.get("severity") == "CRITICAL" for f in all_findings):
        overall_severity = "CRITICAL"
    elif any(f.get("severity") == "WARNING" for f in all_findings):
        overall_severity = "WARNING"
    elif any(f.get("severity") == "INFO" for f in all_findings):
        overall_severity = "INFO"

    result = {
        "log_type":           log_type,
        "total_lines":        total_lines,
        "parsed_events":      len(events),
        "events":             events[:500],
        "all_findings":       all_findings,
        "overall_severity":   overall_severity,
        "failed_logins_by_ip":  dict(failed_logins),
        "success_logins_by_ip": dict(success_logins),
        "top_failed_users":     dict(failed_users.most_common(10)),
        "top_attacker_ips":     dict(Counter(failed_logins).most_common(10)),
    }
    if extra:
        result.update(extra)
    return result
