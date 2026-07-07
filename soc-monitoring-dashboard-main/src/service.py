PROJECT_NAME = "SOC Monitoring Dashboard"


import re
from datetime import datetime

RULES = [
    ("brute_force", "high", re.compile(r"(failed password|authentication failure|invalid user)", re.I)),
    ("malware_indicator", "critical", re.compile(r"(mimikatz|cobalt strike|powershell -enc|rundll32)", re.I)),
    ("privilege_escalation", "high", re.compile(r"(sudo:|sebackupprivilege|administrator group)", re.I)),
    ("data_exfiltration", "high", re.compile(r"(large upload|exfil|mega.nz|pastebin)", re.I)),
    ("suspicious_network", "medium", re.compile(r"(tor exit|beacon|dns tunnel)", re.I))
]

def analyze(payload):
    logs = payload.get("logs") or []
    if isinstance(logs, str):
        logs = logs.splitlines()
    alerts = []
    for index, line in enumerate(logs):
        for name, severity, pattern in RULES:
            if pattern.search(line):
                alerts.append({
                    "rule": name,
                    "severity": severity,
                    "line": index + 1,
                    "evidence": line[:220],
                    "recommended_action": "Triage host, preserve logs, and verify the activity against change tickets."
                })
    return {
        "processed_logs": len(logs),
        "alerts": alerts,
        "score": min(100, len(alerts) * 20),
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }

