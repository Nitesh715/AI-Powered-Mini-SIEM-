"""Transparent, explainable detection rules for a learning SIEM."""
from datetime import datetime

def analyze_event(event):
    text = " ".join(str(event.get(k, "")) for k in ("event_type", "details")).lower()
    score, reasons = 0, []
    if any(x in text for x in ("failed login", "login failed", "authentication failure")):
        score += 35
        reasons.append("Failed authentication activity")
    if any(x in text for x in ("port scan", "nmap", "syn scan")):
        score += 45
        reasons.append("Possible port scanning activity")
    if any(x in text for x in ("malware", "ransomware", "trojan")):
        score += 60
        reasons.append("Malware-related indicator in event")
    if any(x in text for x in ("privilege escalation", "sudoers changed", "admin group")):
        score += 50
        reasons.append("Possible privilege or account change")
    if any(x in text for x in ("powershell encoded", "encoded command", "suspicious script")):
        score += 50
        reasons.append("Potentially suspicious script execution")
    if event.get("source_ip", "").startswith(("10.", "192.168.", "172.16.")):
        # Private addresses are not inherently malicious; no score is added.
        pass
    score = min(score, 100)
    severity = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35 else "Low"
    return {"risk_score": score, "severity": severity, "reason": "; ".join(reasons) if reasons else "No rule matched"}

def should_alert(result):
    return result["risk_score"] >= 35
