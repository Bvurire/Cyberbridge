import re
from datetime import datetime
from db_logging import log_event # NEW: import the MongoDB logger
from db_queries import check_indicator

def detect_event(event):
    """Simulate CyberBridge detection and validation against MongoDB."""
    indicator = event.get("indicator")
    found, threat = check_indicator(indicator)

    if found:
        print(f"Validated threat detected: {indicator}")
        return {"status": "validated", "details": threat}
    else:
        print(f"Potential false positive: {indicator}")
        return {"status": "unconfirmed", "details": None}
def detect_threat(log_entry):
    threats = []
    patterns = {
        "SQL Injection": r"(?:')|(?:--)|(/\*(?:.|[\n\r])*?\*/)|(select|insert|delete|update|drop|union|exec)",
        "XSS Attack": r"(<script.*?>.*?</script>)",
        "Brute Force": r"(Failed login attempt)",
        "Phishing": r"(http[s]?://[^\s]*login[^\s]*)"
    }

    for threat_type, pattern in patterns.items():
        if re.search(pattern, log_entry, re.IGNORECASE):
            severity = "High" if threat_type in ["SQL Injection", "XSS Attack"] else "Medium"
            description = f"Pattern matched: {pattern}"

            threat = {
                "timestamp": datetime.now().isoformat(),
                "threat_type": threat_type,
                "severity": severity,
                "description": description
            }
            threats.append(threat)

            # NEW: log directly to MongoDB
            log_event(threat_type, severity, description)

    return threats
