import json
from datetime import datetime

def log_security_event(event_type, source_ip, user, severity, status="Open"):
    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "source_ip": source_ip,
        "user": user,
        "severity": severity,
        "status": status,
        "siem_source": "Cyber Threat Detection System",
        "log_type": "Security Alert",
        "integration": "Splunk Ready"
    }

    with open("security_events.json", "a") as f:
        f.write(json.dumps(event) + "\n")