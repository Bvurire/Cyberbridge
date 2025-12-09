from pymongo import MongoClient
from dotenv import load_dotenv
import os

import re
from datetime import datetime
# Load environment variables
load_dotenv()
mongo_uri = os.getenv("MONGO_URI")

# Connect to MongoDB
client = MongoClient(mongo_uri)
db = client['cyberbridge']
threats_collection = db['threat_logs']


def detect_threat(log_entry):
    threats = []

    # Example patterns
    patterns = {
        "SQL Injection": r"(?i)(?:')|(?:--)|(/\*(?:.|[\n\r])*?\*/)|(select|insert|delete|update|drop|union|exec)",
        "XSS Attack": r"(<script.*?>.*?</script>)",
        "Brute Force": r"(Failed login attempt)",
        "Phishing": r"(http[s]?://[^\\s]*login[^\\s]*)"
    }

    for threat_type, pattern in patterns.items():
        if re.search(pattern, log_entry, re.IGNORECASE):
            threats.append({
                "timestamp": datetime.now().isoformat(),
                "threat_type": threat_type,
                "severity": "High" if threat_type in ["SQL Injection", "XSS Attack"] else "Medium",
                "description": f"Pattern matched: {pattern}"
            })

    return threats

sample_log = "User tried to login with ' OR 1=1 -- and failed multiple times."

detected = detect_threat(sample_log)
for threat in detected:
    threats_collection.insert_one(threat)   # store in MongoDB
    print("Threat inserted:", threat)




