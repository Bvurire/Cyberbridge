import random
import time
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["cyberbridge"]
logs_collection = db["logs"]

# Sample threats
threat_types = [
    ("Port Scan Detected", "Low"),
    ("Failed Login Attempt", "Medium"),
    ("SQL Injection Attack", "High"),
    ("Malware Signature Found", "High"),
    ("Suspicious File Upload", "Medium"),
    ("Unusual Network Traffic", "Low"),
]

def generate_logs(n=20):
    for _ in range(n):
        threat, severity = random.choice(threat_types)
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "threat_type": threat,
            "severity": severity,
            "description": f"Simulated event: {threat}"
        }
        logs_collection.insert_one(log_entry)
        print(f"Inserted: {log_entry}")
        time.sleep(0.5)  # small delay for realism

if __name__ == "__main__":
    generate_logs(30)  # generate 30 fake logs
