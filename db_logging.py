from pymongo import MongoClient
from datetime import datetime

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["cyberbridge"]
collection = db["events"]

def log_event(event_type, severity, details):
    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "severity": severity,
        "details": details
    }
    collection.insert_one(event)
    print(f"Logged: {event}")
