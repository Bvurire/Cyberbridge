from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017")

# List databases
print("Databases:", client.list_database_names())
db = client['cyberbridge']
threats = db['threat_logs']

sample_threat = {
    "timestamp": "2025-10-21T19:45:00",
    "source_ip": "192.168.1.10",
    "threat_type": "SQL Injection",
    "severity": "High",
    "description": "Detected suspicious query pattern"
}

threats.insert_one(sample_threat)
print("Threat inserted!")
