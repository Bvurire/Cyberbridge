import requests
import os
import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables (OTX API key)
load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["cyberbridge"]
collection = db["confirmed_threats"]

def fetch_otx_pulses():
    """Fetch subscribed pulses from AlienVault OTX and store them in MongoDB."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        for pulse in data.get("results", []):
            threat_doc = {
                "timestamp": datetime.datetime.utcnow(),
                "source": "AlienVault OTX",
                "name": pulse.get("name"),
                "description": pulse.get("description"),
                "indicators": pulse.get("indicators", []),
                "tags": pulse.get("tags", []),
                "status": "confirmed"
            }
            collection.insert_one(threat_doc)
            print(f"Stored threat: {pulse.get('name')}")
    else:
        print("Error fetching data:", response.status_code)
