import requests
from db_client import threats_collection

def fetch_feed():
    url = "https://example-threat-feed.com/api/latest"  # replace with real feed URL
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        for item in data:
            threat_doc = {
                "threat_type": item.get("type"),
                "indicator": item.get("indicator"),
                "source": "ThreatFeed",
                "timestamp": item.get("timestamp")
            }
            threats_collection.insert_one(threat_doc)
        print("Feed data inserted successfully.")
    else:
        print("Failed to fetch feed:", response.status_code)
