from pymongo import MongoClient

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["cyberbridge"]
collection = db["confirmed_threats"]

def check_indicator(indicator_value):
    """Check if an indicator (IP, domain, hash) exists in confirmed threats."""
    result = collection.find_one({"indicators.indicator": indicator_value})
    if result:
        return True, result
    return False, None
