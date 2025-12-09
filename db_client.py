from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()
mongo_uri = os.getenv("MONGO_URI")

client = MongoClient("mongodb://localhost:27017/")
db = client["cyberbridge"]
threats_collection = db["logs"]   # <-- use "logs" consistently

def save_threats(threats):
    for threat in threats:
        threats_collection.insert_one(threat)
        print("Threat inserted:", threat)


from pymongo import MongoClient


