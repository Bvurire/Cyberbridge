from flask import Flask, request, jsonify
from detector import detect_threat
from db_client import save_threats, threats_collection   # keep both save_threats and threats_collection

app = Flask(__name__)

# Home route → simple welcome message (no HTML)
@app.route('/')
def home():
    return jsonify({"message": "CyberBridge Threat Detection API is running."})

# Scan route → processes submitted logs
@app.route('/scan', methods=['POST'])
def scan_log():
    log_entry = request.json.get('log')   # Expect JSON instead of form data
    detected = detect_threat(log_entry)
    save_threats(detected)
    return jsonify({"status": "success", "detected": detected})

# Dashboard route → returns stats + recent activity in JSON
@app.route('/dashboard')
def dashboard():
    # Group threats by type and count them
    pipeline = [
        {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}}
    ]
    results = list(threats_collection.aggregate(pipeline))

    # Fetch recent threats for activity feed (latest 5)
    recent = list(threats_collection.find().sort("timestamp", -1))  # no limit

    # Convert MongoDB objects to plain dicts
    results_clean = [{"threat_type": r["_id"], "count": r["count"]} for r in results]
    recent_clean = [
        {"timestamp": r["timestamp"], "threat_type": r["threat_type"],
         "severity": r["severity"], "description": r["description"]}
        for r in recent
    ]

    return jsonify({
        "stats": results_clean,
        "recent_activity": recent_clean
    })

if __name__ == '__main__':
    app.run(debug=True)

@app.route("/all_logs", methods=["GET"])
def all_logs():
    logs = list(threats_collection.find({}, {"_id": 0}))
    return jsonify({"logs": logs})

