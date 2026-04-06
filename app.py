from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import csv
from datetime import datetime

app = Flask(__name__, static_url_path='', static_folder='static')
CORS(app)

# ---------------- DETECTION LOGIC ----------------
def detect_scam(text):
    text_lower = text.lower()
    score = 0
    reasons = []

    # Urgency
    if any(word in text_lower for word in ["urgent", "immediately", "act now", "final notice", "account blocked"]):
        score += 2
        reasons.append("Uses urgent or threatening language")

    # Links
    if re.search(r"http[s]?://", text_lower):
        score += 2
        reasons.append("Contains a link")

        if any(domain in text_lower for domain in [".xyz", ".top", "bit.ly", "tinyurl"]):
            score += 2
            reasons.append("Uses suspicious or shortened link")

    # Sensitive info
    if any(word in text_lower for word in ["otp", "password", "pin", "bank details", "cvv"]):
        score += 3
        reasons.append("Requests sensitive information")

    # Rewards
    if any(word in text_lower for word in ["winner", "lottery", "prize", "free money", "reward"]):
        score += 2
        reasons.append("Promises money or rewards")

    # Impersonation
    if any(word in text_lower for word in ["fnb", "standard bank", "paypal", "dhl", "sars"]):
        score += 2
        reasons.append("Pretends to be a trusted organization")

    # Emotional manipulation
    if any(word in text_lower for word in ["help me", "new number", "i'm in trouble", "please assist"]):
        score += 2
        reasons.append("Uses emotional manipulation")

    # Payment request
    if any(word in text_lower for word in ["send money", "transfer", "pay now", "deposit"]):
        score += 3
        reasons.append("Requests payment")

    # Final risk
    if score >= 7:
        risk = "HIGH"
    elif score >= 3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return risk, reasons

# ---------------- SAVE SCANS ----------------
def save_scan(text, risk, reasons):
    with open("scans.csv", "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), text, risk, "; ".join(reasons)])

# ---------------- SAVE FEEDBACK ----------------
def save_feedback(text, feedback):
    with open("feedback.csv", "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), text, feedback])

# ---------------- ROUTES ----------------
@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    text = data.get("text", "")

    risk, reasons = detect_scam(text)

    save_scan(text, risk, reasons)

    return jsonify({
        "risk": risk,
        "reasons": reasons
    })

@app.route("/feedback", methods=["POST"])
def feedback():
    data = request.json
    text = data.get("text")
    feedback = data.get("feedback")

    save_feedback(text, feedback)

    return jsonify({"status": "success"})

@app.route("/")
def home():
    return app.send_static_file("index.html")

if __name__ == "__main__":
    app.run(debug=True)