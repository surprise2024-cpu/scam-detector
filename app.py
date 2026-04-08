import os

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

    # ---------------- BASIC RULES ----------------

    # Urgency
    if any(word in text_lower for word in ["urgent", "immediately", "act now", "final notice", "account blocked"]):
        score += 2
        reasons.append("Uses urgent or threatening language")

    # Links
    has_link = bool(re.search(r"https?://", text_lower))
    if has_link:
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

    # Payment request
    if any(word in text_lower for word in ["send money", "transfer", "pay now", "deposit"]):
        score += 3
        reasons.append("Requests payment")

    # ---------------- EMAIL-SPECIFIC RULES ----------------

    # Generic greeting
    if any(word in text_lower for word in ["dear customer", "dear user", "valued customer"]):
        score += 2
        reasons.append("Uses generic greeting (common in phishing emails)")

    # Account/security language
    if any(word in text_lower for word in [
        "verify your account",
        "unusual activity",
        "suspended account",
        "account limited",
        "security alert"
    ]):
        score += 2
        reasons.append("Mentions account security issue")

    # Call-to-action pressure
    if any(word in text_lower for word in [
        "click below",
        "login now",
        "confirm immediately",
        "update your details"
    ]):
        score += 2
        reasons.append("Pushes immediate action")

    # Fake sender cues
    if any(word in text_lower for word in [
        "support team",
        "no-reply",
        "customer service",
        "security team"
    ]):
        score += 1
        reasons.append("Uses generic sender identity")

    if any(word in text_lower for word in [
        "inheritance", "beneficiary", "next of kin", "fund release", "unclaimed funds"
    ]):
        score += 4
        reasons.append("Mentions inheritance or unexpected funds")

    if re.search(r"[\w\.-]+@[\w\.-]+\.\w+", text):
        score += 3
        reasons.append("Asks you to contact via email (common scam tactic)")

    if any(word in text_lower for word in [
        "further info", "more details", "contact for details", "get more information"
    ]):
        score += 2
        reasons.append("Uses vague instructions instead of clear details")



    # ---------------- COMBINATION LOGIC (VERY IMPORTANT) ----------------

    # Link + urgency = strong phishing signal
    if has_link and any(word in text_lower for word in ["urgent", "immediately", "verify"]):
        score += 2
        reasons.append("Combines urgency with a link")

    # Link + impersonation
    if has_link and any(word in text_lower for word in ["paypal", "bank", "dhl", "sars"]):
        score += 2
        reasons.append("Link combined with trusted brand impersonation")

    # ---------------- FINAL DECISION ----------------

    if score >= 8:
        risk = "HIGH"
    elif score >= 4:
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
    if not request.is_json:
        return jsonify({"error": "Invalid JSON"}), 400

    data = request.json
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "Text cannot be empty"}), 400

    risk, reasons = detect_scam(text)
    save_scan(text, risk, reasons)

    return jsonify({"risk": risk, "reasons": reasons})

@app.route("/feedback", methods=["POST"])
def feedback():
    if not request.is_json:
        return jsonify({"error": "Invalid JSON"}), 400

    data = request.json
    text = data.get("text", "")
    feedback_text = data.get("feedback", "")

    if not text:
        return jsonify({"error": "Text cannot be empty"}), 400
    if not feedback_text:
        return jsonify({"error": "Feedback cannot be empty"}), 400

    save_feedback(text, feedback_text)

    return jsonify({"status": "success"})

@app.route("/")
def home():
    return app.send_static_file("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 443))
    app.run(host="0.0.0.0", port=port)