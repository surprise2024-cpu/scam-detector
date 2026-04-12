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

    # ---------------- LINK + MARKETING COMBO (VERY IMPORTANT) ----------------

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

    if has_link and any(word in text_lower for word in [
        "shop now", "buy now", "claim now", "click here", "limited offer"
    ]):
        score += 4
        reasons.append("Combines link with marketing pressure (high-risk pattern)")

    if "shop now" in text_lower:
        score += 2
        reasons.append("Encourages immediate purchase action")

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

    # ---------------- EMAIL SCAM PATTERNS ----------------

    if any(word in text_lower for word in ["dear customer", "dear user", "valued customer"]):
        score += 2
        reasons.append("Generic greeting (phishing style)")

    if any(word in text_lower for word in [
        "verify your account", "unusual activity", "suspended account",
        "account limited", "security alert"
    ]):
        score += 2
        reasons.append("Mentions account security issue")

    if any(word in text_lower for word in [
        "click below", "login now", "confirm immediately", "update your details"
    ]):
        score += 2
        reasons.append("Pushes immediate action")

    if any(word in text_lower for word in [
        "inheritance", "beneficiary", "next of kin", "fund release", "unclaimed funds"
    ]):
        score += 4
        reasons.append("Mentions inheritance or unexpected funds")

    if re.search(r"[\w\.-]+@[\w\.-]+\.\w+", text):
        score += 3
        reasons.append("Contains email contact (common scam tactic)")

    if any(word in text_lower for word in [
        "further info", "more details", "contact for details"
    ]):
        score += 2
        reasons.append("Uses vague instructions")

    # ---------------- SMS / SPAM PATTERNS ----------------

    # Financial / insurance brands
    if any(word in text_lower for word in [
        "absa", "fnb", "standard bank", "nedbank", "capitec",
        "miway", "outsurance", "dialdirect", "king price"
    ]):
        score += 2
        reasons.append("Mentions financial/insurance brand (can be impersonated)")

    # Reply YES trap
    if "reply yes" in text_lower:
        score += 3
        reasons.append("User to reply YES (common scam tactic)")

    # Opt-out pattern
    if any(word in text_lower for word in ["optout", "opt out", "no=out", "stop"]):
        score += 3
        reasons.append("Mass messaging / bulk SMS pattern")

    # Unsolicited offer
    if any(word in text_lower for word in [
        "we would like to call", "discuss your", "offer you", "insurance options"
    ]):
        score += 2
        reasons.append("Unsolicited contact or offer")

    # Promotional language
    if any(word in text_lower for word in ["save", "low premium", "deal", "offer"]):
        score += 1
        reasons.append("Promotional persuasion language")

    # Price bait
    if re.search(r"r\d+\s*(per day|/day)", text_lower):
        score += 2
        reasons.append("Uses attractive pricing bait")

    # Fake personalization
    if re.match(r"^[a-z]+,", text_lower):
        score += 2
        reasons.append("Fake personalization (name-based spam)")

    # ---------------- COMBINATION LOGIC ----------------

    if has_link and "urgent" in text_lower:
        score += 2
        reasons.append("Combines urgency with a link")

    # ---------------- FINAL CLASSIFICATION ----------------

    # Label
    if score >= 10:
        label = "SCAM"
    elif score >= 6:
        label = "SPAM"
    elif score >= 3:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    # Confidence
    confidence = min(score * 10, 100)

    # Risk
    if confidence >= 81:
        risk = "HIGH"
    elif confidence >= 61:
        risk = "MEDIUM"
    elif confidence >= 31:
        risk = "LOW-MEDIUM"
    else:
        risk = "LOW"

    return label, confidence, risk, reasons


# ---------------- SAVE SCANS ----------------
def save_scan(text, label, confidence, risk, reasons):
    with open("scans.csv", "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), text, label, confidence, risk, "; ".join(reasons)])


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

    label, confidence, risk, reasons = detect_scam(text)

    save_scan(text, label, confidence, risk, reasons)

    return jsonify({
        "label": label,
        "confidence": confidence,
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

print("API KEY:", os.getenv("OPENAI_API_KEY"))

if __name__ == "__main__":
    app.run(debug=True)