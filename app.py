import os

from flask import Flask, request, jsonify
from flask_cors import CORS
import re

# Serve static files from the "static" folder
app = Flask(__name__, static_url_path='', static_folder='static')
CORS(app)

# rest of your code stays the same

def detect_scam(text):
    text_lower = text.lower()
    score = 0
    reasons = []

    # 1. Urgency / pressure
    urgency_words = ["urgent", "immediately", "act now", "final notice", "account blocked"]
    if any(word in text_lower for word in urgency_words):
        score += 2
        reasons.append("Uses urgent or threatening language")

    # 2. Suspicious links
    if re.search(r"http[s]?://", text_lower):
        score += 2
        reasons.append("Contains a link")

        # Suspicious domains
        if any(domain in text_lower for domain in [".xyz", ".top", "bit.ly", "tinyurl"]):
            score += 2
            reasons.append("Uses suspicious or shortened link")

    # 3. Sensitive information
    sensitive_words = ["otp", "password", "pin", "bank details", "cvv"]
    if any(word in text_lower for word in sensitive_words):
        score += 3
        reasons.append("Requests sensitive information")

    # 4. Money / reward scams
    reward_words = ["winner", "lottery", "prize", "free money", "reward"]
    if any(word in text_lower for word in reward_words):
        score += 2
        reasons.append("Promises money or rewards")

    # 5. Impersonation (banks / companies)
    impersonation_words = ["fnb", "standard bank", "paypal", "dhl", "sars"]
    if any(word in text_lower for word in impersonation_words):
        score += 2
        reasons.append("Pretends to be a trusted organization")

    # 6. Emotional manipulation
    emotional_words = ["help me", "new number", "i'm in trouble", "please assist"]
    if any(word in text_lower for word in emotional_words):
        score += 2
        reasons.append("Uses emotional manipulation")

    # 7. Payment request
    payment_words = ["send money", "transfer", "pay now", "deposit"]
    if any(word in text_lower for word in payment_words):
        score += 3
        reasons.append("Requests payment")

    # FINAL RISK LEVEL
    if score >= 7:
        risk = "HIGH"
    elif score >= 3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return risk, reasons

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    text = data.get("text", "")

    risk, reasons = detect_scam(text)

    return jsonify({
        "risk": risk,
        "reasons": reasons
    })

@app.route("/")
def home():
    return app.send_static_file("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # use platform-provided port
    app.run(debug=True, host="0.0.0.0", port=port)