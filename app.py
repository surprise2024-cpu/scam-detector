from flask import Flask, request, jsonify
from flask_cors import CORS
import re

# Serve static files from the "static" folder
app = Flask(__name__, static_url_path='', static_folder='static')
CORS(app)

# rest of your code stays the same

def detect_scam(text):
    score = 0
    reasons = []

    # Rule 1: Urgency words
    if any(word in text.lower() for word in ["urgent", "immediately", "account blocked"]):
        score += 2
        reasons.append("Contains urgent language")

    # Rule 2: Link detection
    if re.search(r"http[s]?://", text):
        score += 2
        reasons.append("Contains a link")

    # Rule 3: Sensitive info
    if any(word in text.lower() for word in ["otp", "password", "pin", "bank"]):
        score += 2
        reasons.append("Requests sensitive information")

    # Risk calculation
    if score >= 4:
        risk = "HIGH"
    elif score >= 2:
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
    app.run(debug=True)