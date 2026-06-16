from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
import requests

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    result = db.Column(db.String(50))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    url = request.form.get("url", "").strip()

    if not url:
        return render_template(
            "index.html",
            result="Invalid URL",
            risk_score=100,
            scanned_url="",
            reason="No URL Entered"
        )

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        requests.get(url, timeout=5)

        suspicious_keywords = [
            "login",
            "verify",
            "secure",
            "account",
            "banking",
            "update",
            "paypal",
            "free",
            "gift",
            "win",
            "bonus"
        ]

        risk_score = 0
        reasons = []

        if url.startswith("https://"):
            risk_score += 10
        else:
            risk_score += 40
            reasons.append("No HTTPS")

        if len(url) > 75:
            risk_score += 20
            reasons.append("Very Long URL")

        if "@" in url:
            risk_score += 25
            reasons.append("Contains @ Symbol")

        if "-" in url:
            risk_score += 10
            reasons.append("Contains Hyphen")

        for word in suspicious_keywords:
            if word in url.lower():
                risk_score += 15
                reasons.append(f"Contains '{word}'")

        if risk_score <= 20:
            result = "Safe"
        elif risk_score <= 50:
            result = "Suspicious"
        else:
            result = "Malicious"

        if not reasons:
            reasons.append("No Suspicious Indicators Found")

    except Exception:
        result = "Malicious"
        risk_score = 95
        reasons = ["Website Unreachable"]

    new_scan = Scan(
        url=url,
        result=result
    )

    db.session.add(new_scan)
    db.session.commit()

    return render_template(
        "index.html",
        result=result,
        risk_score=risk_score,
        scanned_url=url,
        reason=", ".join(reasons)
    )


@app.route("/history")
def history():
    scans = Scan.query.order_by(Scan.id.desc()).all()
    return render_template("history.html", scans=scans)


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)