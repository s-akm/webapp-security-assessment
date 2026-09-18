from flask import Flask, request
from flask_login import login_required
app = Flask(__name__)

@app.route("/api/admin")
@login_required
def admin():
    return {"ok": True}

@app.route("/api/report", methods=["POST"])
def report():                                     # ガードなし
    send_mail(request.form["email"])
    return {"ok": True}
