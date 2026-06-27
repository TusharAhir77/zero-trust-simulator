from flask import Flask, render_template, request, redirect, session, url_for
from auth import verify_user, generate_otp, verify_otp
from policy import check_access
import sqlite3
    
from datetime import datetime

app = Flask(__name__)
app.secret_key = "zerotrust-secret-2024"

def save_log(username, resource, status):
    conn = sqlite3.connect("zerotrust.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO logs (username, resource, status, timestamp) VALUES (?, ?, ?, ?)",
        (username, resource, status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()
    
@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if not username or not password:
            error = "⚠️ Please enter both username and password!"
        else:
            user = verify_user(username, password)
            if user:
                session["temp_user"] = user[0]
                session["temp_role"] = user[1]
                return redirect(url_for("mfa"))
            else:
                error = "❌ Invalid username or password!"
    return render_template("login.html", error=error)

@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    if "temp_user" not in session:
        return redirect(url_for("login"))

    error = None
    username = session["temp_user"]
    current_otp = generate_otp(username)
    if request.method == "POST":
        entered_otp = request.form["otp"].strip()

        if not entered_otp:
            error = "⚠️ Please enter the OTP!"
        elif verify_otp(username, entered_otp):
            session["username"] = session["temp_user"]
            session["role"] = session["temp_role"]
            session.pop("temp_user")
            session.pop("temp_role")
            return redirect(url_for("dashboard"))
        else:
            error = "❌ Invalid OTP! Try again."
    return render_template("mfa.html",
                           username=username,
                           current_otp=current_otp,
                           error=error)

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    result = None
    if request.method == "POST":
        resource = request.form["resource"]
        granted, message = check_access(session["role"], resource)
        status = "GRANTED" if granted else "DENIED"
        save_log(session["username"], resource, status)
        result = {"message": message, "granted": granted}

    conn = sqlite3.connect("zerotrust.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10")
    logs = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM logs WHERE status='GRANTED'")
    granted_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE status='DENIED'")
    denied_count = cursor.fetchone()[0]
    cursor.execute("SELECT username, role FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html",
                           username=session["username"],
                           role=session["role"],
                           result=result,
                           logs=logs,
                           granted_count=granted_count,
                           denied_count=denied_count,
                           users=users)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0")