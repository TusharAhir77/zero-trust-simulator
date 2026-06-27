import sqlite3
import hashlib
import pyotp

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_user(username, password):
    conn = sqlite3.connect("zerotrust.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, role FROM users WHERE username=? AND password=?",
        (username, hash_password(password))
    )
    user = cursor.fetchone()
    conn.close()
    return user

# MFA - Generate OTP secret for each user
def get_otp_secret(username):
    # Simple secret based on username (in real world, store in DB)
    return pyotp.random_base32()

# Generate a fixed secret per user (for demo)
USER_SECRETS = {
    "admin": "JBSWY3DPEHPK3PXP",
    "john":  "JBSWY3DPEHPK3PXQ",
    "guest": "JBSWY3DPEHPK3PXR"
}

def generate_otp(username):
    secret = USER_SECRETS.get(username, "JBSWY3DPEHPK3PXP")
    totp = pyotp.TOTP(secret)
    return totp.now()  # Returns current OTP

def verify_otp(username, otp_entered):
    secret = USER_SECRETS.get(username, "JBSWY3DPEHPK3PXP")
    totp = pyotp.TOTP(secret)
    return totp.verify(otp_entered)