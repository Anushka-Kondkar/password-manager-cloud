from flask import Flask, request, jsonify, render_template
import sqlite3
from cryptography.fernet import Fernet
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Database file
db_path = "password_manager.db"

# Load encryption key
with open("secret.key", "rb") as f:
    key = f.read()

cipher = Fernet(key)


# =========================
# HOME PAGE (UI)
# =========================

@app.route("/")
def home():
    return render_template("index.html")


# =========================
# REGISTER USER
# =========================

@app.route("/register", methods=["POST"])
def register():

    data = request.json

    username = data["username"]
    email = data["email"]
    password = data["password"]

    password_hash = bcrypt.generate_password_hash(
        password
    ).decode("utf-8")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:

        cursor.execute("""
        INSERT INTO users
        (username, email, password_hash)
        VALUES (?, ?, ?)
        """, (
            username,
            email,
            password_hash
        ))

        conn.commit()

        return jsonify({
            "message":
            "User registered successfully"
        })

    except:

        return jsonify({
            "message":
            "User already exists"
        })

    finally:

        conn.close()


# =========================
# LOGIN USER
# =========================

@app.route("/login", methods=["POST"])
def login():

    data = request.json

    email = data["email"]
    password = data["password"]

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, password_hash
    FROM users
    WHERE email = ?
    """, (email,))

    result = cursor.fetchone()

    conn.close()

    if result is None:

        return jsonify({
            "message":
            "User not found"
        })

    user_id = result[0]
    stored_hash = result[1]

    if bcrypt.check_password_hash(
        stored_hash,
        password
    ):

        return jsonify({
            "message":
            "Login successful",
            "user_id":
            user_id
        })

    else:

        return jsonify({
            "message":
            "Invalid password"
        })


# =========================
# VIEW PASSWORDS
# =========================

@app.route("/passwords/<int:user_id>")
def view_passwords(user_id):

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT website,
           account_username,
           encrypted_password
    FROM passwords
    WHERE user_id = ?
    """, (user_id,))

    rows = cursor.fetchall()

    conn.close()

    data = []

    for row in rows:

        decrypted_password = cipher.decrypt(
            row[2]
        ).decode()

        data.append({
            "website":
            row[0],

            "username":
            row[1],

            "password":
            decrypted_password
        })

    return jsonify(data)


# =========================
# HEALTH CHECK
# =========================

@app.route("/healthz")
def health():
    return "OK"


# =========================
# RUN SERVER
# =========================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=10000
    )
