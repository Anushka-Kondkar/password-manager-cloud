from flask import Flask, request, jsonify, render_template
import sqlite3
from cryptography.fernet import Fernet
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

db_path = "password_manager.db"

# Load encryption key
with open("secret.key", "rb") as f:
    key = f.read()

cipher = Fernet(key)

# =========================
# HOME → LOGIN PAGE
# =========================

@app.route("/")
def home():
    return render_template("login.html")


# =========================
# DASHBOARD PAGE
# =========================

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


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
# ADD PASSWORD
# =========================

@app.route("/add_password", methods=["POST"])
def add_password():

    data = request.json

    user_id = data["user_id"]
    website = data["website"]
    username = data["username"]
    password = data["password"]

    encrypted_password = cipher.encrypt(
        password.encode()
    )

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO passwords
    (user_id, website,
     account_username,
     encrypted_password)
    VALUES (?, ?, ?, ?)
    """, (
        user_id,
        website,
        username,
        encrypted_password
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "message":
        "Password added successfully"
    })


# =========================
# VIEW PASSWORDS
# =========================

@app.route("/passwords/<int:user_id>")
def view_passwords(user_id):

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id,
           website,
           account_username,
           encrypted_password
    FROM passwords
    WHERE user_id = ?
    """, (user_id,))

    rows = cursor.fetchall()

    conn.close()

    data = []

    for row in rows:

        decrypted = cipher.decrypt(
            row[3]
        ).decode()

        data.append({

            "id": row[0],
            "website": row[1],
            "username": row[2],
            "password": decrypted

        })

    return jsonify(data)


# =========================
# UPDATE PASSWORD
# =========================

@app.route("/update_password", methods=["PUT"])
def update_password():

    data = request.json

    password_id = data["password_id"]
    new_password = data["new_password"]

    encrypted_password = cipher.encrypt(
        new_password.encode()
    )

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    UPDATE passwords
    SET encrypted_password = ?
    WHERE id = ?
    """, (
        encrypted_password,
        password_id
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "message":
        "Password updated successfully"
    })


# =========================
# DELETE PASSWORD
# =========================

@app.route(
    "/delete_password/<int:password_id>",
    methods=["DELETE"]
)
def delete_password(password_id):

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    DELETE FROM passwords
    WHERE id = ?
    """, (password_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "message":
        "Password deleted successfully"
    })


# =========================
# SEARCH PASSWORD
# =========================

@app.route(
    "/search/<int:user_id>/<website>"
)
def search_password(user_id, website):

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT website,
           account_username,
           encrypted_password
    FROM passwords
    WHERE user_id = ?
    AND LOWER(website) =
        LOWER(?)
    """, (
        user_id,
        website
    ))

    rows = cursor.fetchall()

    conn.close()

    data = []

    for row in rows:

        decrypted = cipher.decrypt(
            row[2]
        ).decode()

        data.append({

            "website": row[0],
            "username": row[1],
            "password": decrypted

        })

    return jsonify(data)


# =========================
# HEALTH CHECK (Render)
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
