from flask import Flask, request, jsonify, abort
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import re
import os
import hashlib
import hmac
import base64
import json
import time
from datetime import datetime

app = Flask(__name__)

# ── CORS ───────────────────────────────────────────────────────────────────
CORS(app,
     origins=["http://127.0.0.1:5500", "http://localhost:5500",
               "http://127.0.0.1:3000", "http://localhost:3000", "null",
               "https://*.vercel.app", "https://*.onrender.com"],
     methods=["GET", "POST", "PUT", "DELETE"],
     allow_headers=["Content-Type", "Authorization"])

# ── DATABASE ────────────────────────────────────────────────────────────────
# LINE 24 — Replace YOUR-PASSWORD-HERE with your actual Supabase password
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:#blueysplash001@db.axqlgpdincfxbiagzjws.supabase.co:5432/postgres"
)

JWT_SECRET        = os.environ.get("JWT_SECRET",        "change-me-in-production-use-a-long-random-string")
SUPERADMIN_SECRET = os.environ.get("SUPERADMIN_SECRET", "change-this-superadmin-secret")

# ── Input constraints ──────────────────────────────────────────────────────
MAX_NAME_LEN     = 80
MAX_EMAIL_LEN    = 120
MAX_PHONE_LEN    = 30
MAX_ID_LEN       = 20
MAX_COMPANY_LEN  = 80
MAX_PASSWORD_LEN = 128
PIN_RE           = re.compile(r'^\d{4,8}$')
VALID_ACTIONS    = {"check_in", "check_out"}
STAFF_ID_RE      = re.compile(r'^[A-Za-z0-9_\-]+$')


# ===== Simple JWT ===========================================================
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))

def create_token(user_id: int, company: str) -> str:
    header  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "sub":     user_id,
        "company": company,
        "iat":     int(time.time()),
        "exp":     int(time.time()) + 86400 * 7
    }).encode())
    sig = _b64url(hmac.new(
        JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
    ).digest())
    return f"{header}.{payload}.{sig}"

def verify_token(token: str) -> dict:
    try:
        header, payload, sig = token.split(".")
        expected = _b64url(hmac.new(
            JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
        ).digest())
        if not hmac.compare_digest(sig, expected):
            abort(401, description="Invalid token signature.")
        data = json.loads(_b64url_decode(payload))
        if data.get("exp", 0) < time.time():
            abort(401, description="Token expired. Please log in again.")
        return data
    except (ValueError, KeyError):
        abort(401, description="Malformed token.")

def get_current_user() -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401, description="Missing or invalid Authorization header.")
    return verify_token(auth[7:])


# ===== Password hashing =====================================================
def hash_password(password: str, salt=None) -> str:
    if salt is None:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}${base64.urlsafe_b64encode(dk).decode()}"

def check_password(password: str, stored: str) -> bool:
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


# ===== Database =============================================================
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            company    TEXT    NOT NULL,
            email      TEXT    NOT NULL UNIQUE,
            phone      TEXT,
            password   TEXT    NOT NULL,
            pin        TEXT    NOT NULL,
            created_at TEXT    NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS staff (
            id      TEXT    NOT NULL,
            user_id INTEGER NOT NULL,
            name    TEXT    NOT NULL,
            email   TEXT,
            phone   TEXT,
            PRIMARY KEY (id, user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id        SERIAL PRIMARY KEY,
            user_id   INTEGER NOT NULL,
            staff_id  TEXT    NOT NULL,
            action    TEXT    NOT NULL,
            timestamp TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

init_db()


# ===== Helpers ==============================================================
def require_json():
    data = request.get_json(silent=True)
    if data is None:
        abort(400, description="Request body must be valid JSON.")
    return data

def sanitize(value, max_len, field):
    if value is None:
        return None
    value = str(value).strip()
    if len(value) > max_len:
        abort(400, description=f"'{field}' exceeds max length of {max_len}.")
    return value or None

def validate_staff_id(sid):
    if not sid:
        abort(400, description="staff_id is required.")
    sid = str(sid).strip()
    if not STAFF_ID_RE.match(sid) or len(sid) > MAX_ID_LEN:
        abort(400, description="Invalid staff_id format.")
    return sid

def staff_exists(conn, user_id, staff_id):
    c = conn.cursor()
    c.execute("SELECT 1 FROM staff WHERE id=%s AND user_id=%s", (staff_id, user_id))
    return c.fetchone() is not None

def require_superadmin():
    auth = request.headers.get("X-Admin-Secret", "")
    if not hmac.compare_digest(auth, SUPERADMIN_SECRET):
        abort(403, description="Forbidden.")


# ===== Error handlers =======================================================
@app.errorhandler(400)
def bad_request(e):  return jsonify({"error": str(e.description)}), 400
@app.errorhandler(401)
def unauthorized(e): return jsonify({"error": str(e.description)}), 401
@app.errorhandler(403)
def forbidden(e):    return jsonify({"error": str(e.description)}), 403
@app.errorhandler(404)
def not_found(e):    return jsonify({"error": "Not found."}), 404
@app.errorhandler(409)
def conflict(e):     return jsonify({"error": str(e.description)}), 409
@app.errorhandler(500)
def server_error(e): return jsonify({"error": "Internal server error."}), 500


# ===== Auth =================================================================
@app.route("/auth/register", methods=["POST"])
def register():
    data     = require_json()
    company  = sanitize(data.get("company"),  MAX_COMPANY_LEN,  "company")
    email    = sanitize(data.get("email"),    MAX_EMAIL_LEN,    "email")
    phone    = sanitize(data.get("phone"),    MAX_PHONE_LEN,    "phone")
    password = sanitize(data.get("password"), MAX_PASSWORD_LEN, "password")
    pin      = sanitize(data.get("pin"),      10,               "pin")

    if not company:  abort(400, description="'company' is required.")
    if not email:    abort(400, description="'email' is required.")
    if not password: abort(400, description="'password' is required.")
    if not pin or not PIN_RE.match(pin):
        abort(400, description="'pin' must be 4–8 digits.")

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=%s", (email,))
        if c.fetchone():
            abort(409, description="An account with this email already exists.")
        pw_hash  = hash_password(password)
        pin_hash = hash_password(pin)
        c.execute(
            "INSERT INTO users (company, email, phone, password, pin, created_at) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id, company",
            (company, email, phone, pw_hash, pin_hash, datetime.utcnow().isoformat())
        )
        user = c.fetchone()
        conn.commit()
    finally:
        conn.close()

    token = create_token(user["id"], user["company"])
    return jsonify({"token": token, "company": user["company"], "user_id": user["id"]}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data     = require_json()
    email    = sanitize(data.get("email"),    MAX_EMAIL_LEN,    "email")
    password = sanitize(data.get("password"), MAX_PASSWORD_LEN, "password")

    if not email or not password:
        abort(400, description="'email' and 'password' are required.")

    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = c.fetchone()
    conn.close()

    if not user or not check_password(password, user["password"]):
        abort(401, description="Invalid email or password.")

    token = create_token(user["id"], user["company"])
    return jsonify({"token": token, "company": user["company"], "user_id": user["id"]})


@app.route("/auth/verify-pin", methods=["POST"])
def verify_pin():
    current = get_current_user()
    data    = require_json()
    pin     = sanitize(data.get("pin"), 10, "pin")
    if not pin:
        abort(400, description="'pin' is required.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT pin FROM users WHERE id=%s", (current["sub"],))
    user = c.fetchone()
    conn.close()
    if not user or not check_password(pin, user["pin"]):
        abort(403, description="Incorrect PIN.")
    return jsonify({"ok": True})


@app.route("/auth/profile", methods=["GET"])
def get_profile():
    current = get_current_user()
    conn    = get_db()
    c       = conn.cursor()
    c.execute("SELECT id, company, email, phone, created_at FROM users WHERE id=%s", (current["sub"],))
    user = c.fetchone()
    conn.close()
    if not user:
        abort(404)
    return jsonify(dict(user))


# ===== Staff ================================================================
@app.route("/staff", methods=["GET"])
def list_staff():
    current = get_current_user()
    conn    = get_db()
    c       = conn.cursor()
    c.execute("SELECT * FROM staff WHERE user_id=%s ORDER BY name", (current["sub"],))
    staff = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in staff])


@app.route("/staff", methods=["POST"])
def add_staff():
    current  = get_current_user()
    data     = require_json()
    staff_id = validate_staff_id(data.get("id"))
    name     = sanitize(data.get("name"),  MAX_NAME_LEN,  "name")
    email    = sanitize(data.get("email"), MAX_EMAIL_LEN, "email")
    phone    = sanitize(data.get("phone"), MAX_PHONE_LEN, "phone")
    if not name:
        abort(400, description="'name' is required.")
    conn = get_db()
    try:
        if staff_exists(conn, current["sub"], staff_id):
            abort(409, description=f"Staff ID '{staff_id}' already exists.")
        c = conn.cursor()
        c.execute(
            "INSERT INTO staff (id, user_id, name, email, phone) VALUES (%s,%s,%s,%s,%s)",
            (staff_id, current["sub"], name, email, phone)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"Staff '{name}' added.", "id": staff_id}), 201


@app.route("/staff/<staff_id>", methods=["PUT"])
def update_staff(staff_id):
    current  = get_current_user()
    staff_id = validate_staff_id(staff_id)
    data     = require_json()
    name     = sanitize(data.get("name"),  MAX_NAME_LEN,  "name")
    email    = sanitize(data.get("email"), MAX_EMAIL_LEN, "email")
    phone    = sanitize(data.get("phone"), MAX_PHONE_LEN, "phone")
    if not name:
        abort(400, description="'name' is required.")
    conn = get_db()
    try:
        if not staff_exists(conn, current["sub"], staff_id):
            abort(404)
        c = conn.cursor()
        c.execute(
            "UPDATE staff SET name=%s, email=%s, phone=%s WHERE id=%s AND user_id=%s",
            (name, email, phone, staff_id, current["sub"])
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"Staff '{staff_id}' updated."})


@app.route("/staff/<staff_id>", methods=["DELETE"])
def remove_staff(staff_id):
    current  = get_current_user()
    staff_id = validate_staff_id(staff_id)
    conn     = get_db()
    try:
        if not staff_exists(conn, current["sub"], staff_id):
            abort(404)
        c = conn.cursor()
        c.execute("DELETE FROM attendance WHERE staff_id=%s AND user_id=%s", (staff_id, current["sub"]))
        c.execute("DELETE FROM staff WHERE id=%s AND user_id=%s", (staff_id, current["sub"]))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"Staff '{staff_id}' removed."})


# ===== Attendance ===========================================================
@app.route("/attendance", methods=["GET"])
def list_attendance():
    current = get_current_user()
    conn    = get_db()
    c       = conn.cursor()
    c.execute(
        "SELECT a.*, s.name FROM attendance a "
        "LEFT JOIN staff s ON a.staff_id=s.id AND s.user_id=a.user_id "
        "WHERE a.user_id=%s ORDER BY a.timestamp DESC",
        (current["sub"],)
    )
    records = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in records])


@app.route("/attendance", methods=["POST"])
def record_attendance():
    current  = get_current_user()
    data     = require_json()
    staff_id = validate_staff_id(data.get("staff_id"))
    action   = sanitize(data.get("action"), 20, "action")
    if action not in VALID_ACTIONS:
        abort(400, description=f"'action' must be one of: {', '.join(VALID_ACTIONS)}.")
    timestamp = datetime.utcnow().isoformat()
    conn = get_db()
    try:
        if not staff_exists(conn, current["sub"], staff_id):
            abort(404, description=f"Staff '{staff_id}' not found.")
        c = conn.cursor()
        c.execute(
            "INSERT INTO attendance (user_id, staff_id, action, timestamp) VALUES (%s,%s,%s,%s)",
            (current["sub"], staff_id, action, timestamp)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"{staff_id} {action}", "timestamp": timestamp}), 201


# ===== Superadmin ===========================================================
@app.route("/superadmin/stats", methods=["GET"])
def superadmin_stats():
    require_superadmin()
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT COUNT(*) AS n FROM users");        total_users      = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) AS n FROM staff");        total_staff      = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) AS n FROM attendance");   total_attendance = c.fetchone()["n"]
    today = datetime.utcnow().date().isoformat()
    c.execute("SELECT COUNT(*) AS n FROM attendance WHERE action='check_in' AND timestamp LIKE %s", (today + "%",))
    today_checkins = c.fetchone()["n"]
    c.execute("SELECT company, email, created_at FROM users ORDER BY created_at DESC LIMIT 1")
    newest_user = c.fetchone()
    conn.close()
    return jsonify({
        "total_users": total_users, "total_staff": total_staff,
        "total_attendance": total_attendance, "today_checkins": today_checkins,
        "newest_user": dict(newest_user) if newest_user else None,
        "server_time": datetime.utcnow().isoformat()
    })

@app.route("/superadmin/users", methods=["GET"])
def superadmin_users():
    require_superadmin()
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        SELECT u.id, u.company, u.email, u.phone, u.created_at,
               COUNT(DISTINCT s.id)  AS staff_count,
               COUNT(DISTINCT a.id)  AS attendance_count
        FROM users u
        LEFT JOIN staff      s ON s.user_id = u.id
        LEFT JOIN attendance a ON a.user_id = u.id
        GROUP BY u.id ORDER BY u.created_at DESC
    """)
    users = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in users])

@app.route("/superadmin/users/<int:user_id>", methods=["DELETE"])
def superadmin_delete_user(user_id):
    require_superadmin()
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE id=%s", (user_id,))
        if not c.fetchone():
            abort(404)
        c.execute("DELETE FROM attendance WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM staff      WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM users      WHERE id=%s",      (user_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"User {user_id} deleted."})


# ===== Run ==================================================================
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
