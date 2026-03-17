import os
import re
import sqlite3
from functools import wraps

import psycopg
from flask import Flask, jsonify, render_template, request, redirect, session, url_for, Response

from werkzeug.security import generate_password_hash, check_password_hash



app = Flask(__name__)

# Required for Flask sessions (cookie signing).
# On Render: set SECRET_KEY in env vars.
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

DATABASE_URL = os.environ.get("DATABASE_URL")          # set on Render for Postgres
SQLITE_PATH = os.environ.get("SQLITE_PATH", "entries.db")  # local default


def using_postgres() -> bool:
    return bool(DATABASE_URL)


def normalize_username(raw: str) -> str:
    # Basic normalization: trim + collapse spaces + lower.
    # You can adjust to your taste (e.g. allow caps).
    name = raw.strip()
    name = re.sub(r"\s+", " ", name)
    return name.lower()  # i might change this to name.title()


def init_db():
    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS entries (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        entry_date DATE NOT NULL,
                        value DOUBLE PRECISION NOT NULL
                    )
                """)
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_hash TEXT")
            conn.commit()
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            # IMPORTANT: enforce foreign keys in SQLite
            con.execute("PRAGMA foreign_keys = ON;")

            con.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    entry_date TEXT NOT NULL,   -- YYYY-MM-DD
                    value REAL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            try:
                con.execute("ALTER TABLE users ADD COLUMN pin_hash TEXT;")
            except sqlite3.OperationalError:
                pass
            con.commit()


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def get_or_create_user_id(username: str) -> int:
    """
    If username exists, return its id. Otherwise create it and return new id.
    """
    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                if row:
                    return int(row[0])

                cur.execute("INSERT INTO users(username) VALUES (%s) RETURNING id", (username,))
                new_id = cur.fetchone()[0]
            conn.commit()
        return int(new_id)
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row:
                return int(row[0])

            cur.execute("INSERT INTO users(username) VALUES (?)", (username,))
            con.commit()
            return int(cur.lastrowid)


@app.get("/login")
def login():
    # If already logged in, skip login page
    if "user_id" in session:
        return redirect(url_for("home"))
    return render_template("login.html", error=None)


@app.post("/login")
def login_post():
    raw_user = request.form.get("username", "")
    raw_pin = request.form.get("pin", "")

    username = normalize_username(raw_user)
    pin = raw_pin.strip()

    if not username:
        return render_template("login.html", error="Please enter a username.")
    if not pin or len(pin) < 4 or not pin.isdigit():
        return render_template("login.html", error="Please enter a numeric PIN (at least 4 digits).")

    row = get_user_by_username(username)

    if row is None:
        # New user: create with PIN
        pin_hash = generate_password_hash(pin)
        user_id = create_user(username, pin_hash)
    else:
        user_id, pin_hash = int(row[0]), row[1]

        # Existing user from pre-PIN days: set PIN now (first login after upgrade)
        if not pin_hash:
            pin_hash = generate_password_hash(pin)
            set_user_pin(user_id, pin_hash)
        else:
            # Normal login: verify PIN
            if not check_password_hash(pin_hash, pin):
                return render_template("login.html", error="Incorrect PIN.")

    session["user_id"] = user_id
    session["username"] = username
    session.permanent = True
    return redirect(url_for("home"))

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/")
@require_login
def home():
    return render_template("index.html")


@app.get("/api/entries")
@require_login
def get_entries():
    user_id = int(session["user_id"])
    oldest = request.args.get("oldest", "0") == "1"
    order_dir = "ASC" if oldest else "DESC"

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT id, entry_date, value FROM entries "
                    f"WHERE user_id=%s "
                    f"ORDER BY entry_date {order_dir}, id {order_dir}",
                    (user_id,),
                )
                rows = cur.fetchall()
        entries = [{"id": r[0], "date": r[1].isoformat(), "value": float(r[2])} for r in rows]
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.row_factory = sqlite3.Row
            rows = con.execute(
                f"SELECT id, entry_date, value FROM entries "
                f"WHERE user_id=? "
                f"ORDER BY entry_date {order_dir}, id {order_dir}",
                (user_id,),
            ).fetchall()

        entries = [{"id": r["id"], "date": r["entry_date"], "value": float(r["value"])} for r in rows]

    total = round(sum(e["value"] for e in entries), 2)
    count = len(entries)
    max_value = round(max((e["value"] for e in entries), default=0), 2)

    unique_days = len({e["date"] for e in entries})
    avg_per_entry = round(total / count, 2) if count else 0.0
    avg_per_day = round(total / unique_days, 2) if unique_days else 0.0

    return jsonify({
        "entries": entries,
        "total": total,
        "username": session.get("username"),
        "stats": {
            "count": count,
            "max_value": max_value,
            "avg_per_entry": avg_per_entry,
            "avg_per_day": avg_per_day,
            "unique_days": unique_days
        }
    })

@app.post("/api/entries")
@require_login
def add_entry():
    user_id = int(session["user_id"])
    data = request.get_json(force=True)

    try:
        value = float(data["value"])
        entry_date = str(data["date"])  # "YYYY-MM-DD"
    except Exception:
        return jsonify({"error": "Need JSON like {'value': 12.3, 'date': 'YYYY-MM-DD'}"}), 400

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO entries(user_id, entry_date, value) VALUES (%s, %s, %s)",
                    (user_id, entry_date, value),
                )
            conn.commit()
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.execute(
                "INSERT INTO entries(user_id, entry_date, value) VALUES (?, ?, ?)",
                (user_id, entry_date, value),
            )
            con.commit()

    return jsonify({"ok": True})

@app.delete("/api/entries/<int:entry_id>")
@require_login
def delete_entry(entry_id: int):
    user_id = int(session["user_id"])

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM entries WHERE id=%s AND user_id=%s",
                    (entry_id, user_id),
                )
                deleted = cur.rowcount
            conn.commit()
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.execute(
                "DELETE FROM entries WHERE id=? AND user_id=?",
                (entry_id, user_id),
            )
            deleted = cur.rowcount
            con.commit()

    return jsonify({"ok": True, "deleted": deleted})


@app.get("/download")
@require_login
def download_entries():
    user_id = int(session["user_id"])
    username = session.get("username", "user")

    lines = ["date,value"]

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT entry_date, value
                    FROM entries
                    WHERE user_id = %s
                    ORDER BY entry_date ASC, id ASC
                    """,
                    (user_id,),
                )
                rows = cur.fetchall()

        for row in rows:
            lines.append(f"{row[0].isoformat()},{float(row[1]):.2f}")
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.cursor()
            cur.execute(
                """
                SELECT entry_date, value
                FROM entries
                WHERE user_id = ?
                ORDER BY entry_date ASC, id ASC
                """,
                (user_id,),
            )
            rows = cur.fetchall()

        for row in rows:
            lines.append(f"{row[0]},{float(row[1]):.2f}")

    csv_data = "\n".join(lines) + "\n"
    from datetime import datetime
    filename = f"{username}-mileage-{datetime.now().strftime('%Y-%m-%d')}.csv"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )

def get_user_by_username(username: str):
    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, pin_hash FROM users WHERE username=%s", (username,))
                row = cur.fetchone()
        return row  # (id, pin_hash) or None
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.cursor()
            cur.execute("SELECT id, pin_hash FROM users WHERE username=?", (username,))
            row = cur.fetchone()
        return row  # (id, pin_hash) or None


def create_user(username: str, pin_hash: str) -> int:
    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users(username, pin_hash) VALUES (%s, %s) RETURNING id",
                    (username, pin_hash),
                )
                new_id = cur.fetchone()[0]
            conn.commit()
        return int(new_id)
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.cursor()
            cur.execute(
                "INSERT INTO users(username, pin_hash) VALUES (?, ?)",
                (username, pin_hash),
            )
            con.commit()
            return int(cur.lastrowid)


def set_user_pin(user_id: int, pin_hash: str) -> None:
    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET pin_hash=%s WHERE id=%s", (pin_hash, user_id))
            conn.commit()
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.execute("UPDATE users SET pin_hash=? WHERE id=?", (pin_hash, user_id))
            con.commit()


if __name__ == "__main__":
    # Make session persist for 30 days (optional)
    from datetime import timedelta
    app.permanent_session_lifetime = timedelta(days=30)

    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False)
