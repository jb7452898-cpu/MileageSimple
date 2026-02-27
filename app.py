import os
import re
import sqlite3
from functools import wraps

import psycopg
from flask import Flask, jsonify, render_template, request, redirect, session, url_for

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
    raw = request.form.get("username", "")
    username = normalize_username(raw)

    if not username:
        return render_template("login.html", error="Please enter a username.")

    # Create or fetch user
    user_id = get_or_create_user_id(username)

    # Remember user in a cookie-backed session
    session["user_id"] = user_id
    session["username"] = username
    session.permanent = True  # makes it persist beyond browser close (configurable)

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

    total = sum(e["value"] for e in entries)
    return jsonify({"entries": entries, "total": round(total, 2), "username": session.get("username")})


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


if __name__ == "__main__":
    # Make session persist for 30 days (optional)
    from datetime import timedelta
    app.permanent_session_lifetime = timedelta(days=30)

    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False)
