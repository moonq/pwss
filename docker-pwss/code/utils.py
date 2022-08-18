from flask import request, current_app as app, g, session
from datetime import datetime
import bcrypt
import os
import json
import secrets
import sqlite3
import time
import sys

CONFIGS = os.getenv("CONFIG_FOLDER")


def check_password(config, pw):
    pw = pw.encode("utf-8")
    return bcrypt.checkpw(pw, config["password"].encode("utf-8"))


def check_auth(path):
    folder = path.split(os.sep)[0]
    if not f"auth/{folder}" in session:
        return False
    return has_session(folder)


def authenticate(config, password):
    """Return success of authentication"""
    if not "name" in config:
        return False
    folder = config["name"]
    if config["expires"] == "never":
        expiration = time.time() + app.config["SESSION_EXPIRY"]
    else:
        expiration = datetime.fromisoformat(config["expires"]).timestamp()
    if f"auth/{folder}" in session:
        session.pop(f"auth/{folder}")
    if expiration > time.time():
        if "password" in config and check_password(config, password):
            set_session(folder, max_expiration=expiration)
            return True
    return False


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(app.config["DATABASE"])
    return db


def get_valid_sessions():
    query = "SELECT folder, expire, token FROM sessions WHERE expire > ? AND ip = ?"
    args = (int(time.time()), get_ip())
    # TODO, validate that sessions have the token correct too.
    tokens = [session[key] for key in session if key.startswith("auth/")]
    try:
        cur = get_db().execute(query, args)
        valid_sessions = [
            (
                row[0],
                int((row[1] - time.time()) / 60),
                read_config(row[0]).get("days_left", "end of"),
            )
            for row in cur.fetchall()
            if row[2] in tokens
        ]
        cur.close()
        return valid_sessions
    except Exception as e:
        print(e, file=sys.stderr)
        return []


def has_session(folder):
    query = "SELECT count(token) FROM sessions WHERE folder = ? AND expire > ? AND token = ? AND ip = ?"
    args = (folder, int(time.time()), session[f"auth/{folder}"], get_ip())
    try:
        cur = get_db().execute(query, args)
        is_valid = cur.fetchall()[0][0] > 0
        cur.close()
    except Exception as e:
        print(e, file=sys.stderr)
        return False
    return is_valid


def set_session(folder, max_expiration=None):
    token = secrets.token_hex(16)
    query = "INSERT INTO sessions (folder, expire, token, ip) VALUES (?,?,?,?)"
    expiry_time = int(app.config["SESSION_EXPIRY"] + time.time())
    if max_expiration:
        expiry_time = int(min(max_expiration, expiry_time))
    args = (folder, expiry_time, token, get_ip())
    db = get_db()
    cur = db.execute(query, args)
    cur.close()
    db.commit()
    session[f"auth/{folder}"] = token


def get_ip():

    ip = request.environ.get(
        "HTTP_X_FORWARDED_FOR", request.remote_addr or "127.0.0.1"
    )
    ip = ip.split(",")[0].strip()
    return ip


def read_config(path):
    try:
        rootdir = path.split(os.sep)[0]
        config_file = os.path.join(CONFIGS, f"{rootdir}.json")
        with open(config_file, "rt") as fp:
            config = json.load(fp)
            config["name"] = rootdir
            try:
                config["days_left"] = round(
                    (
                        datetime.fromisoformat(config["expires"]).timestamp()
                        - time.time()
                    )
                    / 86400,
                    1,
                )
            except ValueError:
                config["days_left"] = "end of"

            return config
    except (FileNotFoundError, AttributeError):
        return {}
