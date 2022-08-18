import os
import sys
import json
import time
import bcrypt
import argparse
import sqlite3
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from utils import read_config

ENTRY = {"expires": "never", "password": None}
CONFIGS = os.getenv("CONFIG_FOLDER")
FOLDERS = os.getenv("STATIC_FOLDER")
DATABASE = os.getenv("DATABASE", None)
SCHEMA = """CREATE TABLE IF NOT EXISTS sessions(
   ID INTEGER PRIMARY KEY AUTOINCREMENT,
   folder         TEXT    NOT NULL,
   ip             TEXT    NOT NULL,
   token          TEXT    NOT NULL,
   expire         INTEGER     NOT NULL
);"""


def get_opts():

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    sub_add = subparsers.add_parser("add")
    sub_remove = subparsers.add_parser("remove")
    sub_edit = subparsers.add_parser("edit")
    sub_list = subparsers.add_parser("list")
    sub_session_list = subparsers.add_parser("sessions-list")
    sub_session_clean = subparsers.add_parser(
        "sessions-clean", help="Clean out session DB"
    )
    sub_session_remove = subparsers.add_parser(
        "sessions-remove", help="Terminates all sessions"
    )

    for p in (sub_add, sub_remove, sub_edit):
        p.add_argument("folder", action="store", help="Folder name to share")

    for p in (sub_add, sub_edit):

        p.add_argument(
            "--expires",
            action="store",
            help="Share expires in days, or 'never'",
            default=None,
        )
        p.add_argument(
            "--password", action="store", help="Set password", default=None
        )

    args = parser.parse_args()
    return args


def manager():
    opts = get_opts()
    if opts.command == None or opts.command == "list":
        shares_list()
    if opts.command == "add":
        share_add(opts)
    if opts.command == "remove":
        share_remove(opts)
    if opts.command == "edit":
        share_edit(opts)
    if opts.command == "sessions-list":
        session_list()
    if opts.command == "sessions-remove":
        session_remove()
    if opts.command == "sessions-clean":
        session_clean()


def load_config(name):
    config = read_config(name)
    return config


def save_config(path, config):
    with open(path, "wt") as fp:
        save_config = ENTRY.copy()
        for key in save_config:
            save_config[key] = config[key]
        return json.dump(save_config, fp, indent=2, sort_keys=True)


def share_oneliner(entry):
    return f"{(entry['name']+'/').ljust(15)} expires: {entry['expires']}"


def shares_list():

    print("Shared folders:")
    for c in sorted(os.listdir(CONFIGS)):
        if c.endswith(".json"):
            entry = load_config(c[0:-5])
            print(share_oneliner(entry))


def share_add(opts):

    entry = ENTRY.copy()
    if opts.folder != secure_filename(opts.folder):
        raise ValueError(f"Folder '{opts.folder}' is not a safe filename")

    if opts.expires:
        entry["expires"] = (
            (datetime.now() + timedelta(days=float(opts.expires)))
            .replace(microsecond=0)
            .isoformat()
        )
    if not opts.password:
        raise ValueError("Password required")
    (pw, _) = hash_password(opts.password)
    entry["password"] = pw
    share_folder = os.path.join(FOLDERS, opts.folder)
    share_config = os.path.join(CONFIGS, f"{opts.folder}.json")
    if os.path.exists(share_config):
        raise FileExistsError("Configuration already exists. Edit with `edit`")

    save_config(share_config, entry)
    if not os.path.exists(share_folder):
        os.mkdir(share_folder)
    print(f"Added:\n{share_oneliner(load_config(opts.folder))}")


def share_remove(opts):

    share_folder = os.path.join(FOLDERS, opts.folder)
    share_config = os.path.join(CONFIGS, f"{opts.folder}.json")
    if not os.path.exists(share_config):
        raise FileNotFoundError("Configuration doesn't exist.")
    else:
        print(f"Removing configuration {share_config}")
        os.remove(share_config)
    if os.path.exists(share_folder):
        if len(os.listdir(share_folder)) > 0:
            print(f"Not removing folder {share_folder}, contains data")
        else:
            print(f"Removing empty folder {share_folder}")
            os.rmdir(share_folder)


def share_edit(opts):

    share_config = os.path.join(CONFIGS, f"{opts.folder}.json")
    if not os.path.exists(share_config):
        raise FileNotFoundError("Configuration doesn't exist.")
    entry = load_config(opts.folder)
    if opts.expires:
        print(f"Updating expiry date: {opts.expires}")
        if opts.expires == "never":
            entry["expires"] = opts.expires
        else:
            entry["expires"] = (
                (datetime.now() + timedelta(days=float(opts.expires)))
                .replace(microsecond=0)
                .isoformat()
            )
    if opts.password:
        print("Updating password")
        (pw, _) = hash_password(opts.password)
        entry["password"] = pw

    save_config(share_config, entry)
    print(f"Added:\n{share_oneliner(load_config(opts.folder))}")


def session_get_database():
    return sqlite3.connect(DATABASE)


def session_create_database():
    args = tuple()
    db = session_get_database()
    cur = db.execute(SCHEMA, args)
    db.commit()
    cur.close()


def session_list():
    query = "SELECT folder, expire, token, ip FROM sessions"
    args = tuple()
    cur = session_get_database().execute(query, args)
    print(f"{'Share'.ljust(15)} {'Expires'.ljust(19)} IP")
    for session in cur.fetchall():
        d = datetime.fromtimestamp(session[1])
        print(f"{session[0].ljust(15)} {d} {session[3]}")
    cur.close()


def session_remove():
    query = "DELETE FROM sessions"
    args = tuple()
    db = session_get_database()
    cur = db.execute(query, args)
    db.commit()
    cur.close()


def session_clean():
    query = "DELETE FROM sessions WHERE expire < ?"
    args = (int(time.time()),)
    db = session_get_database()
    cur = db.execute(query, args)
    db.commit()
    cur.close()


def hash_password(pw):
    pw = pw.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pw, salt)
    return hashed.decode(), salt.decode()


if __name__ == "__main__":
    manager()
