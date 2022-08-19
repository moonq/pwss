from flask import (
    Flask,
    request,
    session,
    g,
    redirect,
    url_for,
    render_template,
    send_file,
)

from flask_limiter import Limiter
from revprox import ReverseProxied
from utils import (
    authenticate,
    check_auth,
    get_ip,
    get_valid_sessions,
    read_config,
)
import os
import sys

DEBUG = False
SECRET_KEY = os.getenv("SECRET_KEY", "2f6aa45dfcfc37a50537f0b05af6452c")
DATABASE = os.getenv("DATABASE", "serve.db")
SESSION_EXPIRY = int(os.getenv("SESSION_EXPIRY", 1800))
FOLDERS = os.getenv("STATIC_FOLDER")

app = Flask(__name__)
app.config.from_object(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)

limiter = Limiter(
    key_func=get_ip,
    default_limits=["5 per 5 seconds"],
    storage_uri="memcached://localhost:11211",
)
limiter.init_app(app)


@app.route("/s/<path:path>", methods=["POST", "GET"])
@limiter.limit(os.getenv("LIMITER_SHARE"))
def serve(path=None):
    realpath = os.path.join(FOLDERS, path)
    is_auth = check_auth(path)
    if not is_auth:
        session["return_to"] = path
        return redirect(
            url_for("login", folder=path.split(os.sep)[0]), code=302
        )

    if os.path.isdir(realpath):
        if not path.endswith("/"):
            return redirect(url_for("serve", path=f"{path}/"), code=302)
        realpath = os.path.join(realpath, "index.html")

    if not os.path.exists(realpath):
        return "", 404

    return send_file(
        realpath,
    )


@app.route("/l", methods=["POST", "GET"])
@app.route("/l/<folder>", methods=["POST", "GET"])
def login(folder=None):

    if request.method == "POST":
        folder = "".join(
            letter
            for letter in request.form["folder"]
            if letter.isalnum() or letter in "-._"
        )
        config = read_config(folder)
        success = authenticate(config, request.form["password"])
        print(
            f"{'Successful' if success else 'Failed'} login {folder}: {get_ip()}",
            file=sys.stderr,
        )

        ret = session.get("return_to", None)

        if "return_to" in session:
            session.pop("return_to")
        if ret:
            return redirect(url_for("serve", path=ret))
    else:
        # GET
        config = read_config(folder)

    sessions = get_valid_sessions()
    if not folder:
        folder = ""
    return render_template("login.html", folder=folder, sessions=sessions)


@app.route("/logout", methods=["GET"])
def logout():
    to_delete = [key for key in session if key.startswith("auth/")]
    for key in to_delete:
        del session[key]
    return redirect(url_for("index"))


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


@app.errorhandler(429)
def ratelimit_handler(e):
    print(
        f"Ratelimit exceeded: {e.description} key: {e.limit.key_func()}",
        file=sys.stderr,
    )
    return render_template("ratelimit.html", description=e.description), 429


if __name__ == "__main__":

    app.run()
