import os
import sqlite3
from functools import wraps

from flask import Flask, flash, g, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["DATABASE"] = os.path.join(os.path.dirname(__file__), "memo.db")


BASE_HTML = """
<!doctype html>
<html lang="ko">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }}</title>
</head>
<body>
    <main>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <ul>
                {% for message in messages %}<li>{{ message }}</li>{% endfor %}
                </ul>
            {% endif %}
        {% endwith %}
        <!-- CONTENT -->
    </main>
</body>
</html>
"""

REGISTER_HTML = """
<h1>회원가입</h1>
<form method="post">
    <p><label>아이디 <input type="text" name="username" required autofocus></label></p>
    <p><label>비밀번호 <input type="password" name="password" required></label></p>
    <p><button type="submit">회원가입</button></p>
</form>
<p><a href="{{ url_for('login') }}">로그인</a></p>
"""

LOGIN_HTML = """
<h1>로그인</h1>
<form method="post">
    <p><label>아이디 <input type="text" name="username" required autofocus></label></p>
    <p><label>비밀번호 <input type="password" name="password" required></label></p>
    <p><button type="submit">로그인</button></p>
</form>
<p><a href="{{ url_for('register') }}">회원가입</a></p>
"""

HOME_HTML = """
<h1>메모 서비스</h1>
<p>{{ username }}님, 로그인되어 있습니다.</p>
<form method="post" action="{{ url_for('logout') }}">
    <button type="submit">로그아웃</button>
</form>
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        get_db().execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        get_db().commit()


def render_page(template, **context):
    # HTML is kept in app.py. Do not use extends/include here because those
    # tags ask Jinja to find a file through Flask's template loader.
    full_template = BASE_HTML.replace("<!-- CONTENT -->", template)
    return render_template_string(
        full_template, title="메모 서비스", **context
    )


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


@app.route("/")
@login_required
def index():
    return render_page(HOME_HTML, username=session["username"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("아이디와 비밀번호를 입력해주세요.")
            return render_page(REGISTER_HTML), 400

        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("이미 사용 중인 아이디입니다.")
            return render_page(REGISTER_HTML), 409

        flash("회원가입이 완료되었습니다. 로그인해주세요.")
        return redirect(url_for("login"))

    return render_page(REGISTER_HTML)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
            return render_page(LOGIN_HTML), 401

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("index"))

    return render_page(LOGIN_HTML)


@app.post("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("login"))


init_db()


if __name__ == "__main__":
    app.run(debug=True)
