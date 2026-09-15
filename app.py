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
    <style>
        :root {
            color-scheme: light;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            color: #171717;
            background: #f5f5f5;
        }

        * { box-sizing: border-box; }

        body {
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }

        main {
            width: min(100% - 32px, 440px);
            min-height: 100vh;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 32px 0;
        }

        .card {
            width: 100%;
            padding: 40px;
            background: #fff;
            border: 1px solid #e7e7e7;
            border-radius: 16px;
            box-shadow: 0 12px 32px rgba(0, 0, 0, 0.08);
        }

        h1 {
            margin: 0 0 28px;
            font-size: 28px;
            letter-spacing: -0.04em;
            text-align: center;
        }

        .alert {
            width: 100%;
            margin-bottom: 20px;
            padding: 12px 14px;
            color: #333;
            background: #f1f1f1;
            border: 1px solid #dedede;
            border-radius: 8px;
            font-size: 14px;
            line-height: 1.5;
        }

        .field { margin-bottom: 16px; }

        label {
            display: block;
            margin-bottom: 7px;
            color: #404040;
            font-size: 14px;
            font-weight: 600;
        }

        input {
            display: block;
            width: 100%;
            padding: 12px 13px;
            color: #171717;
            background: #fff;
            border: 1px solid #d4d4d4;
            border-radius: 8px;
            outline: none;
            font: inherit;
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }

        input:hover { border-color: #999; }

        input:focus {
            border-color: #171717;
            box-shadow: 0 0 0 3px rgba(23, 23, 23, 0.12);
        }

        button {
            width: 100%;
            margin-top: 8px;
            padding: 12px 16px;
            color: #fff;
            background: #171717;
            border: 1px solid #171717;
            border-radius: 8px;
            cursor: pointer;
            font: inherit;
            font-weight: 600;
            transition: background 0.15s ease, transform 0.15s ease, box-shadow 0.15s ease;
        }

        button:hover {
            background: #3a3a3a;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.14);
        }

        button:focus-visible {
            outline: 3px solid rgba(23, 23, 23, 0.25);
            outline-offset: 2px;
        }

        button:active { transform: translateY(1px); }

        .switch {
            margin: 22px 0 0;
            color: #737373;
            font-size: 14px;
            text-align: center;
        }

        a { color: #171717; font-weight: 600; }
        a:hover { color: #666; }

        @media (max-width: 480px) {
            main { width: min(100% - 24px, 440px); padding: 20px 0; }
            .card { padding: 28px 22px; border-radius: 12px; }
            h1 { margin-bottom: 24px; font-size: 24px; }
        }
    </style>
</head>
<body>
    <main>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <div class="alert" role="alert">{{ messages[-1] }}</div>
            {% endif %}
        {% endwith %}
        <!-- CONTENT -->
    </main>
</body>
</html>
"""

REGISTER_HTML = """
<section class="card">
    <h1>회원가입</h1>
    <form method="post">
        <div class="field">
            <label for="username">아이디</label>
            <input id="username" type="text" name="username" required autofocus>
        </div>
        <div class="field">
            <label for="password">비밀번호</label>
            <input id="password" type="password" name="password" required>
        </div>
        <button type="submit">회원가입</button>
    </form>
    <p class="switch">이미 계정이 있나요? <a href="{{ url_for('login') }}">로그인</a></p>
</section>
"""

LOGIN_HTML = """
<section class="card">
    <h1>로그인</h1>
    <form method="post">
        <div class="field">
            <label for="username">아이디</label>
            <input id="username" type="text" name="username" required autofocus>
        </div>
        <div class="field">
            <label for="password">비밀번호</label>
            <input id="password" type="password" name="password" required>
        </div>
        <button type="submit">로그인</button>
    </form>
    <p class="switch">계정이 없나요? <a href="{{ url_for('register') }}">회원가입</a></p>
</section>
"""

HOME_HTML = """
<section class="card">
    <h1>메모 서비스</h1>
    <p>{{ username }}님, 로그인되어 있습니다.</p>
    <form method="post" action="{{ url_for('logout') }}">
        <button type="submit">로그아웃</button>
    </form>
</section>
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
