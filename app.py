import os
import re
import secrets
import sqlite3
import uuid
import hmac
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    DATABASE=os.path.join(os.path.dirname(__file__), "memo.db"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"},
)

MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_LENGTH = 128
MAX_TITLE_LENGTH = 200
MAX_CONTENT_LENGTH = 10000


BASE_HTML = """
<!doctype html>
<html lang="ko">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }}</title>
    <style>
        :root { color-scheme: dark; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Malgun Gothic", sans-serif; color: #f5f3ff; background: #09080d; }
        * { box-sizing: border-box; }
        body { min-height: 100vh; margin: 0; overflow-x: hidden; background: radial-gradient(circle at 50% -10%, rgba(126,87,255,.2), transparent 34rem), #09080d; }
        main { width: min(100% - 32px, 760px); min-height: 100vh; margin: auto; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 48px 0; }
        .brand { margin-bottom: 22px; text-align: center; } .brand-name { margin: 0; color: #fff; font-size: clamp(38px, 11vw, 58px); font-weight: 850; letter-spacing: .16em; text-shadow: 0 0 28px rgba(150,102,255,.42); } .tagline { margin: 13px 0 0; color: #9d96b0; font-size: 13px; }
        .card { width: 100%; padding: 36px; background: linear-gradient(145deg, rgba(31,28,42,.9), rgba(18,16,25,.9)); border: 1px solid rgba(169,142,255,.18); border-radius: 18px; box-shadow: 0 20px 70px rgba(0,0,0,.42), inset 0 1px rgba(255,255,255,.04); backdrop-filter: blur(16px); } .auth-card { max-width: 460px; }
        h1 { margin: 0 0 26px; color: #fff; font-size: 22px; } h2 { margin: 0 0 18px; color: #fff; font-size: 18px; }
        .alert { width: 100%; margin-bottom: 14px; padding: 11px 15px; color: #e9ddff; background: rgba(108,66,187,.22); border: 1px solid rgba(174,139,255,.32); border-radius: 10px; font-size: 13px; line-height: 1.5; text-align: center; }
        .field { margin-bottom: 17px; } label { display: block; margin-bottom: 8px; color: #bbb3cf; font-size: 14px; font-weight: 600; }
        input, textarea { display: block; width: 100%; padding: 13px 14px; color: #f7f4ff; background: rgba(8,7,12,.7); border: 1px solid #3a3448; border-radius: 9px; outline: none; font: inherit; transition: .18s ease; } textarea { min-height: 150px; resize: vertical; } input::placeholder, textarea::placeholder { color: #696277; } input:hover, textarea:hover { border-color: #665493; } input:focus, textarea:focus { border-color: #a887ff; box-shadow: 0 0 0 3px rgba(139,92,246,.18); }
        button { width: 100%; margin-top: 8px; padding: 13px 16px; color: #fff; background: linear-gradient(135deg,#7c4dff,#5b25c8); border: 1px solid #9a78ff; border-radius: 9px; cursor: pointer; font: inherit; font-weight: 600; transition: .18s ease; } button:hover { background: linear-gradient(135deg,#946fff,#7035e3); box-shadow: 0 8px 22px rgba(108,64,229,.35); transform: translateY(-1px); } button:focus-visible { outline: 3px solid rgba(175,145,255,.4); outline-offset: 2px; }
        .button-secondary, .button-danger { width: auto; margin: 0; padding: 9px 13px; background: transparent; border-color: #4b425e; } .button-danger { background: #3a1727; border-color: #6d3048; } .switch { margin: 22px 0 0; color: #898198; font-size: 14px; text-align: center; } a { color: #c0aaff; font-weight: 650; text-decoration: none; transition: .18s ease; } a:hover { color: #fff; text-shadow: 0 0 12px rgba(178,143,255,.65); }
        .topbar, .memo-header, .memo-actions { display: flex; align-items: center; justify-content: space-between; gap: 14px; } .topbar { width: 100%; margin-bottom: 18px; } .topbar .brand-name { font-size: 24px; } .topbar .tagline { margin: 4px 0 0; font-size: 11px; } .memo-list { display: grid; gap: 12px; margin: 0 0 24px; padding: 0; list-style: none; } .memo-item { padding: 17px; background: rgba(8,7,12,.46); border: 1px solid #3a3448; border-radius: 11px; } .memo-item p, .home-copy { margin: 7px 0 0; color: #aaa1bd; line-height: 1.7; } .muted { color: #898198; font-size: 14px; } .memo-actions { justify-content: flex-start; margin-top: 22px; } .memo-actions form { margin: 0; } .memo-actions button { margin: 0; }
        @media (max-width: 480px) { main { width: min(100% - 24px, 760px); padding: 20px 0; } .card { padding: 28px 22px; border-radius: 14px; } .topbar, .memo-header { align-items: flex-start; flex-direction: column; } }
    </style>
</head>
<body><main>
    {% with messages = get_flashed_messages() %}{% if messages %}<div class="alert" role="alert" aria-live="polite">{{ messages[-1] }}</div>{% endif %}{% endwith %}
    <div class="brand"><p class="brand-name">CRUCIO</p><p class="tagline">우리집에왜왔니왜왔니</p></div>
    <!-- CONTENT -->
</main></body>
</html>
"""

REGISTER_HTML = """
<section class="card auth-card"><h1>입장은 일로</h1><form method="post">
<div class="field"><label for="username">아이디</label><input id="username" name="username" placeholder="친구들이 부르는 이름" required autofocus></div>
<div class="field"><label for="password">비밀번호</label><input id="password" type="password" name="password" placeholder="ㅍ ㅐ 스 워 드" required></div>
<button type="submit">회원가입</button></form><p class="switch">이미 계정이 있나? <a href="{{ url_for('login') }}">로그인</a></p></section>
"""

LOGIN_HTML = """
<section class="card auth-card"><h1>들어가기</h1><form method="post">
<div class="field"><label for="username">아이디</label><input id="username" name="username" placeholder="아이디 여기" required autofocus></div>
<div class="field"><label for="password">비밀번호</label><input id="password" type="password" name="password" placeholder="비밀번호 여기" required></div>
<button type="submit">로그인</button></form><p class="switch">계정이 아직도 없다고? ㄷㄷ <a href="{{ url_for('register') }}">회원가입</a></p></section>
"""

MEMOS_HTML = """
{% if session.get('is_admin') %}<nav style="width:100%; margin-bottom:10px; text-align:right;"><a href="{{ url_for('admin') }}">회원 관리</a></nav>{% endif %}
<section class="card"><div class="topbar"><div><p class="brand-name">CRUCIO</p><p class="tagline">{{ username }}의 흔적</p></div><div class="memo-actions"><a href="{{ url_for('activity') }}">최근 활동</a><form method="post" action="{{ url_for('logout') }}"><button class="button-secondary" type="submit">로그아웃</button></form></div></div>
<div class="memo-header"><h1>내 메모</h1><a href="{{ url_for('new_memo') }}">+ 새 메모</a></div>
{% if memos %}<ul class="memo-list">{% for memo in memos %}<li class="memo-item"><a href="{{ url_for('view_memo', memo_id=memo['id']) }}">{{ memo['title'] }}</a><p>{{ memo['content']|truncate(100) }}</p></li>{% endfor %}</ul>{% else %}<p class="muted">아직 남긴 흔적이 없습니다.</p>{% endif %}</section>
"""

MEMO_FORM_HTML = """
<section class="card"><h1>{{ form_title }}</h1><form method="post"><div class="field"><label for="title">제목</label><input id="title" name="title" value="{{ memo['title'] if memo else '' }}" placeholder="제목을 적어주세요" required autofocus></div><div class="field"><label for="content">내용</label><textarea id="content" name="content" placeholder="여기에 메모를 남겨보세요" required>{{ memo['content'] if memo else '' }}</textarea></div><button type="submit">저장하기</button></form><p class="switch"><a href="{{ url_for('memos') }}">메모 목록으로 돌아가기</a></p></section>
"""

MEMO_VIEW_HTML = """
<section class="card"><div class="memo-header"><h1>{{ memo['title'] }}</h1><a href="{{ url_for('memos') }}">목록</a></div><p class="home-copy">{{ memo['content'] }}</p><div class="memo-actions"><a class="button-secondary" href="{{ url_for('edit_memo', memo_id=memo['id']) }}">수정</a><form method="post" action="{{ url_for('delete_memo', memo_id=memo['id']) }}"><button class="button-danger" type="submit">삭제</button></form></div></section>
"""

ADMIN_HTML = """
<section class="card"><div class="topbar"><div><p class="brand-name">CRUCIO // ADMIN</p><p class="tagline">관리자 전용 구역</p></div><a href="{{ url_for('memos') }}">내 메모</a></div><h1>전체 메모</h1><ul class="memo-list">{% for memo in memos %}<li class="memo-item"><strong>{{ memo['title'] }}</strong><p>소유자: {{ memo['username'] }} · {% if memo['is_private'] %}private{% else %}public{% endif %}</p><p>{{ memo['content'] }}</p></li>{% else %}<li class="muted">메모가 없습니다.</li>{% endfor %}</ul></section>
"""

USER_LIST_HTML = """
<section class="card"><h1>회원 관리</h1><ul class="memo-list">{% for member in users %}<li class="memo-item"><strong>{{ member['username'] }}</strong><p>권한: {% if member['is_admin'] %}admin{% else %}일반 회원{% endif %}</p></li>{% else %}<li class="muted">회원이 없습니다.</li>{% endfor %}</ul></section>
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
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        raise RuntimeError("ADMIN_PASSWORD environment variable is required")

    with app.app_context():
        db = get_db()
        db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL)")
        columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        if "is_admin" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        db.execute("""CREATE TABLE IF NOT EXISTS memos (
            id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL,
            content TEXT NOT NULL, is_private INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )""")
        admin = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
        if admin is None:
            db.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)", ("admin", generate_password_hash(admin_password)))
            admin = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
        else:
            db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (admin["id"],))
        db.commit()


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": get_csrf_token}


@app.before_request
def validate_csrf():
    if request.method == "POST":
        session_token = session.get("_csrf_token")
        submitted_token = request.form.get("_csrf_token", "")
        if not session_token or not submitted_token or not hmac.compare_digest(session_token, submitted_token):
            abort(400)


def render_page(template, **context):
    rendered = render_template_string(BASE_HTML.replace("<!-- CONTENT -->", template), title="CRUCIO", **context)
    csrf_input = '<input type="hidden" name="_csrf_token" value="{}">'.format(get_csrf_token())
    return re.sub(r"(<form\b[^>]*>)", r"\1" + csrf_input, rendered, flags=re.IGNORECASE)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; "
        "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
    )
    return response


@app.errorhandler(400)
def bad_request(_error):
    return "잘못된 요청입니다.", 400


@app.errorhandler(403)
def forbidden(_error):
    return "접근 권한이 없습니다.", 403


@app.errorhandler(404)
def not_found(_error):
    return "요청한 페이지를 찾을 수 없습니다.", 404


@app.errorhandler(500)
def internal_error(_error):
    return "서버 오류가 발생했습니다.", 500


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(**kwargs)
    return wrapped_view


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(**kwargs):
        user = get_db().execute("SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if user is None or not user["is_admin"]:
            abort(403)
        return view(**kwargs)
    return wrapped_view


def owned_memo_or_404(memo_id):
    memo = get_db().execute("SELECT * FROM memos WHERE id = ? AND user_id = ?", (memo_id, session["user_id"])).fetchone()
    if memo is None:
        abort(404)
    return memo


@app.route("/")
@login_required
def index():
    return redirect(url_for("memos"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password or len(username) > MAX_USERNAME_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
            flash("아이디와 비밀번호를 입력해주세요.")
            return render_page(REGISTER_HTML), 400
        try:
            db = get_db()
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, generate_password_hash(password)))
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
        user = get_db().execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", (username,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
            return render_page(LOGIN_HTML), 401
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])
        return redirect(url_for("index"))
    return render_page(LOGIN_HTML)


@app.post("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("login"))


@app.route("/memos", methods=["GET", "POST"])
@login_required
def memos():
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content or len(title) > MAX_TITLE_LENGTH or len(content) > MAX_CONTENT_LENGTH:
            flash("제목과 내용을 입력해주세요.")
            return render_page(MEMO_FORM_HTML, form_title="새 메모", memo=None), 400
        db.execute("INSERT INTO memos (id, user_id, title, content, is_private) VALUES (?, ?, ?, ?, 1)", (str(uuid.uuid4()), session["user_id"], title, content))
        db.commit()
        flash("메모를 저장했습니다.")
        return redirect(url_for("memos"))
    rows = db.execute("SELECT id, title, content, is_private FROM memos WHERE user_id = ? ORDER BY created_at DESC", (session["user_id"],)).fetchall()
    return render_page(MEMOS_HTML, memos=rows, username=session["username"])


@app.route("/memos/new", methods=["GET", "POST"])
@login_required
def new_memo():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content or len(title) > MAX_TITLE_LENGTH or len(content) > MAX_CONTENT_LENGTH:
            flash("제목과 내용을 입력해주세요.")
            return render_page(MEMO_FORM_HTML, form_title="새 메모", memo=None), 400
        get_db().execute(
            "INSERT INTO memos (id, user_id, title, content, is_private) VALUES (?, ?, ?, ?, 1)",
            (str(uuid.uuid4()), session["user_id"], title, content),
        )
        get_db().commit()
        flash("메모를 저장했습니다.")
        return redirect(url_for("memos"))
    return render_page(MEMO_FORM_HTML, form_title="새 메모", memo=None)


@app.get("/activity")
@login_required
def activity():
    rows = get_db().execute("SELECT id, title, content, is_private FROM memos WHERE user_id = ? ORDER BY created_at DESC", (session["user_id"],)).fetchall()
    return render_page(MEMOS_HTML, memos=rows, username=session["username"])


@app.get("/memo/<string:memo_id>")
@login_required
def view_memo(memo_id):
    return render_page(MEMO_VIEW_HTML, memo=owned_memo_or_404(memo_id))


@app.get("/memos/<string:memo_id>")
@login_required
def view_memo_legacy(memo_id):
    return render_page(MEMO_VIEW_HTML, memo=owned_memo_or_404(memo_id))


@app.route("/memos/<string:memo_id>/edit", methods=["GET", "POST"])
@login_required
def edit_memo(memo_id):
    memo = owned_memo_or_404(memo_id)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content or len(title) > MAX_TITLE_LENGTH or len(content) > MAX_CONTENT_LENGTH:
            flash("제목과 내용을 입력해주세요.")
            return render_page(MEMO_FORM_HTML, form_title="메모 수정", memo=memo), 400
        get_db().execute("UPDATE memos SET title = ?, content = ? WHERE id = ? AND user_id = ?", (title, content, memo_id, session["user_id"]))
        get_db().commit()
        flash("메모를 수정했습니다.")
        return redirect(url_for("view_memo", memo_id=memo_id))
    return render_page(MEMO_FORM_HTML, form_title="메모 수정", memo=memo)


@app.post("/memos/<string:memo_id>/delete")
@login_required
def delete_memo(memo_id):
    owned_memo_or_404(memo_id)
    get_db().execute("DELETE FROM memos WHERE id = ? AND user_id = ?", (memo_id, session["user_id"]))
    get_db().commit()
    flash("메모를 삭제했습니다.")
    return redirect(url_for("memos"))


@app.get("/admin")
@admin_required
def admin():
    rows = get_db().execute("SELECT memos.title, memos.content, memos.is_private, users.username FROM memos JOIN users ON users.id = memos.user_id ORDER BY memos.created_at DESC").fetchall()
    users = get_db().execute("SELECT id, username, is_admin FROM users ORDER BY id").fetchall()
    return render_page(ADMIN_HTML + USER_LIST_HTML, memos=rows, users=users)


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
