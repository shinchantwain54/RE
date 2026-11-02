#!/usr/bin/env python3
"""Blog backend for the SHINCHAN.EXE page. Standard library only.

Start it with a strong admin password in the environment:
    PowerShell:  $env:ADMIN_PASSWORD = "..."; python server.py
    bash:        ADMIN_PASSWORD="..." python server.py

Public:  GET /api/blogs            published posts only
         GET /           index.html
         GET /admin      control page (still needs the password to do anything)
Admin:   POST /api/login, POST /api/logout, and /api/admin/blogs (CRUD), all behind a session cookie.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT / "blogs.json"
PAGES = {"/": "index.html", "/index.html": "index.html", "/admin": "admin.html", "/admin.html": "admin.html"}
COOKIE = "shx_admin"
SESSION_TTL = 8 * 60 * 60
LOGIN_WINDOW = 15 * 60
LOGIN_MAX = 5
MAX_BODY = 100 * 1024
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
UUID_RE = re.compile(r"^/api/admin/blogs/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")

PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
if len(PASSWORD) < 12:
    raise SystemExit("Set ADMIN_PASSWORD to at least 12 characters before starting.")
PASSWORD_DIGEST = hashlib.sha256(PASSWORD.encode()).digest()
COOKIE_SECURE = os.environ.get("COOKIE_SECURE") == "1"  # set to 1 when served over HTTPS

sessions = {}   # sha256(token) -> expiry (epoch seconds); raw tokens are never stored
failures = {}   # client ip -> (failed count, window start)
state_lock = threading.Lock()
data_lock = threading.Lock()


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def sha256_hex(text):
    return hashlib.sha256(text.encode()).hexdigest()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_posts():
    try:
        # utf-8-sig also accepts a BOM, which Windows editors and PowerShell often add.
        return json.loads(DATA_FILE.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return []


def sorted_posts(posts):
    return sorted(posts, key=lambda p: (p.get("date", ""), p.get("createdAt", "")), reverse=True)


def mutate_posts(change):
    """Apply change(posts) under a lock and save. If change raises, nothing is written."""
    with data_lock:
        posts = load_posts()
        result = change(posts)
        tmp = DATA_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(posts, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, DATA_FILE)  # atomic swap, so readers never see a half-written file
        return result


def find_post(posts, post_id):
    for post in posts:
        if post["id"] == post_id:
            return post
    raise ApiError(404, "Post not found.")


def validate(data):
    if not isinstance(data, dict):
        raise ApiError(400, "Expected a JSON object.")

    def text(key, limit, required=False):
        value = data.get(key, "")
        value = value.strip() if isinstance(value, str) else ""
        if len(value) > limit:
            raise ApiError(400, f"{key} must be at most {limit} characters.")
        if required and not value:
            raise ApiError(400, f"{key} is required.")
        return value

    date = text("date", 10, required=True)
    if not DATE_RE.match(date):
        raise ApiError(400, "date must look like YYYY-MM-DD.")
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise ApiError(400, "date is not a real calendar date.")
    return {
        "title": text("title", 120, required=True),
        "excerpt": text("excerpt", 300),
        "date": date,
        "body": text("body", 20000, required=True),
        "published": data.get("published") is True,
    }


def new_session():
    token = secrets.token_urlsafe(32)
    now = time.time()
    with state_lock:
        for key in [k for k, exp in sessions.items() if exp < now]:
            del sessions[key]
        sessions[sha256_hex(token)] = now + SESSION_TTL
    return token


def session_valid(token):
    if not token:
        return False
    key = sha256_hex(token)
    with state_lock:
        exp = sessions.get(key)
        if exp is None or exp < time.time():
            sessions.pop(key, None)
            return False
        return True


def login_blocked(ip):
    with state_lock:
        count, start = failures.get(ip, (0, 0.0))
        return time.time() - start <= LOGIN_WINDOW and count >= LOGIN_MAX


def record_failure(ip):
    now = time.time()
    with state_lock:
        count, start = failures.get(ip, (0, now))
        if now - start > LOGIN_WINDOW:
            count, start = 0, now
        failures[ip] = (count + 1, start)


def cookie_header(value, max_age):
    header = f"{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    return header + ("; Secure" if COOKIE_SECURE else "")


class Handler(BaseHTTPRequestHandler):
    server_version = "shx-blog"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass  # keep the console quiet; add logging here if you need an audit trail

    def send_body(self, status, body, content_type, extra_headers=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, status, payload, extra_headers=()):
        self.send_body(status, json.dumps(payload, ensure_ascii=False),
                       "application/json; charset=utf-8", extra_headers)

    def read_json(self):
        # Requiring JSON also blocks cross-site HTML forms, which cannot send this content type.
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ApiError(415, "Send the request as application/json.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "Bad Content-Length.")
        if length > MAX_BODY:
            raise ApiError(413, "Request is too large.")
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            raise ApiError(400, "Malformed JSON.")

    def session_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                return value
        return ""

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_PUT(self):
        self.dispatch("PUT")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def dispatch(self, method):
        try:
            path = urlsplit(self.path).path
            if method == "GET" and path in PAGES:
                return self.send_body(200, (ROOT / PAGES[path]).read_bytes(), "text/html; charset=utf-8")
            if method == "GET" and path == "/api/blogs":
                published = [p for p in sorted_posts(load_posts()) if p.get("published")]
                public = [{k: v for k, v in p.items() if k != "published"} for p in published]
                return self.send_json(200, {"posts": public})
            if method == "POST" and path == "/api/login":
                return self.login()
            if method == "POST" and path == "/api/logout":
                with state_lock:
                    sessions.pop(sha256_hex(self.session_token()), None)
                return self.send_json(200, {"ok": True}, [("Set-Cookie", cookie_header("", 0))])
            if path.startswith("/api/admin/"):
                if not session_valid(self.session_token()):
                    raise ApiError(401, "Log in first.")
                return self.admin(method, path)
            raise ApiError(404, "Not found.")
        except ApiError as err:
            self.send_json(err.status, {"error": err.message})
        except Exception:
            import traceback
            traceback.print_exc()
            self.send_json(500, {"error": "Server error."})

    def login(self):
        ip = self.client_address[0]
        if login_blocked(ip):
            raise ApiError(429, "Too many attempts. Try again in 15 minutes.")
        body = self.read_json()
        password = body.get("password", "") if isinstance(body, dict) else ""
        if not isinstance(password, str) or not hmac.compare_digest(
                hashlib.sha256(password.encode()).digest(), PASSWORD_DIGEST):
            record_failure(ip)
            raise ApiError(401, "Wrong password.")
        with state_lock:
            failures.pop(ip, None)
        token = new_session()
        self.send_json(200, {"ok": True}, [("Set-Cookie", cookie_header(token, SESSION_TTL))])

    def admin(self, method, path):
        if path == "/api/admin/blogs" and method == "GET":
            return self.send_json(200, {"posts": sorted_posts(load_posts())})
        if path == "/api/admin/blogs" and method == "POST":
            fields = validate(self.read_json())
            post = {"id": str(uuid.uuid4()), **fields, "createdAt": now_iso()}
            mutate_posts(lambda posts: posts.append(post))
            return self.send_json(201, {"post": post})
        match = UUID_RE.match(path)
        if match and method == "PUT":
            fields = validate(self.read_json())

            def update(posts):
                post = find_post(posts, match.group(1))
                post.update(fields)
                return post

            return self.send_json(200, {"post": mutate_posts(update)})
        if match and method == "DELETE":
            def remove(posts):
                posts.remove(find_post(posts, match.group(1)))

            mutate_posts(remove)
            return self.send_json(200, {"ok": True})
        raise ApiError(404, "Not found.")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")  # localhost only unless you say otherwise
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Blog control panel: http://{host}:{port}/admin")
    server.serve_forever()
