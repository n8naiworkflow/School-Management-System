"""Administrator login for the school app. Settings are read from .env."""
import hashlib
import os
import secrets
import threading
import time
from collections import deque

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pwdlib import PasswordHash
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GPS 223 RB II — Login</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;
place-items:center;padding:20px;font-family:Arial,sans-serif;
background:linear-gradient(135deg,#123b70,#087f8c)}
main{background:white;padding:30px;border-radius:16px;width:100%;max-width:420px}
h1{color:#123b70;font-size:25px}label{display:block;margin:18px 0 7px}
input,button{width:100%;padding:13px;border-radius:8px;font:inherit}
input{border:1px solid #bac9d8}button{margin-top:24px;background:#1266b0;
color:white;border:0;cursor:pointer}p{color:#536277}
</style></head><body><main><h1>GPS 223 RB II</h1>
<p>Administrator sign in</p><form action="/login" method="post">
<label for="username">Username</label>
<input id="username" name="username" required maxlength="100" autocomplete="username">
<label for="password">Password</label>
<input id="password" name="password" type="password" required maxlength="256"
autocomplete="current-password"><button type="submit">Sign in</button>
</form></main></body></html>"""


def install_security(app: FastAPI):
    username = os.getenv("ADMIN_USERNAME", "").strip()
    password_hash = os.getenv("ADMIN_PASSWORD_HASH", "")
    secret = os.getenv("SESSION_SECRET", "")
    origin = os.getenv("APP_ORIGIN", "").rstrip("/")
    secure_cookie = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    if not all((username, password_hash, secret, origin)):
        raise RuntimeError("Missing administrator settings in .env.")
    if len(secret) < 32:
        raise RuntimeError("SESSION_SECRET must contain at least 32 characters.")
    if secure_cookie and not origin.startswith("https://"):
        raise RuntimeError("Secure cookies require an HTTPS APP_ORIGIN.")

    hasher = PasswordHash.recommended()
    # Fail clearly at startup if the stored hash was copied incorrectly.
    try:
        hasher.verify("configuration-check-only", password_hash)
    except Exception:
        raise RuntimeError("ADMIN_PASSWORD_HASH is invalid. Copy the full generated hash into .env.") from None

    version = hashlib.sha256(f"{username}:{password_hash}".encode()).hexdigest()
    lifetime = 8 * 60 * 60
    attempts = deque()
    lock = threading.Lock()

    class LoginRequired(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                if request.headers.get("origin") != origin:
                    return JSONResponse({"detail": "Request origin not allowed. Open the APP_ORIGIN address."}, status_code=403)

            if request.url.path != "/login":
                expires = request.session.get("expires_at", 0)
                valid = (
                    request.session.get("admin") == username
                    and request.session.get("version") == version
                    and isinstance(expires, (int, float))
                    and expires > time.time()
                )
                if not valid:
                    request.session.clear()
                    if request.url.path == "/":
                        response = RedirectResponse("/login", status_code=303)
                    else:
                        response = JSONResponse({"detail": "Please log in."}, status_code=401)
                    response.headers["Cache-Control"] = "no-store"
                    return response

            response = await call_next(request)
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "same-origin"
            return response

    @app.get("/login", response_class=HTMLResponse)
    def login_page():
        return HTMLResponse(LOGIN_PAGE)

    @app.post("/login")
    def login(request: Request,
              username_input: str = Form(alias="username", max_length=100),
              password: str = Form(max_length=256)):
        now = time.monotonic()
        with lock:
            while attempts and attempts[0] <= now - 60:
                attempts.popleft()
            if len(attempts) >= 20:
                return HTMLResponse('<p>Too many attempts. Wait one minute.</p><a href="/login">Try again</a>', status_code=429, headers={"Retry-After": "60"})
            attempts.append(now)
        password_ok = hasher.verify(password, password_hash)
        username_ok = secrets.compare_digest(username_input.encode(), username.encode())
        if not (username_ok and password_ok):
            return HTMLResponse('<p>Incorrect username or password.</p><a href="/login">Try again</a>', status_code=401)
        request.session.clear()
        request.session.update(admin=username, version=version, expires_at=time.time() + lifetime)
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    app.add_middleware(LoginRequired)
    # SessionMiddleware must wrap LoginRequired, so it is added last.
    app.add_middleware(SessionMiddleware, secret_key=secret,
                       session_cookie="gps_school_session", max_age=lifetime,
                       same_site="strict", https_only=secure_cookie)
