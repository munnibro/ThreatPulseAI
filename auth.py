# ============================================================
#  ThreatPulse AI - auth.py
#  Full authentication system for PostgreSQL
# ============================================================

import hashlib
import hmac
import os
import secrets
import psycopg2
import psycopg2.extras
import logging
from datetime import datetime, timedelta
from contextlib import contextmanager

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger("sentinel.auth")

from database import DB_CONFIG

SESSION_TTL       = timedelta(days=7)
SESSION_TTL_SHORT = timedelta(hours=8)
SECRET_KEY        = os.environ.get("SECRET_KEY", secrets.token_hex(32))

router = APIRouter(prefix="/auth", tags=["auth"])


# ── DB connection ─────────────────────────────────────────
@contextmanager
def get_conn():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise
    finally:
        conn.close()


def _q(conn, sql, params=None):
    """Run SQL, return cursor."""
    cur = conn.cursor()
    cur.execute(sql, params or ())
    return cur


# ── Init auth tables ──────────────────────────────────────
def init_auth_tables():
    with get_conn() as conn:
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                username      TEXT    NOT NULL UNIQUE,
                email         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                role          TEXT    DEFAULT 'analyst',
                created_at    TIMESTAMPTZ DEFAULT NOW(),
                last_login    TIMESTAMPTZ,
                is_active     BOOLEAN DEFAULT TRUE,
                google_id     TEXT,
                github_id     TEXT,
                avatar_url    TEXT,
                organisation  TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id          SERIAL PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token       TEXT    NOT NULL UNIQUE,
                created_at  TIMESTAMPTZ DEFAULT NOW(),
                expires_at  TIMESTAMPTZ NOT NULL,
                ip_address  TEXT,
                user_agent  TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS reset_tokens (
                id          SERIAL PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token       TEXT    NOT NULL UNIQUE,
                created_at  TIMESTAMPTZ DEFAULT NOW(),
                expires_at  TIMESTAMPTZ NOT NULL,
                used        BOOLEAN DEFAULT FALSE
            )
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token    ON sessions(token)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user     ON sessions(user_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires  ON sessions(expires_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email       ON users(email)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username    ON users(username)")

    logger.info("Auth tables ready.")


# ── Password helpers ──────────────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h    = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"{salt}:{h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        return hmac.compare_digest(
            h,
            hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()
        )
    except Exception:
        return False


# ── Session helpers ───────────────────────────────────────
def create_session(user_id: int, remember_me: bool = False,
                   ip: str = None, ua: str = None) -> str:
    token  = secrets.token_urlsafe(48)
    ttl    = SESSION_TTL if remember_me else SESSION_TTL_SHORT
    exp    = datetime.utcnow() + ttl
    with get_conn() as conn:
        _q(conn,
           "INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent) "
           "VALUES (%s, %s, %s, %s, %s)",
           (user_id, token, exp, ip, ua))
    return token


def get_session_user(token: str) -> dict | None:
    if not token:
        return None
    with get_conn() as conn:
        cur = _q(conn,
                 "SELECT s.*, u.id as uid, u.username, u.email, u.role, "
                 "u.avatar_url, u.organisation, u.is_active "
                 "FROM sessions s JOIN users u ON s.user_id = u.id "
                 "WHERE s.token = %s AND s.expires_at > NOW()",
                 (token,))
        row = cur.fetchone()
    if not row:
        return None
    if not row["is_active"]:
        return None
    return dict(row)


def get_current_user(request: Request) -> dict | None:
    """Check if user is logged in - used by frontend."""
    token = request.cookies.get("sentinel_session")
    return get_session_user(token)


# ── Cleanup expired sessions ──────────────────────────────
def cleanup_expired():
    with get_conn() as conn:
        _q(conn, "DELETE FROM sessions WHERE expires_at < NOW()")


# ── Pydantic models ───────────────────────────────────────
class RegisterRequest(BaseModel):
    username:         str
    email:            str
    password:         str
    confirm_password: str
    role:             str = "analyst"


class LoginRequest(BaseModel):
    email:       str
    password:    str
    remember_me: bool = False


class ForgotRequest(BaseModel):
    email: str


class ResetRequest(BaseModel):
    token:            str
    password:         str
    confirm_password: str


class UpdateProfileRequest(BaseModel):
    username:     str = ""
    email:        str = ""
    role:         str = ""
    organisation: str = ""


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str
    confirm_password: str


# ── Routes ────────────────────────────────────────────────
@router.post("/register")
async def register(data: RegisterRequest, request: Request):
    if len(data.username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")
    if len(data.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if data.password != data.confirm_password:
        raise HTTPException(400, "Passwords do not match")
    if "@" not in data.email:
        raise HTTPException(400, "Invalid email address")

    with get_conn() as conn:
        existing = _q(conn,
            "SELECT id FROM users WHERE email=%s OR username=%s",
            (data.email.lower(), data.username.lower())
        ).fetchone()
        if existing:
            raise HTTPException(400, "Email or username already registered")

        valid_roles = ("analyst", "engineer", "admin", "viewer")
        role = data.role if data.role in valid_roles else "analyst"

        _q(conn,
           "INSERT INTO users (username, email, password_hash, role) VALUES (%s,%s,%s,%s)",
           (data.username.lower(), data.email.lower(), hash_password(data.password), role))

        user_id = _q(conn,
            "SELECT id FROM users WHERE email=%s",
            (data.email.lower(),)
        ).fetchone()["id"]

    token = create_session(
        user_id,
        remember_me=True,
        ip=request.client.host,
        ua=request.headers.get("user-agent")
    )

    resp = JSONResponse({"success": True, "message": "Account created", "username": data.username})
    resp.set_cookie("sentinel_session", token, httponly=True, samesite="lax",
                    max_age=int(SESSION_TTL.total_seconds()))
    logger.info(f"New user registered: {data.username}")
    return resp


@router.post("/login")
async def login(data: LoginRequest, request: Request):
    with get_conn() as conn:
        user = _q(conn,
            "SELECT * FROM users WHERE email=%s AND is_active=TRUE",
            (data.email.lower(),)
        ).fetchone()

    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(401, "Invalid email or password")

    with get_conn() as conn:
        _q(conn, "UPDATE users SET last_login=NOW() WHERE id=%s", (user["id"],))

    token = create_session(
        user["id"],
        remember_me=data.remember_me,
        ip=request.client.host,
        ua=request.headers.get("user-agent")
    )

    ttl = SESSION_TTL if data.remember_me else SESSION_TTL_SHORT
    resp = JSONResponse({
        "success":  True,
        "username": user["username"],
        "role":     user["role"],
        "email":    user["email"],
    })
    resp.set_cookie("sentinel_session", token, httponly=True, samesite="lax",
                    max_age=int(ttl.total_seconds()))
    return resp


@router.post("/logout")
async def logout(request: Request):
    token = request.cookies.get("sentinel_session")
    if token:
        with get_conn() as conn:
            _q(conn, "DELETE FROM sessions WHERE token=%s", (token,))
    resp = JSONResponse({"success": True})
    resp.delete_cookie("sentinel_session")
    return resp


@router.get("/check")
async def check_auth(request: Request):
    user = get_current_user(request)
    return {"authenticated": user is not None}


@router.get("/me")
async def get_me(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return {
        "id":           user["uid"],
        "username":     user["username"],
        "email":        user["email"],
        "role":         user["role"],
        "avatar_url":   user.get("avatar_url"),
        "organisation": user.get("organisation"),
    }


@router.post("/update-profile")
async def update_profile(data: UpdateProfileRequest, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")

    with get_conn() as conn:
        if data.username:
            _q(conn, "UPDATE users SET username=%s WHERE id=%s",
               (data.username.lower(), user["uid"]))
        if data.email:
            _q(conn, "UPDATE users SET email=%s WHERE id=%s",
               (data.email.lower(), user["uid"]))
        if data.role:
            valid = ("analyst", "engineer", "admin", "viewer")
            if data.role in valid:
                _q(conn, "UPDATE users SET role=%s WHERE id=%s",
                   (data.role, user["uid"]))
        if data.organisation is not None:
            _q(conn, "UPDATE users SET organisation=%s WHERE id=%s",
               (data.organisation, user["uid"]))

    return {"success": True, "message": "Profile updated"}


@router.post("/change-password")
async def change_password(data: ChangePasswordRequest, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    if data.new_password != data.confirm_password:
        raise HTTPException(400, "Passwords do not match")
    if len(data.new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    with get_conn() as conn:
        row = _q(conn, "SELECT password_hash FROM users WHERE id=%s",
                 (user["uid"],)).fetchone()
        if not row or not verify_password(data.current_password, row["password_hash"]):
            raise HTTPException(401, "Current password is incorrect")
        _q(conn, "UPDATE users SET password_hash=%s WHERE id=%s",
           (hash_password(data.new_password), user["uid"]))

    return {"success": True, "message": "Password changed"}


@router.delete("/delete-account")
async def delete_account(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    with get_conn() as conn:
        _q(conn, "DELETE FROM users WHERE id=%s", (user["uid"],))
    resp = JSONResponse({"success": True})
    resp.delete_cookie("sentinel_session")
    return resp


@router.post("/forgot-password")
async def forgot_password(data: ForgotRequest):
    with get_conn() as conn:
        user = _q(conn,
            "SELECT id, email FROM users WHERE email=%s",
            (data.email.lower(),)
        ).fetchone()

        if not user:
            return {"success": True, "message": "If that email exists, a reset link was sent"}

        token  = secrets.token_urlsafe(48)
        exp    = datetime.utcnow() + timedelta(hours=1)
        _q(conn,
           "INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (%s,%s,%s)",
           (user["id"], token, exp))

    logger.info(f"Password reset token generated for user {user['id']}")
    return {"success": True, "token": token, "message": "Reset token generated"}


@router.post("/reset-password")
async def reset_password(data: ResetRequest):
    if data.password != data.confirm_password:
        raise HTTPException(400, "Passwords do not match")
    if len(data.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    with get_conn() as conn:
        row = _q(conn,
            "SELECT * FROM reset_tokens WHERE token=%s AND used=FALSE AND expires_at > NOW()",
            (data.token,)
        ).fetchone()

        if not row:
            raise HTTPException(400, "Invalid or expired reset token")

        _q(conn, "UPDATE users SET password_hash=%s WHERE id=%s",
           (hash_password(data.password), row["user_id"]))
        _q(conn, "UPDATE reset_tokens SET used=TRUE WHERE id=%s", (row["id"],))

    return {"success": True, "message": "Password reset successfully"}
