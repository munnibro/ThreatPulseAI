# ============================================================
#  ThreatPulse AI - google_auth.py
#  Google OAuth 2.0 Authentication (PostgreSQL)
# ============================================================

import os
import secrets
import httpx
import logging
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from auth import get_conn, _q, create_session, hash_password, SESSION_TTL

logger = logging.getLogger("sentinel.google_auth")
router = APIRouter(prefix="/auth/google", tags=["google-auth"])

GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "799581287306-t4vjkcfjkm1j33p4u0nud37grk40pm8t.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "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")
REDIRECT_URI         = os.environ.get("GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/auth/google/callback")

GOOGLE_AUTH_URL  = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USER_URL  = "https://www.googleapis.com/oauth2/v3/userinfo"

_oauth_states: dict = {}


@router.get("/login")
async def google_login(request: Request):
    if not GOOGLE_CLIENT_ID or GOOGLE_CLIENT_ID == "799581287306-t4vjkcfjkm1j33p4u0nud37grk40pm8t.apps.googleusercontent.com":
        return RedirectResponse(url="/login.html?error=not_configured")

    state = secrets.token_urlsafe(32)
    _oauth_states[state] = True

    params = {
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         "openid email profile",
        "state":         state,
        "access_type":   "online",
        "prompt":        "select_account",
    }
    return RedirectResponse(url=GOOGLE_AUTH_URL + "?" + urlencode(params))


@router.get("/callback")
async def google_callback(request: Request):
    params = dict(request.query_params)
    code   = params.get("code")
    state  = params.get("state")
    error  = params.get("error")

    if error:
        return RedirectResponse(url="/login.html?error=google_denied")
    if not state or state not in _oauth_states:
        return RedirectResponse(url="/login.html?error=invalid_state")
    del _oauth_states[state]
    if not code:
        return RedirectResponse(url="/login.html?error=no_code")

    try:
        # Exchange code for token
        async with httpx.AsyncClient() as client:
            token_resp = await client.post(GOOGLE_TOKEN_URL, data={
                "client_id":     GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code":          code,
                "grant_type":    "authorization_code",
                "redirect_uri":  REDIRECT_URI,
            })
            token_data = token_resp.json()

        if "error" in token_data:
            logger.error(f"Google token error: {token_data}")
            return RedirectResponse(url="/login.html?error=token_failed")

        access_token = token_data.get("access_token")
        if not access_token:
            return RedirectResponse(url="/login.html?error=no_token")

        # Get user info
        async with httpx.AsyncClient() as client:
            user_resp = await client.get(
                GOOGLE_USER_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            google_user = user_resp.json()

        google_id = google_user.get("sub")
        email     = google_user.get("email", "").lower()
        name      = google_user.get("name", "")
        picture   = google_user.get("picture", "")

        if not email or not google_id:
            return RedirectResponse(url="/login.html?error=no_email")

        # Upsert user in PostgreSQL
        user_id = upsert_google_user(google_id, email, name, picture)

        # Create session
        token = create_session(
            user_id=user_id,
            remember_me=True,
            ip=request.client.host,
            ua=request.headers.get("user-agent"),
        )

        resp = RedirectResponse(url="/dashboard.html")
        resp.set_cookie(
            "sentinel_session", token,
            httponly=True, samesite="lax",
            max_age=int(SESSION_TTL.total_seconds())
        )
        logger.info(f"Google login success: {email}")
        return resp

    except Exception as e:
        logger.error(f"Google OAuth error: {e}", exc_info=True)
        return RedirectResponse(url="/login.html?error=oauth_failed")


def upsert_google_user(google_id: str, email: str, name: str, picture: str) -> int:
    """Find or create user from Google OAuth. Returns user id."""
    with get_conn() as conn:
        # Check if already signed in with Google
        row = _q(conn,
            "SELECT id FROM users WHERE google_id = %s",
            (google_id,)
        ).fetchone()
        if row:
            _q(conn,
               "UPDATE users SET last_login=NOW(), avatar_url=%s WHERE google_id=%s",
               (picture, google_id))
            return row["id"]

        # Check if email already exists (link accounts)
        row = _q(conn,
            "SELECT id FROM users WHERE email = %s",
            (email,)
        ).fetchone()
        if row:
            _q(conn,
               "UPDATE users SET google_id=%s, avatar_url=%s, last_login=NOW() WHERE id=%s",
               (google_id, picture, row["id"]))
            return row["id"]

        # New user - create account
        username = _unique_username(name or email.split("@")[0], conn)
        _q(conn, """
            INSERT INTO users
              (username, email, password_hash, google_id, avatar_url, role)
            VALUES (%s, %s, %s, %s, %s, 'analyst')
        """, (
            username,
            email,
            hash_password(secrets.token_hex(32)),
            google_id,
            picture,
        ))

        return _q(conn,
            "SELECT id FROM users WHERE email = %s",
            (email,)
        ).fetchone()["id"]


def _unique_username(base: str, conn) -> str:
    """Generate a unique username from base string."""
    base = "".join(c for c in base.lower() if c.isalnum())[:20] or "user"
    username, n = base, 1
    while _q(conn, "SELECT id FROM users WHERE username=%s", (username,)).fetchone():
        username = f"{base}{n}"
        n += 1
    return username
