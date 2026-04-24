# ============================================================
#  ThreatPulse AI - github_auth.py
#  GitHub OAuth 2.0 Authentication (PostgreSQL)
# ============================================================

import os
import secrets
import httpx
import logging
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from auth import get_conn, _q, create_session, hash_password, SESSION_TTL

logger = logging.getLogger("sentinel.github_auth")
router = APIRouter(prefix="/auth/github", tags=["github-auth"])

GITHUB_CLIENT_ID     = os.environ.get("GITHUB_CLIENT_ID", "Ov23li6g7L66zkast59N")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "3acfebad4f259f64fa5c5ba6ae13558093c19b4d")
REDIRECT_URI         = os.environ.get("GITHUB_REDIRECT_URI", "http://127.0.0.1:8000/auth/github/callback")

GITHUB_AUTH_URL  = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL  = "https://api.github.com/user"
GITHUB_EMAIL_URL = "https://api.github.com/user/emails"

_oauth_states: dict = {}


@router.get("/login")
async def github_login(request: Request):
    if not GITHUB_CLIENT_ID or GITHUB_CLIENT_ID == "Ov23li6g7L66zkast59N":
        return RedirectResponse(url="/login.html?error=github_not_configured")

    state = secrets.token_urlsafe(32)
    _oauth_states[state] = True

    params = {
        "client_id":    GITHUB_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope":        "user:email read:user",
        "state":        state,
    }
    return RedirectResponse(url=GITHUB_AUTH_URL + "?" + urlencode(params))


@router.get("/callback")
async def github_callback(request: Request):
    params = dict(request.query_params)
    code   = params.get("code")
    state  = params.get("state")
    error  = params.get("error")

    if error:
        return RedirectResponse(url="/login.html?error=github_denied")
    if not state or state not in _oauth_states:
        return RedirectResponse(url="/login.html?error=invalid_state")
    del _oauth_states[state]
    if not code:
        return RedirectResponse(url="/login.html?error=no_code")

    try:
        # Exchange code for token
        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                GITHUB_TOKEN_URL,
                data={
                    "client_id":     GITHUB_CLIENT_ID,
                    "client_secret": GITHUB_CLIENT_SECRET,
                    "code":          code,
                    "redirect_uri":  REDIRECT_URI,
                },
                headers={"Accept": "application/json"}
            )
            token_data = token_resp.json()

        if "error" in token_data:
            logger.error(f"GitHub token error: {token_data}")
            return RedirectResponse(url="/login.html?error=token_failed")

        access_token = token_data.get("access_token")
        if not access_token:
            return RedirectResponse(url="/login.html?error=no_token")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept":        "application/vnd.github+json",
        }

        # Get user info and emails
        async with httpx.AsyncClient() as client:
            user_resp  = await client.get(GITHUB_USER_URL,  headers=headers)
            email_resp = await client.get(GITHUB_EMAIL_URL, headers=headers)

        github_user   = user_resp.json()
        github_emails = email_resp.json()

        github_id = str(github_user.get("id", ""))
        username  = github_user.get("login", "")
        avatar    = github_user.get("avatar_url", "")

        # Get primary verified email
        email = None
        if isinstance(github_emails, list):
            for e in github_emails:
                if e.get("primary") and e.get("verified"):
                    email = e.get("email")
                    break
            if not email and github_emails:
                email = github_emails[0].get("email")
        if not email:
            email = github_user.get("email")
        if not email:
            return RedirectResponse(url="/login.html?error=no_email")

        email = email.lower()

        # Upsert user in PostgreSQL
        user_id = upsert_github_user(github_id, email, username, avatar)

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
        logger.info(f"GitHub login success: {email}")
        return resp

    except Exception as e:
        logger.error(f"GitHub OAuth error: {e}", exc_info=True)
        return RedirectResponse(url="/login.html?error=oauth_failed")


def upsert_github_user(github_id: str, email: str, username: str, avatar: str) -> int:
    """Find or create user from GitHub OAuth. Returns user id."""
    with get_conn() as conn:
        # Check if already signed in with GitHub
        row = _q(conn,
            "SELECT id FROM users WHERE github_id = %s",
            (github_id,)
        ).fetchone()
        if row:
            _q(conn,
               "UPDATE users SET last_login=NOW(), avatar_url=%s WHERE github_id=%s",
               (avatar, github_id))
            return row["id"]

        # Check if email already exists (link accounts)
        row = _q(conn,
            "SELECT id FROM users WHERE email = %s",
            (email,)
        ).fetchone()
        if row:
            _q(conn,
               "UPDATE users SET github_id=%s, avatar_url=%s, last_login=NOW() WHERE id=%s",
               (github_id, avatar, row["id"]))
            return row["id"]

        # New user - create account
        safe_username = _unique_username(username or email.split("@")[0], conn)
        _q(conn, """
            INSERT INTO users
              (username, email, password_hash, github_id, avatar_url, role)
            VALUES (%s, %s, %s, %s, %s, 'analyst')
        """, (
            safe_username,
            email,
            hash_password(secrets.token_hex(32)),
            github_id,
            avatar,
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
