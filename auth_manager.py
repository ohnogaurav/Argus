"""
Simple Session Manager for CyberOPS.
Uses in-memory user store + hashed passwords.
Follows existing project patterns.
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Optional

# ── CONFIG ──────────────────────────────────────────────────────────────
SESSION_TIMEOUT = 3600  # 1 hour in seconds
HASH_ALGORITHM = "sha256"

# ── STATE ───────────────────────────────────────────────────────────────
# In-memory user store
USERS = {
    "admin": {
        "password_hash": hashlib.sha256("admin@123".encode()).hexdigest(),
        "created": datetime.now().isoformat()
    }
}

# Active sessions: token -> {user, created_at, last_access}
SESSIONS = {}

# Security Tracking
FAILED_ATTEMPTS = {}  # user -> {count, last_fail, ip}
LOCKED_USERS = {}     # user -> lock_until_dt
LOCK_DURATION_MINS = 15
MAX_FAILED_ATTEMPTS = 5


def hash_password(password: str) -> str:
    """Hash password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash."""
    return hash_password(password) == password_hash


def generate_session_token() -> str:
    """Generate secure session token."""
    return secrets.token_urlsafe(32)


def create_user(username: str, password: str) -> dict:
    """
    Create new user. Returns {"success": bool, "error": str, "user": username}.
    """
    if not username or len(username) < 3:
        return {"success": False, "error": "Username must be 3+ chars"}
    if not password or len(password) < 8:
        return {"success": False, "error": "Password must be 8+ chars"}
    if username in USERS:
        return {"success": False, "error": "User already exists"}

    USERS[username] = {
        "password_hash": hash_password(password),
        "created": datetime.now().isoformat()
    }
    return {"success": True, "user": username}


def is_user_locked(username: str) -> Optional[datetime]:
    """Check if user is currently locked. Returns unlock time or None."""
    if username in LOCKED_USERS:
        unlock_time = LOCKED_USERS[username]
        if datetime.now() < unlock_time:
            return unlock_time
        else:
            del LOCKED_USERS[username]
    return None


def login_user(username: str, password: str, ip: str = "unknown") -> dict:
    """
    Authenticate user. Returns {"success": bool, "error": str, "token": str, "user": username}.
    """
    # Check if locked
    unlock_time = is_user_locked(username)
    if unlock_time:
        wait_secs = int((unlock_time - datetime.now()).total_seconds())
        return {
            "success": False, 
            "error": f"Account locked due to multiple failed attempts. Try again in {wait_secs}s.",
            "locked": True,
            "unlock_at": unlock_time.isoformat()
        }

    if username not in USERS:
        return {"success": False, "error": "Invalid username or password"}

    user_data = USERS[username]
    if not verify_password(password, user_data["password_hash"]):
        # Track failure
        fail_data = FAILED_ATTEMPTS.get(username, {"count": 0})
        fail_data["count"] += 1
        fail_data["last_fail"] = datetime.now()
        fail_data["ip"] = ip
        FAILED_ATTEMPTS[username] = fail_data

        # Lock if too many attempts
        if fail_data["count"] >= MAX_FAILED_ATTEMPTS:
            LOCKED_USERS[username] = datetime.now() + timedelta(minutes=LOCK_DURATION_MINS)
            return {
                "success": False, 
                "error": "Account locked! Too many failed attempts.",
                "locked": True,
                "count": fail_data["count"]
            }

        return {
            "success": False, 
            "error": "Invalid username or password",
            "count": fail_data["count"]
        }

    # Success: reset failures
    if username in FAILED_ATTEMPTS:
        del FAILED_ATTEMPTS[username]

    token = generate_session_token()
    SESSIONS[token] = {
        "user": username,
        "created": datetime.now(),
        "last_access": datetime.now()
    }
    return {"success": True, "token": token, "user": username}


def validate_session(token: Optional[str]) -> dict:
    """
    Check if session token is valid. Returns {"valid": bool, "user": str, "error": str}.
    """
    if not token or token not in SESSIONS:
        return {"valid": False, "user": None, "error": "Invalid session"}

    session = SESSIONS[token]
    now = datetime.now()
    created = session["created"]
    last_access = session["last_access"]

    # Check if session expired
    if (now - created).total_seconds() > SESSION_TIMEOUT:
        del SESSIONS[token]
        return {"valid": False, "user": None, "error": "Session expired"}

    # Check if inactive too long
    if (now - last_access).total_seconds() > SESSION_TIMEOUT:
        del SESSIONS[token]
        return {"valid": False, "user": None, "error": "Session expired"}

    # Update last access time
    session["last_access"] = now
    return {"valid": True, "user": session["user"], "error": None}


def logout_user(token: str) -> dict:
    """Logout user by destroying session."""
    if token in SESSIONS:
        del SESSIONS[token]
        return {"success": True}
    return {"success": False, "error": "Invalid session"}


def get_session_count() -> int:
    """Get active session count."""
    return len(SESSIONS)


def get_user_count() -> int:
    """Get registered user count."""
    return len(USERS)


def require_login(f):
    """
    Decorator to require login for route.
    Extracts token from cookie and validates.
    Passes validated user to route as 'user' parameter.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request, redirect
        token = request.cookies.get("session_token")
        session = validate_session(token)
        if not session["valid"]:
            return redirect("/login?redirect=" + request.path)
        return f(*args, **kwargs, user=session["user"])
    return decorated_function


def get_current_user(request):
    """Extract current user from request cookies."""
    token = request.cookies.get("session_token")
    session = validate_session(token)
    if session["valid"]:
        return session["user"]
    return None
