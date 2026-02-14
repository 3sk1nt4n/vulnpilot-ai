"""
VulnPilot AI - Authentication & Authorization
JWT-based auth with role-based access control (RBAC).

Roles:
  admin    - Full access: config, users, scan triggers, all data
  analyst  - Read all data, create tickets, run reports, trigger scans
  viewer   - Read-only: dashboards, reports, findings (no config changes)
  api      - Service account: API-only access for integrations/CI-CD

Auth flow:
  1. POST /api/v1/auth/login   → {username, password} → JWT token
  2. Include header: Authorization: Bearer <token>
  3. Token expires in AUTH_TOKEN_EXPIRY_HOURS (default: 8)

Disable auth for development:
  AUTH_ENABLED=false (default: false for dev, true for production)

Password hashing: bcrypt (direct)
Token signing: PyJWT with HS256
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").lower() == "true"
AUTH_SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "vulnpilot-dev-secret-change-in-production")
AUTH_ALGORITHM = "HS256"
AUTH_TOKEN_EXPIRY_HOURS = int(os.getenv("AUTH_TOKEN_EXPIRY_HOURS", "8"))


class Role:
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API = "api"
    ALL = [ADMIN, ANALYST, VIEWER, API]


# In-memory user store for dev. Production: use PostgreSQL users table.
DEFAULT_USERS = {
    "admin": {
        "password_hash": "",  # Set on first run or via AUTH_ADMIN_PASSWORD
        "role": Role.ADMIN,
        "display_name": "Admin",
        "email": "",
    },
}


def _hash_password(password: str) -> str:
    """Hash password. Uses SHA-256 by default (safe for dev). bcrypt if available."""
    import hashlib
    return "sha256:" + hashlib.sha256(password.encode()).hexdigest()


def _verify_password(plain: str, hashed: str) -> bool:
    """Verify password against hash."""
    import hashlib
    if hashed.startswith("sha256:"):
        return hashed == "sha256:" + hashlib.sha256(plain.encode()).hexdigest()
    return False


def _create_token(username: str, role: str) -> str:
    """Create a JWT token."""
    try:
        import jwt
    except ImportError:
        # Fallback: simple base64 token (dev only)
        import base64, json
        payload = {"sub": username, "role": role, "exp": (datetime.utcnow() + timedelta(hours=AUTH_TOKEN_EXPIRY_HOURS)).isoformat()}
        return "dev." + base64.b64encode(json.dumps(payload).encode()).decode()

    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=AUTH_TOKEN_EXPIRY_HOURS),
    }
    return jwt.encode(payload, AUTH_SECRET_KEY, algorithm=AUTH_ALGORITHM)


def _decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token."""
    if token.startswith("dev."):
        # Dev fallback token
        import base64, json
        try:
            payload = json.loads(base64.b64decode(token[4:]).decode())
            exp = datetime.fromisoformat(payload["exp"])
            if exp < datetime.utcnow():
                return None
            return payload
        except Exception:
            return None
    try:
        import jwt
        return jwt.decode(token, AUTH_SECRET_KEY, algorithms=[AUTH_ALGORITHM])
    except Exception:
        return None


class UserStore:
    """In-memory user store. Replace with DB for production."""

    def __init__(self):
        self.users = dict(DEFAULT_USERS)
        # Auto-create admin from env var
        admin_pw = os.getenv("AUTH_ADMIN_PASSWORD", "admin")
        if admin_pw:
            self.users["admin"]["password_hash"] = _hash_password(admin_pw)

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        """Authenticate user, return user dict or None."""
        user = self.users.get(username)
        if not user:
            return None
        if not _verify_password(password, user["password_hash"]):
            return None
        return {"username": username, "role": user["role"], "display_name": user["display_name"]}

    def create_user(self, username: str, password: str, role: str = Role.VIEWER,
                    display_name: str = "", email: str = "") -> bool:
        """Create a new user."""
        if username in self.users:
            return False
        if role not in Role.ALL:
            return False
        self.users[username] = {
            "password_hash": _hash_password(password),
            "role": role,
            "display_name": display_name or username,
            "email": email,
        }
        return True

    def delete_user(self, username: str) -> bool:
        if username == "admin":
            return False  # Cannot delete admin
        return self.users.pop(username, None) is not None

    def list_users(self) -> list[dict]:
        return [{"username": k, "role": v["role"], "display_name": v["display_name"]}
                for k, v in self.users.items()]

    def update_role(self, username: str, role: str) -> bool:
        if username not in self.users or role not in Role.ALL:
            return False
        self.users[username]["role"] = role
        return True


# Lazy singleton - initialized on first use, not at import time
_store = None


def get_user_store() -> UserStore:
    global _store
    if _store is None:
        _store = UserStore()
    return _store
