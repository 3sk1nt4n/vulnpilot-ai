"""
VulnPilot AI - Auth Middleware
Enforces JWT authentication and role-based access control on API routes.

Usage in routes:
    from vulnpilot.auth.middleware import require_auth, require_role

    @router.get("/protected")
    async def protected(user=Depends(require_auth)):
        return {"hello": user["username"]}

    @router.post("/admin-only")
    async def admin_only(user=Depends(require_role("admin"))):
        return {"admin": True}

Disable for development:
    AUTH_ENABLED=false  → all routes open (default)
"""

import logging
import os
from typing import Optional

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from vulnpilot.auth.auth import (
    AUTH_ENABLED, _decode_token, _create_token,
    get_user_store, Role,
)

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[dict]:
    """Extract and validate user from JWT token.
    Returns None if auth is disabled (dev mode)."""

    if not AUTH_ENABLED:
        # Dev mode: return a fake admin user
        return {"username": "dev", "role": Role.ADMIN}

    if not credentials:
        raise HTTPException(status_code=401, detail="Missing authorization header")

    token = credentials.credentials
    payload = _decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return {"username": payload["sub"], "role": payload["role"]}


def require_auth(user: dict = Depends(get_current_user)) -> dict:
    """Dependency: require any authenticated user."""
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_role(*roles: str):
    """Dependency factory: require specific role(s).

    Usage:
        @router.post("/admin-only")
        async def admin_only(user=Depends(require_role("admin"))):
            ...

        @router.get("/analyst-or-admin")
        async def data(user=Depends(require_role("admin", "analyst"))):
            ...
    """
    async def _check(user: dict = Depends(get_current_user)):
        if not AUTH_ENABLED:
            return user
        if user["role"] not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{user['role']}' not authorized. Required: {', '.join(roles)}",
            )
        return user
    return _check
