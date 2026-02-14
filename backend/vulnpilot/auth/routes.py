"""
VulnPilot AI - Auth Routes
POST /api/v1/auth/login      → Get JWT token
POST /api/v1/auth/register   → Create new user (admin only)
GET  /api/v1/auth/me          → Current user info
GET  /api/v1/auth/users       → List all users (admin only)
PUT  /api/v1/auth/users/{id}  → Update user role (admin only)
DELETE /api/v1/auth/users/{id} → Delete user (admin only)
"""

from fastapi import APIRouter, Request, HTTPException, Depends

from vulnpilot.auth.auth import (
    AUTH_ENABLED, _create_token, get_user_store, Role,
)
from vulnpilot.auth.middleware import require_auth, require_role

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


@auth_router.post("/login")
async def login(request: Request):
    """Authenticate and get JWT token.

    Body: {"username": "admin", "password": "admin"}
    Returns: {"token": "eyJ...", "role": "admin", "expires_in_hours": 8}
    """
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    store = get_user_store()
    user = store.authenticate(username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = _create_token(user["username"], user["role"])
    return {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "display_name": user["display_name"],
        "auth_enabled": AUTH_ENABLED,
    }


@auth_router.get("/me")
async def me(user: dict = Depends(require_auth)):
    """Get current authenticated user info."""
    return {
        "username": user["username"],
        "role": user["role"],
        "auth_enabled": AUTH_ENABLED,
    }


@auth_router.post("/register")
async def register(request: Request, admin: dict = Depends(require_role(Role.ADMIN))):
    """Create a new user (admin only).

    Body: {"username": "analyst1", "password": "pass", "role": "analyst", "display_name": "John"}
    """
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    role = body.get("role", Role.VIEWER)
    display_name = body.get("display_name", "")
    email = body.get("email", "")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    if role not in Role.ALL:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be: {', '.join(Role.ALL)}")

    store = get_user_store()
    if not store.create_user(username, password, role, display_name, email):
        raise HTTPException(status_code=409, detail=f"User '{username}' already exists")

    return {"ok": True, "username": username, "role": role}


@auth_router.get("/users")
async def list_users(admin: dict = Depends(require_role(Role.ADMIN))):
    """List all users (admin only)."""
    store = get_user_store()
    return {"users": store.list_users()}


@auth_router.put("/users/{username}")
async def update_user(username: str, request: Request, admin: dict = Depends(require_role(Role.ADMIN))):
    """Update user role (admin only).

    Body: {"role": "analyst"}
    """
    body = await request.json()
    role = body.get("role", "")
    if not role:
        raise HTTPException(status_code=400, detail="Role required")

    store = get_user_store()
    if not store.update_role(username, role):
        raise HTTPException(status_code=404, detail=f"User '{username}' not found or invalid role")

    return {"ok": True, "username": username, "role": role}


@auth_router.delete("/users/{username}")
async def delete_user(username: str, admin: dict = Depends(require_role(Role.ADMIN))):
    """Delete a user (admin only). Cannot delete 'admin'."""
    store = get_user_store()
    if not store.delete_user(username):
        raise HTTPException(status_code=400, detail=f"Cannot delete '{username}'")
    return {"ok": True, "deleted": username}
