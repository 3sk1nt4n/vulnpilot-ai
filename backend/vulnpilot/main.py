"""
VulnPilot AI - FastAPI Application
Main entry point. Same app serves local and cloud modes.
"""

import logging
import os as _os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from vulnpilot.config import get_settings
from vulnpilot.api.routes import router
from vulnpilot.db.session import init_db

# Auth routes - import safely (PyJWT/bcrypt may not be installed yet)
try:
    from vulnpilot.auth.routes import auth_router
    _auth_available = True
except ImportError as e:
    _auth_available = False
    auth_router = None

APP_VERSION = "1.0.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    settings = get_settings()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    logger = logging.getLogger("vulnpilot")

    logger.info("=" * 60)
    logger.info(f"  VulnPilot AI v{APP_VERSION}")
    logger.info(f"  Mode: {'LOCAL (Ollama)' if settings.is_local_mode else 'CLOUD (Claude)'}")
    logger.info(f"  LLM: {settings.llm_provider}")
    logger.info(f"  Scanners: {settings.scanner_provider_list}")
    logger.info(f"  Tickets: {settings.ticket_provider}")
    logger.info(f"  Threat Intel: {settings.threatintel_mode}")
    logger.info("=" * 60)

    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.warning(f"Database init skipped (may not be available): {e}")

    yield

    logger.info("VulnPilot AI shutting down")


app = FastAPI(
    title="VulnPilot AI",
    description=(
        "Agentic Vulnerability Management Orchestrator. "
        "Zero Noise. Zero Delay. Zero Missed Patches."
    ),
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock down in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(router)
if _auth_available:
    app.include_router(auth_router, prefix="/api/v1")


# ─── Serve Dashboard ───
# Try multiple possible frontend locations
_frontend_candidates = [
    _os.path.join("/app", "frontend"),                                    # Docker mount
    _os.path.join(_os.path.dirname(__file__), "..", "..", "frontend"),     # Local dev
    _os.path.join(_os.path.dirname(__file__), "..", "frontend"),          # Alt layout
]

_frontend_dir = None
for _candidate in _frontend_candidates:
    _resolved = _os.path.abspath(_candidate)
    if _os.path.isdir(_resolved) and _os.path.isfile(_os.path.join(_resolved, "index.html")):
        _frontend_dir = _resolved
        break

if _frontend_dir:
    app.mount("/static", StaticFiles(directory=_frontend_dir), name="static")

    @app.get("/")
    async def dashboard():
        resp = FileResponse(_os.path.join(_frontend_dir, "index.html"))
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.get("/setup")
    async def setup_page():
        setup_file = _os.path.join(_frontend_dir, "setup.html")
        if _os.path.isfile(setup_file):
            return FileResponse(setup_file)
        return {"error": "setup.html not found"}
else:
    @app.get("/")
    async def root():
        settings = get_settings()
        return {
            "name": "VulnPilot AI",
            "tagline": "Zero Noise. Zero Delay. Zero Missed Patches.",
            "version": "1.0.0",
            "mode": "local" if settings.is_local_mode else "cloud",
            "docs": "/docs",
            "note": "Frontend not found. Place frontend/ directory alongside backend/",
        }
