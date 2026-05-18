"""
ESGA Application Entry Point.

Creates the FastAPI app, mounts static files, configures templates,
includes API routers, and seeds the database on startup.
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from esga.api.router import api_router
from esga.database import Base, SessionLocal, engine
from esga.rules.seed import seed_rules

# Paths
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables and seed rules on startup."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        count = seed_rules(db)
        if count > 0:
            print(f"[ESGA] Seeded {count} security rules into database.")
        else:
            print("[ESGA] All rules already present in database.")
    finally:
        db.close()
    yield


# Create FastAPI app
app = FastAPI(
    title="ESGA - Enterprise Security Guardrail Auditor",
    description="Terraform security configuration scanner",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Jinja2 templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Include API routes
app.include_router(api_router)


@app.get("/", include_in_schema=False)
async def dashboard(request: Request):
    """Serve the single-page dashboard."""
    return templates.TemplateResponse(
        request=request, name="dashboard.html"
    )
