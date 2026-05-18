"""Aggregate all API sub-routers."""

from fastapi import APIRouter

from esga.api.dashboard import router as dashboard_router
from esga.api.rules import router as rules_router
from esga.api.scans import router as scans_router

api_router = APIRouter()
api_router.include_router(scans_router)
api_router.include_router(rules_router)
api_router.include_router(dashboard_router)
