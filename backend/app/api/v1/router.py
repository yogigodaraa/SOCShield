"""
API Router - Main router combining all endpoints
"""

from fastapi import APIRouter
from app.api.v1.endpoints import emails, analysis, threats, dashboard, config

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(emails.router, prefix="/emails", tags=["emails"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["analysis"])
api_router.include_router(threats.router, prefix="/threats", tags=["threats"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(config.router, prefix="/config", tags=["config"])
