"""Dashboard statistics endpoints - placeholder"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/stats")
async def get_stats():
    return {
        "total_emails": 1250,
        "threats_detected": 47,
        "emails_today": 156,
        "detection_rate": 0.95
    }
