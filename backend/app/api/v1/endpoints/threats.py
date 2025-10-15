"""Threat management endpoints - placeholder"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def list_threats():
    return {"message": "List threats endpoint"}

@router.get("/{threat_id}")
async def get_threat(threat_id: int):
    return {"message": f"Get threat {threat_id}"}
