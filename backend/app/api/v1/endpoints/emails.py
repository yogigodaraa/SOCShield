"""Email management endpoints - placeholder"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def list_emails():
    return {"message": "List emails endpoint"}

@router.get("/{email_id}")
async def get_email(email_id: int):
    return {"message": f"Get email {email_id}"}
