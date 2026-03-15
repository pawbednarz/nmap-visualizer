"""Health check endpoint."""
from fastapi import APIRouter
from datetime import datetime

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "VIAR", "timestamp": datetime.utcnow().isoformat()}
