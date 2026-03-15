from .health import router as health_router
from .uploads import router as uploads_router
from .reports import router as reports_router

__all__ = ["health_router", "uploads_router", "reports_router"]
