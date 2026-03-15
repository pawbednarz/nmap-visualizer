"""
VIAR — Vulnerability Intelligence and Analysis Reporting
FastAPI Application Entry Point
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from viar.api.middleware import InputSanitizationMiddleware
from viar.api.routes import health_router, uploads_router, reports_router
from viar.config import get_settings

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    app = FastAPI(
        title="VIAR — Vulnerability Intelligence and Analysis Reporting",
        description=(
            "AI-powered penetration test report generation system. "
            "Correlates Burp Suite traffic with screen recordings and produces "
            "professional security reports using a multi-agent AI pipeline."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS — restrict to configured origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # Input validation / sanitization
    app.add_middleware(
        InputSanitizationMiddleware,
        max_upload_size=settings.max_upload_size,
    )

    # Ensure upload/output directories exist
    for directory in (settings.upload_dir, settings.output_dir, settings.frames_dir):
        Path(directory).mkdir(parents=True, exist_ok=True)

    # Register routes
    app.include_router(health_router)
    app.include_router(uploads_router)
    app.include_router(reports_router)

    logger.info("VIAR started on %s:%d", settings.host, settings.port)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "viar.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
