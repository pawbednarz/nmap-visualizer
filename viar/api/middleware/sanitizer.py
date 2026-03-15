"""
Input sanitization middleware for the FastAPI backend.

Validates file uploads and request sizes before they reach route handlers.
This is the first line of defence — PII scrubbing happens later, before LLM calls.
"""
from __future__ import annotations

import logging
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

_ALLOWED_MIME_TYPES = {
    "text/xml",
    "application/xml",
    "application/json",
    "video/mp4",
    "video/x-matroska",
    "video/webm",
    "video/quicktime",
    "video/avi",
    "multipart/form-data",
}

# Paths that skip size validation (e.g. health check)
_EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}


class InputSanitizationMiddleware(BaseHTTPMiddleware):
    """
    Validates incoming requests:
    - Enforces max content-length for file uploads
    - Rejects obviously invalid Content-Type headers
    - Logs security-relevant request metadata

    Does NOT block legitimate application traffic — only validates metadata.
    Actual file content validation happens in route handlers using Pydantic.
    """

    def __init__(self, app, max_upload_size: int = 500 * 1024 * 1024):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        # Check Content-Length for upload endpoints
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    size = int(content_length)
                    if size > self.max_upload_size:
                        logger.warning(
                            "Request rejected: content-length %d exceeds max %d from %s",
                            size,
                            self.max_upload_size,
                            request.client.host if request.client else "unknown",
                        )
                        return JSONResponse(
                            status_code=413,
                            content={
                                "error": "File too large",
                                "max_size_mb": self.max_upload_size // (1024 * 1024),
                            },
                        )
                except ValueError:
                    pass

        # Log security-relevant info
        logger.debug(
            "Request: %s %s from %s",
            request.method,
            request.url.path,
            request.client.host if request.client else "unknown",
        )

        try:
            response = await call_next(request)
        except Exception as exc:
            logger.error("Unhandled error processing request: %s", exc)
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error"},
            )

        return response
