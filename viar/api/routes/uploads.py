"""File upload endpoints for Burp and video files."""
from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from viar.config import get_settings
from viar.core.burp_parser import BurpXmlParser, BurpJsonParser, NoiseFilter
from viar.core.security import PIIScrubber

router = APIRouter(prefix="/upload", tags=["Uploads"])

_ALLOWED_BURP_EXTENSIONS = {".xml", ".json"}
_ALLOWED_VIDEO_EXTENSIONS = {".mp4", ".mkv", ".webm", ".mov", ".avi"}


@router.post("/burp")
async def upload_burp_file(file: UploadFile = File(...)) -> JSONResponse:
    """
    Upload a Burp Suite export file (XML or JSON).

    Returns a session_id to reference this upload in subsequent API calls.
    """
    settings = get_settings()
    ext = Path(file.filename or "").suffix.lower()
    if ext not in _ALLOWED_BURP_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{ext}'. Allowed: {_ALLOWED_BURP_EXTENSIONS}",
        )

    session_id = str(uuid.uuid4())
    upload_path = Path(settings.upload_dir) / session_id
    upload_path.mkdir(parents=True, exist_ok=True)
    dest = upload_path / f"burp{ext}"

    try:
        with dest.open("wb") as f:
            shutil.copyfileobj(file.file, f)
    finally:
        file.file.close()

    # Parse and validate
    try:
        if ext == ".xml":
            scan_data = BurpXmlParser().parse_file(dest)
        else:
            scan_data = BurpJsonParser().parse_file(dest)
    except ValueError as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail=f"Parse error: {exc}") from exc

    # Apply noise filter
    filtered = NoiseFilter().filter(scan_data)

    return JSONResponse(
        status_code=200,
        content={
            "session_id": session_id,
            "source_format": scan_data.source_format,
            "http_items": len(filtered.http_items),
            "issues": len(filtered.issues),
            "unique_hosts": filtered.unique_hosts,
            "tech_fingerprints": filtered.tech_fingerprints,
            "time_range_start": scan_data.time_range_start.isoformat() if scan_data.time_range_start else None,
            "time_range_end": scan_data.time_range_end.isoformat() if scan_data.time_range_end else None,
        },
    )


@router.post("/video")
async def upload_video_file(
    session_id: str,
    file: UploadFile = File(...),
) -> JSONResponse:
    """
    Upload a screen recording video for a given session.

    The video will be associated with the previously uploaded Burp file.
    """
    settings = get_settings()
    ext = Path(file.filename or "").suffix.lower()
    if ext not in _ALLOWED_VIDEO_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid video type '{ext}'. Allowed: {_ALLOWED_VIDEO_EXTENSIONS}",
        )

    upload_path = Path(settings.upload_dir) / session_id
    if not upload_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Session '{session_id}' not found. Upload Burp file first.",
        )

    dest = upload_path / f"recording{ext}"
    try:
        with dest.open("wb") as f:
            shutil.copyfileobj(file.file, f)
    finally:
        file.file.close()

    file_size_mb = dest.stat().st_size / (1024 * 1024)

    return JSONResponse(
        status_code=200,
        content={
            "session_id": session_id,
            "video_path": str(dest),
            "size_mb": round(file_size_mb, 2),
            "status": "uploaded",
        },
    )
