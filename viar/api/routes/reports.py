"""Report generation endpoints."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from viar.config import get_settings
from viar.core.burp_parser import BurpXmlParser, BurpJsonParser, NoiseFilter
from viar.core.security import PIIScrubber
from viar.core.synchronizer import BurpVideoSynchronizer, SyncConfig
from viar.core.video import FrameExtractor, TemporalAnalyzer
from viar.agents import ExploitationAgent, BusinessAgent, QAAgent, ViarAgentGraph
from viar.agents.graph import AgentState
from viar.reporting import ReportBuilder
from viar.reporting.exporters import MarkdownExporter, JsonExporter, PdfExporter

router = APIRouter(prefix="/report", tags=["Reports"])

# In-memory job status tracker (replace with Redis/DB in production)
_jobs: dict[str, dict] = {}


class GenerateReportRequest(BaseModel):
    session_id: str
    client_name: str = "Client"
    engagement_type: str = "Web Application Penetration Test"
    export_formats: list[str] = ["markdown", "json"]
    # Optional manual sync anchor (video_offset_ms for the first Burp request)
    video_offset_anchor_ms: Optional[float] = None


@router.post("/generate")
async def generate_report(
    request: GenerateReportRequest,
    background_tasks: BackgroundTasks,
) -> JSONResponse:
    """
    Trigger async report generation for a session.

    Returns a job_id for polling status via GET /report/status/{job_id}.
    """
    settings = get_settings()
    session_path = Path(settings.upload_dir) / request.session_id

    if not session_path.exists():
        raise HTTPException(status_code=404, detail="Session not found")

    # Locate uploaded files
    burp_file = next(session_path.glob("burp.*"), None)
    video_file = next(session_path.glob("recording.*"), None)

    if not burp_file:
        raise HTTPException(status_code=400, detail="No Burp file uploaded for this session")

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "queued", "session_id": request.session_id}

    background_tasks.add_task(
        _run_pipeline,
        job_id=job_id,
        burp_file=burp_file,
        video_file=video_file,
        session_path=session_path,
        request=request,
        settings=settings,
    )

    return JSONResponse(
        status_code=202,
        content={"job_id": job_id, "status": "queued"},
    )


@router.get("/status/{job_id}")
async def get_job_status(job_id: str) -> JSONResponse:
    """Poll report generation status."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JSONResponse(content=job)


@router.get("/download/{job_id}")
async def download_report(job_id: str, format: str = "markdown") -> FileResponse:
    """Download a completed report in the specified format."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] != "completed":
        raise HTTPException(status_code=400, detail=f"Report not ready. Status: {job['status']}")

    output_files: dict[str, str] = job.get("output_files", {})
    file_path = output_files.get(format)
    if not file_path or not Path(file_path).exists():
        raise HTTPException(status_code=404, detail=f"Format '{format}' not available")

    return FileResponse(path=file_path, filename=Path(file_path).name)


# ──────────────────────────────────────────────────────────────────────────────
# Background pipeline
# ──────────────────────────────────────────────────────────────────────────────


async def _run_pipeline(
    job_id: str,
    burp_file: Path,
    video_file: Optional[Path],
    session_path: Path,
    request: GenerateReportRequest,
    settings,
) -> None:
    """Full VIAR pipeline run as a background task."""
    try:
        _jobs[job_id]["status"] = "running"
        llm = settings.get_llm_client()
        scrubber = PIIScrubber()

        # Step 1: Parse Burp
        _jobs[job_id]["step"] = "parsing_burp"
        if burp_file.suffix == ".xml":
            burp_data = BurpXmlParser().parse_file(burp_file)
        else:
            burp_data = BurpJsonParser().parse_file(burp_file)
        burp_data = NoiseFilter().filter(burp_data)

        # Step 2: Video analysis (if available)
        _jobs[job_id]["step"] = "analysing_video"
        if video_file:
            extractor = FrameExtractor()
            video_analysis = extractor.extract(video_file)
            analyzer = TemporalAnalyzer(llm_client=llm)
            video_analysis = analyzer.analyse(video_analysis)
        else:
            from viar.models.video import VideoAnalysis
            video_analysis = VideoAnalysis(
                video_path="", video_duration_ms=0, fps=0, total_frames=0
            )

        # Step 3: Synchronise
        _jobs[job_id]["step"] = "synchronising"
        sync_config = SyncConfig()
        if request.video_offset_anchor_ms is not None and burp_data.http_items:
            from viar.core.synchronizer.burp_video_sync import TimelineAnchor
            sync_config.anchors = [
                TimelineAnchor(
                    burp_timestamp=burp_data.http_items[0].timestamp,
                    video_offset_ms=request.video_offset_anchor_ms,
                    confidence=1.0,
                    source="user-manual",
                )
            ]
        sync_result = BurpVideoSynchronizer(config=sync_config).synchronise(
            burp_data, video_analysis
        )

        # Step 4: Multi-agent pipeline
        _jobs[job_id]["step"] = "running_agents"
        exploitation = ExploitationAgent(llm)
        business = BusinessAgent(llm)
        qa = QAAgent(llm)
        report_builder = ReportBuilder(
            llm,
            client_name=request.client_name,
            engagement_type=request.engagement_type,
        )
        graph = ViarAgentGraph(exploitation, business, qa, report_builder)

        state = AgentState(
            burp_data=burp_data,
            video_analysis=video_analysis,
            sync_result=sync_result,
        )
        final_state = graph.run(state)

        if not final_state.report:
            raise RuntimeError("Agent pipeline did not produce a report")

        # Step 5: Export
        _jobs[job_id]["step"] = "exporting"
        output_dir = Path(settings.output_dir) / job_id
        output_dir.mkdir(parents=True, exist_ok=True)
        output_files: dict[str, str] = {}
        report = final_state.report

        if "markdown" in request.export_formats:
            path = MarkdownExporter().export(report, output_dir / "report.md")
            output_files["markdown"] = str(path)

        if "json" in request.export_formats:
            path = JsonExporter().export_native(report, output_dir / "report.json")
            output_files["json"] = str(path)
            dojo_path = JsonExporter().export_defectdojo(report, output_dir / "defectdojo.json")
            output_files["defectdojo"] = str(dojo_path)

        if "pdf" in request.export_formats:
            path = PdfExporter().export(report, output_dir / "report.pdf")
            output_files["pdf"] = str(path)

        _jobs[job_id].update(
            {
                "status": "completed",
                "step": "done",
                "output_files": output_files,
                "findings_count": len(report.findings),
                "attack_chains_count": len(report.attack_chains),
                "overall_risk": report.overall_risk_rating.value if report.overall_risk_rating else None,
            }
        )

    except Exception as exc:
        import traceback
        _jobs[job_id].update(
            {
                "status": "failed",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        )
