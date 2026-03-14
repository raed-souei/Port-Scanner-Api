"""
FastAPI application for the Port Scanner.
Provides REST API endpoints for scan management and WebSocket for real-time updates.
"""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from sqlalchemy.ext.asyncio import AsyncSession

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import core components
import sys
sys.path.insert(0, '/mnt/okcomputer/output/portscanner/backend')

from core.database import (
    init_db, get_db, ScanRepository, 
    ScanJob, async_engine
)
from core.scanner import PortScanner, ScanStatus


# ============== Pydantic Models ==============

class ScanTargetRequest(BaseModel):
    """Request model for creating a scan."""
    targets: List[str] = Field(..., description="List of IP addresses or hostnames to scan")
    port_preset: str = Field(default="common", description="Port preset: quick, common, extended, full, web, database, mail")
    custom_ports: Optional[List[int]] = Field(None, description="Custom port list if not using preset")
    name: Optional[str] = Field(None, description="Optional scan name")
    description: Optional[str] = Field(None, description="Optional scan description")
    timeout: float = Field(default=2.0, ge=0.5, le=30.0, description="Connection timeout in seconds")
    max_concurrent: int = Field(default=100, ge=1, le=500, description="Maximum concurrent connections")
    rate_limit: Optional[int] = Field(None, ge=1, le=10000, description="Rate limit (connections per second)")
    
    @validator('targets')
    def validate_targets(cls, v):
        if not v:
            raise ValueError('At least one target is required')
        if len(v) > 100:
            raise ValueError('Maximum 100 targets allowed per scan')
        return v
    
    @validator('port_preset')
    def validate_preset(cls, v):
        valid_presets = PortScanner.get_available_presets()
        if v not in valid_presets:
            raise ValueError(f'Invalid preset. Must be one of: {valid_presets}')
        return v


class ScanResponse(BaseModel):
    """Response model for scan job."""
    id: str
    name: Optional[str]
    description: Optional[str]
    status: str
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    targets: List[str]
    port_preset: str
    total_hosts: int
    total_ports: int
    open_ports_found: int
    error_message: Optional[str]


class ScanResultResponse(BaseModel):
    """Response model for individual scan result."""
    id: str
    host: str
    port: int
    is_open: bool
    service_name: Optional[str]
    banner: Optional[str]
    response_time_ms: Optional[float]
    scanned_at: datetime
    error: Optional[str]


class ScanProgressResponse(BaseModel):
    """Response model for scan progress."""
    scan_id: str
    status: str
    total_hosts: int
    completed_hosts: int
    total_ports: int
    completed_ports: int
    open_ports_found: int
    current_target: Optional[str]
    message: Optional[str]
    progress_percent: float


class TargetValidationRequest(BaseModel):
    """Request to validate targets."""
    targets: List[str]


class TargetValidationResponse(BaseModel):
    """Response for target validation."""
    valid: List[str]
    invalid: List[Dict[str, str]]
    resolved: Dict[str, str]


# ============== Global State ==============

# Store active scan tasks and their cancellation tokens
active_scans: Dict[str, dict] = {}


# ============== Lifespan ==============

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Starting up Port Scanner API...")
    await init_db()
    logger.info("Database initialized")
    yield
    logger.info("Shutting down Port Scanner API...")
    # Cancel any active scans
    for scan_id, scan_info in active_scans.items():
        if scan_info.get("scanner"):
            scan_info["scanner"].cancel()


# ============== FastAPI App ==============

app = FastAPI(
    title="Port Scanner API",
    description="Production-grade port scanning API with real-time updates",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============== Helper Functions ==============

def scan_job_to_dict(scan_job: ScanJob) -> dict:
    """Convert ScanJob to dictionary."""
    return {
        "id": scan_job.id,
        "name": scan_job.name,
        "description": scan_job.description,
        "status": scan_job.status,
        "created_at": scan_job.created_at.isoformat() if scan_job.created_at else None,
        "started_at": scan_job.started_at.isoformat() if scan_job.started_at else None,
        "completed_at": scan_job.completed_at.isoformat() if scan_job.completed_at else None,
        "targets": scan_job.targets,
        "port_preset": scan_job.port_preset,
        "total_hosts": scan_job.total_hosts,
        "total_ports": scan_job.total_ports,
        "open_ports_found": scan_job.open_ports_found,
        "error_message": scan_job.error_message
    }


def scan_result_to_dict(result) -> dict:
    """Convert ScanResult to dictionary."""
    return {
        "id": result.id,
        "host": result.host,
        "port": result.port,
        "is_open": result.is_open,
        "service_name": result.service_name,
        "banner": result.banner,
        "response_time_ms": result.response_time_ms,
        "scanned_at": result.scanned_at.isoformat() if result.scanned_at else None,
        "error": result.error
    }


# ============== API Endpoints ==============

@app.get("/")
async def root():
    """API information endpoint."""
    return {
        "name": "Port Scanner API",
        "version": "1.0.0",
        "endpoints": {
            "scans": "/api/scans",
            "scan_detail": "/api/scans/{scan_id}",
            "scan_results": "/api/scans/{scan_id}/results",
            "validate_targets": "/api/validate",
            "presets": "/api/presets",
            "websocket": "/ws/{scan_id}"
        }
    }


@app.get("/api/presets")
async def get_presets():
    """Get available port presets."""
    presets = PortScanner.get_available_presets()
    preset_details = {}
    for preset in presets:
        ports = PortScanner.get_preset_ports(preset)
        preset_details[preset] = {
            "name": preset,
            "port_count": len(ports),
            "sample_ports": ports[:10] if len(ports) > 10 else ports
        }
    return {"presets": preset_details}


@app.post("/api/validate", response_model=TargetValidationResponse)
async def validate_targets(request: TargetValidationRequest):
    """Validate target hostnames/IPs without scanning."""
    valid = []
    invalid = []
    resolved = {}
    
    scanner = PortScanner(timeout=1.0)
    
    for target in request.targets:
        try:
            # Basic format validation
            import re
            if not re.match(r'^[a-zA-Z0-9.\-:]+$', target):
                invalid.append({"target": target, "error": "Invalid characters"})
                continue
            
            # Try to resolve
            try:
                import ipaddress
                ipaddress.ip_address(target)
                resolved[target] = target
            except ValueError:
                # It's a hostname, try resolution
                import socket
                try:
                    ip = socket.gethostbyname(target)
                    resolved[target] = ip
                except socket.gaierror as e:
                    invalid.append({"target": target, "error": f"Could not resolve: {str(e)}"})
                    continue
            
            valid.append(target)
            
        except Exception as e:
            invalid.append({"target": target, "error": str(e)})
    
    return TargetValidationResponse(valid=valid, invalid=invalid, resolved=resolved)


@app.get("/api/scans")
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    session: AsyncSession = Depends(get_db)
):
    """List all scan jobs."""
    repo = ScanRepository(session)
    scans = await repo.get_scan_jobs(limit=limit, offset=offset)
    return {"scans": [scan_job_to_dict(scan) for scan in scans], "total": len(scans)}


@app.post("/api/scans", response_model=ScanResponse, status_code=201)
async def create_scan(
    request: ScanTargetRequest,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db)
):
    """Create and start a new scan job."""
    repo = ScanRepository(session)
    
    # Determine ports to scan
    if request.custom_ports:
        ports = request.custom_ports
    else:
        ports = PortScanner.get_preset_ports(request.port_preset)
    
    # Create scan job in database
    scan_job = await repo.create_scan_job(
        targets=request.targets,
        port_preset=request.port_preset,
        custom_ports=request.custom_ports,
        name=request.name,
        description=request.description,
        timeout=request.timeout,
        max_concurrent=request.max_concurrent,
        rate_limit=request.rate_limit
    )
    
    # Start scan in background
    background_tasks.add_task(
        run_scan_task,
        scan_job.id,
        request.targets,
        ports,
        request.timeout,
        request.max_concurrent,
        request.rate_limit
    )
    
    return ScanResponse(**scan_job_to_dict(scan_job))


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_db)):
    """Get scan job details."""
    repo = ScanRepository(session)
    scan_job = await repo.get_scan_job(scan_id)
    
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_job_to_dict(scan_job)


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str, session: AsyncSession = Depends(get_db)):
    """Delete a scan job and its results."""
    # Cancel if running
    if scan_id in active_scans:
        scanner = active_scans[scan_id].get("scanner")
        if scanner:
            scanner.cancel()
        del active_scans[scan_id]
    
    repo = ScanRepository(session)
    success = await repo.delete_scan_job(scan_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {"message": "Scan deleted successfully"}


@app.get("/api/scans/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    only_open: bool = False,
    host: Optional[str] = None,
    session: AsyncSession = Depends(get_db)
):
    """Get scan results."""
    repo = ScanRepository(session)
    
    scan_job = await repo.get_scan_job(scan_id)
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    results = await repo.get_scan_results(scan_id, only_open=only_open)
    
    # Filter by host if specified
    if host:
        results = [r for r in results if r.host == host]
    
    return {
        "scan_id": scan_id,
        "total_results": len(results),
        "open_ports": len([r for r in results if r.is_open]),
        "results": [scan_result_to_dict(r) for r in results]
    }


@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, session: AsyncSession = Depends(get_db)):
    """Cancel a running scan."""
    if scan_id not in active_scans:
        raise HTTPException(status_code=400, detail="Scan is not running")
    
    scanner = active_scans[scan_id].get("scanner")
    if scanner:
        scanner.cancel()
    
    repo = ScanRepository(session)
    await repo.update_scan_status(scan_id, "cancelled")
    
    return {"message": "Scan cancellation requested"}


# ============== WebSocket ==============

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan updates."""
    await websocket.accept()
    
    try:
        # Check if scan exists
        from sqlalchemy.ext.asyncio import AsyncSession
        async with AsyncSession(async_engine) as session:
            repo = ScanRepository(session)
            scan_job = await repo.get_scan_job(scan_id)
            
            if not scan_job:
                await websocket.send_json({"error": "Scan not found"})
                await websocket.close()
                return
        
        # Send initial status
        await websocket.send_json({
            "type": "status",
            "data": scan_job_to_dict(scan_job)
        })
        
        # Subscribe to scan updates
        if scan_id not in active_scans:
            active_scans[scan_id] = {"subscribers": []}
        
        active_scans[scan_id]["subscribers"] = active_scans[scan_id].get("subscribers", []) + [websocket]
        
        # Keep connection alive and listen for client messages
        while True:
            try:
                message = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                data = json.loads(message)
                
                if data.get("action") == "ping":
                    await websocket.send_json({"type": "pong"})
                    
            except asyncio.TimeoutError:
                # Send keepalive
                await websocket.send_json({"type": "keepalive"})
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
    finally:
        # Remove from subscribers
        if scan_id in active_scans and websocket in active_scans[scan_id].get("subscribers", []):
            active_scans[scan_id]["subscribers"].remove(websocket)


# ============== Background Scan Task ==============

async def run_scan_task(
    scan_id: str,
    targets: List[str],
    ports: List[int],
    timeout: float,
    max_concurrent: int,
    rate_limit: Optional[int]
):
    """Background task to run the scan."""
    from sqlalchemy.ext.asyncio import AsyncSession
    
    async with AsyncSession(async_engine) as session:
        repo = ScanRepository(session)
        
        try:
            # Update status to running
            await repo.update_scan_status(scan_id, "running")
            
            # Create scanner
            scanner = PortScanner(
                timeout=timeout,
                max_concurrent=max_concurrent,
                rate_limit=rate_limit
            )
            
            # Store in active scans
            active_scans[scan_id] = {
                "scanner": scanner,
                "subscribers": active_scans.get(scan_id, {}).get("subscribers", [])
            }
            
            # Progress callback
            async def progress_callback(data: dict):
                # Update subscribers
                subscribers = active_scans.get(scan_id, {}).get("subscribers", [])
                message = {
                    "type": "progress",
                    "data": data
                }
                
                # Send to all connected WebSocket clients
                for ws in subscribers[:]:
                    try:
                        await ws.send_json(message)
                    except Exception:
                        # Remove dead connections
                        subscribers.remove(ws)
            
            # Run the scan
            results = await scanner.scan_targets(
                targets=targets,
                ports=ports,
                scan_id=scan_id,
                progress_callback=progress_callback
            )
            
            # Flatten results and save to database
            all_results = []
            for host, host_results in results.items():
                for result in host_results:
                    all_results.append(result.to_dict())
            
            await repo.add_scan_results(scan_id, all_results)
            
            # Update status
            if scanner._cancelled:
                await repo.update_scan_status(scan_id, "cancelled")
            else:
                await repo.update_scan_status(scan_id, "completed")
            
            # Notify subscribers of completion
            subscribers = active_scans.get(scan_id, {}).get("subscribers", [])
            for ws in subscribers[:]:
                try:
                    await ws.send_json({
                        "type": "completed",
                        "data": {"open_ports": len([r for r in all_results if r["is_open"]])}
                    })
                except Exception:
                    pass
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            await repo.update_scan_status(scan_id, "failed", error_message=str(e))
            
            # Notify subscribers of failure
            subscribers = active_scans.get(scan_id, {}).get("subscribers", [])
            for ws in subscribers[:]:
                try:
                    await ws.send_json({
                        "type": "error",
                        "data": {"error": str(e)}
                    })
                except Exception:
                    pass
        finally:
            # Clean up
            if scan_id in active_scans:
                del active_scans[scan_id]


# ============== Main Entry Point ==============

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
