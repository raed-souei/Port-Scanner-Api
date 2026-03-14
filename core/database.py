"""
Database models and connection management for the port scanner.
Uses SQLAlchemy with async SQLite support.
"""

import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import (
    create_engine, Column, String, Integer, Boolean, 
    DateTime, Float, ForeignKey, Text, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

# Use async SQLite for production, sync for simplicity in some cases
DATABASE_URL = "sqlite+aiosqlite:///./portscanner.db"
SYNC_DATABASE_URL = "sqlite:///./portscanner.db"

Base = declarative_base()


class ScanJob(Base):
    """Represents a scan job/session."""
    __tablename__ = "scan_jobs"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    status = Column(String, default="pending")  # pending, running, completed, failed, cancelled
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Scan configuration
    targets = Column(JSON)  # List of target IPs/hostnames
    port_preset = Column(String, default="common")
    custom_ports = Column(JSON, nullable=True)  # List of integers if not using preset
    timeout = Column(Float, default=2.0)
    max_concurrent = Column(Integer, default=100)
    rate_limit = Column(Integer, nullable=True)
    
    # Results summary
    total_hosts = Column(Integer, default=0)
    total_ports = Column(Integer, default=0)
    open_ports_found = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    
    # Relationships
    results = relationship("ScanResult", back_populates="scan_job", cascade="all, delete-orphan")


class ScanResult(Base):
    """Individual port scan result."""
    __tablename__ = "scan_results"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False)
    
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    is_open = Column(Boolean, default=False)
    service_name = Column(String, nullable=True)
    banner = Column(Text, nullable=True)
    response_time_ms = Column(Float, nullable=True)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    error = Column(String, nullable=True)
    
    # Relationship
    scan_job = relationship("ScanJob", back_populates="results")


# Async engine and session
async_engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)

# Sync engine for migrations/initialization
sync_engine = create_engine(SYNC_DATABASE_URL)
SyncSessionLocal = sessionmaker(bind=sync_engine)


async def init_db():
    """Initialize the database tables."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def init_db_sync():
    """Initialize database synchronously (for setup scripts)."""
    Base.metadata.create_all(bind=sync_engine)


async def get_db():
    """Dependency for getting database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


class ScanRepository:
    """Repository pattern for scan operations."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create_scan_job(
        self,
        targets: List[str],
        port_preset: str = "common",
        custom_ports: Optional[List[int]] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timeout: float = 2.0,
        max_concurrent: int = 100,
        rate_limit: Optional[int] = None
    ) -> ScanJob:
        """Create a new scan job."""
        ports = custom_ports if custom_ports else []
        total_ports = len(ports) if ports else len(PortScanner.get_preset_ports(port_preset))
        
        scan_job = ScanJob(
            name=name,
            description=description,
            targets=targets,
            port_preset=port_preset,
            custom_ports=custom_ports,
            timeout=timeout,
            max_concurrent=max_concurrent,
            rate_limit=rate_limit,
            total_hosts=len(targets),
            total_ports=total_ports * len(targets),
            status="pending"
        )
        
        self.session.add(scan_job)
        await self.session.commit()
        await self.session.refresh(scan_job)
        return scan_job
    
    async def get_scan_job(self, scan_id: str) -> Optional[ScanJob]:
        """Get a scan job by ID."""
        from sqlalchemy import select
        result = await self.session.execute(
            select(ScanJob).where(ScanJob.id == scan_id)
        )
        return result.scalar_one_or_none()
    
    async def get_scan_jobs(self, limit: int = 50, offset: int = 0) -> List[ScanJob]:
        """Get list of scan jobs ordered by creation date."""
        from sqlalchemy import select
        result = await self.session.execute(
            select(ScanJob)
            .order_by(ScanJob.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return result.scalars().all()
    
    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        error_message: Optional[str] = None
    ):
        """Update scan job status."""
        scan_job = await self.get_scan_job(scan_id)
        if scan_job:
            scan_job.status = status
            if status == "running" and not scan_job.started_at:
                scan_job.started_at = datetime.utcnow()
            if status in ("completed", "failed", "cancelled"):
                scan_job.completed_at = datetime.utcnow()
            if error_message:
                scan_job.error_message = error_message
            await self.session.commit()
    
    async def add_scan_results(self, scan_id: str, results: List[Dict[str, Any]]):
        """Add scan results to a job."""
        scan_job = await self.get_scan_job(scan_id)
        if not scan_job:
            return
        
        open_count = 0
        for result_data in results:
            result = ScanResult(
                scan_job_id=scan_id,
                host=result_data["host"],
                port=result_data["port"],
                is_open=result_data["is_open"],
                service_name=result_data.get("service_name"),
                banner=result_data.get("banner"),
                response_time_ms=result_data.get("response_time_ms"),
                error=result_data.get("error")
            )
            self.session.add(result)
            if result_data["is_open"]:
                open_count += 1
        
        scan_job.open_ports_found = open_count
        await self.session.commit()
    
    async def get_scan_results(
        self,
        scan_id: str,
        only_open: bool = False
    ) -> List[ScanResult]:
        """Get results for a scan job."""
        from sqlalchemy import select
        query = select(ScanResult).where(ScanResult.scan_job_id == scan_id)
        if only_open:
            query = query.where(ScanResult.is_open == True)
        result = await self.session.execute(query)
        return result.scalars().all()
    
    async def delete_scan_job(self, scan_id: str) -> bool:
        """Delete a scan job and its results."""
        scan_job = await self.get_scan_job(scan_id)
        if scan_job:
            await self.session.delete(scan_job)
            await self.session.commit()
            return True
        return False


# Import here to avoid circular dependency
from core.scanner import PortScanner
