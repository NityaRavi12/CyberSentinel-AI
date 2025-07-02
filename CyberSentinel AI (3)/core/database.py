"""
Database layer for CyberSentinel AI - ATITA
"""

import asyncio
from typing import List, Optional, Dict, Any, Sequence
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Float, Text, JSON, Integer
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.future import select
from core.config import settings
from core.models import ThreatData, ThreatCase, ThreatStatus, ThreatType, ThreatSeverity, SourceType

Base = declarative_base()


class ThreatModel(Base):
    """SQLAlchemy model for threats"""
    __tablename__ = "threats"
    
    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    threat_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    source = Column(String, nullable=False)
    source_details = Column(JSON, default={})
    confidence = Column(Float, default=0.5)
    status = Column(String, default="received")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    threat_metadata = Column(JSON, default={})


class CaseModel(Base):
    """SQLAlchemy model for threat cases"""
    __tablename__ = "cases"
    
    id = Column(String, primary_key=True)
    threat_id = Column(String, nullable=False)
    enrichment_data = Column(JSON, default={})
    policy_decisions = Column(JSON, default=[])
    escalation_data = Column(JSON, default={})
    feedback_data = Column(JSON, default=[])
    auto_actions = Column(JSON, default=[])
    processing_time = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    threat_metadata = Column(JSON, default={})


class DatabaseManager:
    """Database manager for handling database operations"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self.async_engine = None
        self.AsyncSessionLocal = None
    
    async def initialize(self):
        """Initialize database connections"""
        try:
            self.async_engine = create_async_engine(
                settings.database_url.replace("postgresql://", "postgresql+asyncpg://"),
                echo=settings.debug
            )
            self.AsyncSessionLocal = async_sessionmaker(
                self.async_engine, expire_on_commit=False
            )
            self.engine = create_engine(settings.database_url, echo=settings.debug)
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            async with self.async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        except Exception as e:
            print(f"Database initialization failed: {e}")
            self.async_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=settings.debug)
            self.AsyncSessionLocal = async_sessionmaker(
                self.async_engine, expire_on_commit=False
            )
            self.engine = create_engine("sqlite:///:memory:", echo=settings.debug)
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            async with self.async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
    
    async def close(self):
        """Close database connections"""
        if self.async_engine:
            await self.async_engine.dispose()
        if self.engine:
            self.engine.dispose()
    
    async def _ensure_initialized(self):
        """Ensure database is initialized"""
        if self.async_engine is None or self.AsyncSessionLocal is None:
            await self.initialize()
        if self.AsyncSessionLocal is None:
            raise RuntimeError("AsyncSessionLocal is not initialized")

    async def create_threat(self, threat_data: ThreatData) -> ThreatData:
        """Create a new threat in the database"""
        await self._ensure_initialized()
        assert self.AsyncSessionLocal is not None  # Type assertion for linter
        async with self.AsyncSessionLocal() as session:
            threat_model = ThreatModel(
                id=threat_data.id,
                title=threat_data.title,
                description=threat_data.description,
                threat_type=threat_data.threat_type.value,
                severity=threat_data.severity.value,
                source=threat_data.source.value,
                source_details=threat_data.source_details,
                confidence=threat_data.confidence,
                status=threat_data.status.value,
                threat_metadata=threat_data.threat_metadata
            )
            session.add(threat_model)
            await session.commit()
            return threat_data
    
    async def get_threat(self, threat_id: str) -> Optional[ThreatData]:
        """Get a threat by ID"""
        await self._ensure_initialized()
        assert self.AsyncSessionLocal is not None  # Type assertion for linter
        async with self.AsyncSessionLocal() as session:
            result = await session.execute(
                select(ThreatModel).where(ThreatModel.id == threat_id)
            )
            threat_model: Optional[ThreatModel] = result.scalar_one_or_none()
            
            if threat_model:
                return ThreatData(
                    id=threat_model.id,  # type: ignore
                    title=threat_model.title,  # type: ignore
                    description=threat_model.description,  # type: ignore
                    threat_type=ThreatType(threat_model.threat_type),
                    severity=ThreatSeverity(threat_model.severity),
                    source=SourceType(threat_model.source),
                    source_details=threat_model.source_details,  # type: ignore
                    confidence=threat_model.confidence,  # type: ignore
                    status=ThreatStatus(threat_model.status),
                    created_at=threat_model.created_at,  # type: ignore
                    updated_at=threat_model.updated_at,  # type: ignore
                    metadata=threat_model.threat_metadata  # type: ignore
                )
            return None
    
    async def update_threat(self, threat_id: str, updates: Dict[str, Any]) -> Optional[ThreatData]:
        """Update a threat"""
        await self._ensure_initialized()
        assert self.AsyncSessionLocal is not None  # Type assertion for linter
        async with self.AsyncSessionLocal() as session:
            result = await session.execute(
                select(ThreatModel).where(ThreatModel.id == threat_id)
            )
            threat_model: Optional[ThreatModel] = result.scalar_one_or_none()
            
            if threat_model:
                for key, value in updates.items():
                    if hasattr(threat_model, key):
                        setattr(threat_model, key, value)
                threat_model.updated_at = datetime.utcnow()  # type: ignore
                await session.commit()
                
                return await self.get_threat(threat_id)
            return None
    
    async def list_threats(self, limit: int = 100, offset: int = 0) -> List[ThreatData]:
        """List threats with pagination"""
        await self._ensure_initialized()
        assert self.AsyncSessionLocal is not None  # Type assertion for linter
        async with self.AsyncSessionLocal() as session:
            result = await session.execute(
                select(ThreatModel).limit(limit).offset(offset)
            )
            threat_models: Sequence[ThreatModel] = result.scalars().all()
            
            return [
                ThreatData(
                    id=threat.id,  # type: ignore
                    title=threat.title,  # type: ignore
                    description=threat.description,  # type: ignore
                    threat_type=ThreatType(threat.threat_type),
                    severity=ThreatSeverity(threat.severity),
                    source=SourceType(threat.source),
                    source_details=threat.source_details,  # type: ignore
                    confidence=threat.confidence,  # type: ignore
                    status=ThreatStatus(threat.status),
                    created_at=threat.created_at,  # type: ignore
                    updated_at=threat.updated_at,  # type: ignore
                    metadata=threat.threat_metadata  # type: ignore
                )
                for threat in threat_models
            ]
    
    async def create_case(self, case: ThreatCase) -> ThreatCase:
        """Create a new case in the database"""
        await self._ensure_initialized()
        assert self.AsyncSessionLocal is not None  # Type assertion for linter
        async with self.AsyncSessionLocal() as session:
            case_model = CaseModel(
                id=case.id,
                threat_id=case.threat_id,
                enrichment_data=case.enrichment_data,
                policy_decisions=case.policy_decisions,
                escalation_data=case.escalation_data,
                feedback_data=case.feedback_data,
                auto_actions=case.auto_actions,
                processing_time=case.processing_time,
                threat_metadata=case.threat_metadata
            )
            session.add(case_model)
            await session.commit()
            return case
    
    async def get_case(self, case_id: str) -> Optional[ThreatCase]:
        """Get a case by ID"""
        await self._ensure_initialized()
        assert self.AsyncSessionLocal is not None  # Type assertion for linter
        async with self.AsyncSessionLocal() as session:
            result = await session.execute(
                select(CaseModel).where(CaseModel.id == case_id)
            )
            case_model: Optional[CaseModel] = result.scalar_one_or_none()
            
            if case_model:
                threat = await self.get_threat(str(case_model.threat_id))
                if threat:
                    return ThreatCase(
                        threat=threat,
                        enrichment=case_model.enrichment_data if case_model.enrichment_data else None,  # type: ignore
                        policy_decisions=case_model.policy_decisions,  # type: ignore
                        escalation=case_model.escalation_data if case_model.escalation_data else None,  # type: ignore
                        feedback=case_model.feedback_data,  # type: ignore
                        auto_actions_taken=case_model.auto_actions,  # type: ignore
                        processing_time=case_model.processing_time,  # type: ignore
                        threat_metadata=case_model.threat_metadata  # type: ignore
                    )
            return None

    def is_connected(self) -> bool:
        """Check if database is connected"""
        return self.async_engine is not None and self.AsyncSessionLocal is not None

    async def count_threats(self) -> int:
        """Count total number of threats"""
        await self._ensure_initialized()
        assert self.AsyncSessionLocal is not None
        async with self.AsyncSessionLocal() as session:
            result = await session.execute(select(ThreatModel))
            return len(result.scalars().all())

    async def count_pending_threats(self) -> int:
        """Count pending threats"""
        await self._ensure_initialized()
        assert self.AsyncSessionLocal is not None
        async with self.AsyncSessionLocal() as session:
            result = await session.execute(
                select(ThreatModel).where(ThreatModel.status == "received")
            )
            return len(result.scalars().all())


# Global database manager instance
db_manager = DatabaseManager() 