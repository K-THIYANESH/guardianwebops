"""
Guardian WebOps Evidence & Research Models
=========================================
Structured data structures for public-web research results, source evidence,
and governance policy outcomes.
"""
from __future__ import annotations

import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class EvidenceStatus(str, Enum):
    FOUND = "FOUND"
    MISSING = "MISSING"
    CONFLICTING = "CONFLICTING"
    UNVERIFIED = "UNVERIFIED"
    FAILED_TO_RETRIEVE = "FAILED_TO_RETRIEVE"


class ResearchTaskStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class ResearchClaim(BaseModel):
    category: str  # e.g., "SOC 2 & Compliance", "Data Encryption & Residency", "Access Controls & SSO"
    claim: str
    status: EvidenceStatus = EvidenceStatus.UNVERIFIED
    source_url: Optional[str] = None
    source_excerpt: Optional[str] = None
    missing_explanation: Optional[str] = None
    retrieval_timestamp: Optional[str] = None
    confidence: float = 1.0


class VendorResearchResult(BaseModel):
    vendor_name: str
    target_domain: str
    claims: List[ResearchClaim] = Field(default_factory=list)
    retrieval_status: str = "COMPLETED"  # "COMPLETED", "PARTIAL", "FAILED"
    error_message: Optional[str] = None


class GateDecision(BaseModel):
    gate_name: str
    passed: bool
    status_code: Optional[str] = None
    details: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class ResearchTask(BaseModel):
    task_id: str
    objective: str
    scope: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    vendors: List[str] = Field(default_factory=list)
    status: ResearchTaskStatus = ResearchTaskStatus.PENDING
    is_mock: bool = True
    provider: str = "tinyfish"
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    completed_at: Optional[str] = None
    user_id: str = "researcher_user"
    user_role: str = "RESEARCHER"
    gate_decisions: List[GateDecision] = Field(default_factory=list)
    results: List[VendorResearchResult] = Field(default_factory=list)
    audit_block_hash: Optional[str] = None
    audit_block_index: Optional[int] = None
    error_summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
