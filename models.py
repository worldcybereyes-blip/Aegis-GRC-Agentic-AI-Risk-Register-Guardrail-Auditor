"""Pydantic data models for Aegis-GRC risk registers, mappings, and audit reports."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class AutonomyLevel(str, Enum):
    LEVEL_1 = "Level 1: Human-Assisted"
    LEVEL_2 = "Level 2: Semi-Autonomous / HITL-Gated"
    LEVEL_3 = "Level 3: Fully Autonomous Agent"


class RiskTier(str, Enum):
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    CRITICAL = "Critical"


class AISystemInput(BaseModel):
    system_name: str = Field(..., description="Name of the AI or agentic system.")
    purpose: str = Field(..., description="Operational purpose and business/security scope.")
    model_provider: str = Field(default="Frontier LLM API", description="Foundation model or inference provider.")
    has_pii_or_sensitive_data: bool = Field(default=False, description="Whether system ingests PII, credentials, or regulated data.")
    has_write_or_exec_permissions: bool = Field(default=False, description="Whether agents can execute tools, APIs, or state-changing actions.")
    blast_radius: str = Field(default="Departmental", description="Potential operational blast radius (Local, Departmental, Enterprise).")
    human_in_the_loop: bool = Field(default=False, description="Whether high-impact actions require explicit human approval.")
    existing_guardrails: List[str] = Field(default_factory=list, description="List of implemented technical guardrails and controls.")
    telemetry_sources: List[str] = Field(default_factory=list, description="Available logging and monitoring sources.")


class RiskRegisterEntry(BaseModel):
    risk_id: str
    threat_failure_mode: str
    owasp_atlas_ref: str
    technical_impact: str
    inherent_risk: RiskTier
    mapped_technical_control: str
    residual_risk: RiskTier


class FrameworkMapping(BaseModel):
    technical_guardrail: str
    iso_42001_ref: str
    nist_ai_rmf_ref: str
    audit_verification_artifact: str
    status: str = "Implemented"


class GapAnalysis(BaseModel):
    control_strengths: List[str]
    identified_gaps: List[str]
    actionable_fixes: List[str]
    telemetry_assumptions: List[str]


class AuditReport(BaseModel):
    system_name: str
    purpose: str
    autonomy_level: AutonomyLevel
    inherent_risk_tier: RiskTier
    risk_justification: str
    risk_register: List[RiskRegisterEntry]
    framework_mappings: List[FrameworkMapping]
    gap_analysis: GapAnalysis
