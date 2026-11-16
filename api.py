"""FastAPI service exposing Aegis-GRC Risk Register & Guardrail Gap Audit endpoints."""

from fastapi import FastAPI
from .auditor import AegisGRCAuditor
from .frameworks import ISO_42001_CONTROLS, MITRE_ATLAS_REFS, NIST_AI_RMF_SUBCATEGORIES, OWASP_LLM_TOP_10_2025
from .models import AISystemInput, AuditReport

app = FastAPI(
    title="Aegis-GRC: Agentic AI Risk Register & Guardrail Auditor",
    version="1.0.0",
    description="Translates LLM and agentic AI architecture controls into ISO/IEC 42001:2023 and NIST AI RMF 1.0 / AI 600-1 compliance mappings.",
)
auditor = AegisGRCAuditor()


@app.get("/health")
def health_check() -> dict:
    return {"status": "healthy", "service": "aegis-grc", "version": "1.0.0"}


@app.get("/v1/frameworks")
def list_frameworks() -> dict:
    return {
        "iso_42001_controls": ISO_42001_CONTROLS,
        "nist_ai_rmf_subcategories": NIST_AI_RMF_SUBCATEGORIES,
        "owasp_llm_top_10_2025": OWASP_LLM_TOP_10_2025,
        "mitre_atlas_refs": MITRE_ATLAS_REFS,
    }


@app.post("/v1/audit", response_model=AuditReport)
def run_audit(system: AISystemInput) -> AuditReport:
    return auditor.audit(system)
