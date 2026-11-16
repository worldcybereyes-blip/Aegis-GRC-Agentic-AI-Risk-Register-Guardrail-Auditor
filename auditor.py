"""Core Aegis-GRC Risk Register & Guardrail Gap Audit engine."""

from typing import List
from .models import (
    AISystemInput,
    AuditReport,
    AutonomyLevel,
    FrameworkMapping,
    GapAnalysis,
    RiskRegisterEntry,
    RiskTier,
)


class AegisGRCAuditor:
    """Translates agentic AI architectures and guardrails into ISO/IEC 42001 & NIST AI RMF audits."""

    def classify_autonomy(self, system: AISystemInput) -> AutonomyLevel:
        if not system.has_write_or_exec_permissions:
            return AutonomyLevel.LEVEL_1
        if system.human_in_the_loop:
            return AutonomyLevel.LEVEL_2
        return AutonomyLevel.LEVEL_3

    def classify_inherent_risk(self, system: AISystemInput, autonomy: AutonomyLevel) -> tuple[RiskTier, str]:
        blast = system.blast_radius.lower()
        if autonomy == AutonomyLevel.LEVEL_3 and (system.has_pii_or_sensitive_data or "enterprise" in blast):
            return (
                RiskTier.CRITICAL,
                "Critical inherent risk due to un-gated autonomous execution permissions combined with enterprise blast radius or sensitive data access.",
            )
        if system.has_write_or_exec_permissions and (system.has_pii_or_sensitive_data or "enterprise" in blast):
            return (
                RiskTier.HIGH,
                f"High inherent risk driven by state-changing tool/API execution, {system.blast_radius.lower()} blast radius, and sensitive data exposure.",
            )
        if system.has_write_or_exec_permissions or system.has_pii_or_sensitive_data:
            return (
                RiskTier.MODERATE,
                "Moderate inherent risk due to bounded tool execution or sensitive data handling without enterprise-wide write blast radius.",
            )
        return (
            RiskTier.LOW,
            "Low inherent risk: read-only advisory system with no sensitive data ingestion or state-changing execution.",
        )

    def _has_control(self, guardrails: List[str], keywords: List[str]) -> bool:
        joined = " | ".join(guardrails).lower()
        return any(kw.lower() in joined for kw in keywords)

    def build_risk_register(self, system: AISystemInput, autonomy: AutonomyLevel) -> List[RiskRegisterEntry]:
        g = system.existing_guardrails
        has_hitl = system.human_in_the_loop or self._has_control(g, ["hitl", "human-in-the-loop", "approval"])
        has_pi_filter = self._has_control(g, ["t1698", "prompt injection", "input sanitization", "delimiter"])
        has_rbac = self._has_control(g, ["rbac", "policy-as-code", "least privilege", "scoped token"])
        has_dlp = self._has_control(g, ["pii", "redaction", "dlp", "secret scanning"])
        has_grounding = self._has_control(g, ["rag", "citation", "schema", "deterministic", "pydantic"])

        entries = [
            RiskRegisterEntry(
                risk_id="AI-RISK-01",
                threat_failure_mode="Indirect Prompt Injection via untrusted telemetry or external inputs",
                owasp_atlas_ref="LLM01:2025 / AML.T0051.001 / T1698",
                technical_impact="Adversary hijacks agent reasoning loop to exfiltrate data or trigger unauthorized actions.",
                inherent_risk=RiskTier.CRITICAL if system.has_write_or_exec_permissions else RiskTier.HIGH,
                mapped_technical_control=(
                    "T1698 prompt-injection defense & structured input delimiters"
                    if has_pi_filter
                    else "MISSING: Input sanitization & T1698 injection classifier"
                ),
                residual_risk=RiskTier.MODERATE if has_pi_filter else RiskTier.HIGH,
            ),
            RiskRegisterEntry(
                risk_id="AI-RISK-02",
                threat_failure_mode="Excessive Agency & unauthorized state-changing tool execution",
                owasp_atlas_ref="LLM06:2025 / AML.T0054",
                technical_impact="Agent revokes production accounts, isolates hosts, or modifies records without authorization.",
                inherent_risk=RiskTier.CRITICAL if autonomy == AutonomyLevel.LEVEL_3 else RiskTier.HIGH,
                mapped_technical_control=(
                    "Aegis-SOC HITL approval hooks & Policy-as-Code RBAC"
                    if (has_hitl and has_rbac)
                    else ("HITL approval gate (partial — missing Policy-as-Code RBAC)" if has_hitl else "MISSING: HITL gate & RBAC tool scoping")
                ),
                residual_risk=RiskTier.LOW if (has_hitl and has_rbac) else (RiskTier.MODERATE if has_hitl else RiskTier.CRITICAL),
            ),
            RiskRegisterEntry(
                risk_id="AI-RISK-03",
                threat_failure_mode="Sensitive Information & System Prompt Leakage",
                owasp_atlas_ref="LLM02:2025 / LLM07:2025",
                technical_impact="Exposure of PII, API credentials, or internal detection/system instructions in model outputs.",
                inherent_risk=RiskTier.HIGH if system.has_pii_or_sensitive_data else RiskTier.MODERATE,
                mapped_technical_control=(
                    "Output PII/secret redaction & DLP filter"
                    if has_dlp
                    else "MISSING: Automated output DLP & system-prompt boundary checks"
                ),
                residual_risk=RiskTier.LOW if has_dlp else RiskTier.HIGH,
            ),
            RiskRegisterEntry(
                risk_id="AI-RISK-04",
                threat_failure_mode="Confabulation / Hallucinated Security Findings or Actions",
                owasp_atlas_ref="LLM09:2025 / NIST AI 600-1 Confabulation",
                technical_impact="False-positive incident escalations or fabricated compliance/IOC evidence.",
                inherent_risk=RiskTier.HIGH,
                mapped_technical_control=(
                    "Deterministic Pydantic schema validation & grounded tool outputs"
                    if has_grounding
                    else "MISSING: Schema validation & source-grounding verification"
                ),
                residual_risk=RiskTier.MODERATE if has_grounding else RiskTier.HIGH,
            ),
            RiskRegisterEntry(
                risk_id="AI-RISK-05",
                threat_failure_mode="Third-Party Foundation Model / MCP Supply Chain Compromise",
                owasp_atlas_ref="LLM03:2025 / NIST AI 600-1 Value Chain",
                technical_impact="Upstream model drift, silent API deprecation, or compromised MCP tool server.",
                inherent_risk=RiskTier.MODERATE,
                mapped_technical_control=(
                    "Scoped MCP server allowlists & pinned model versions"
                    if self._has_control(g, ["mcp", "allowlist", "version", "vendor"])
                    else "MISSING: Model version pinning & third-party SLA/DPA tracking"
                ),
                residual_risk=RiskTier.LOW if self._has_control(g, ["mcp", "allowlist", "version", "vendor"]) else RiskTier.MODERATE,
            ),
        ]
        return entries

    def build_framework_mappings(self, system: AISystemInput) -> List[FrameworkMapping]:
        g = system.existing_guardrails
        mappings: List[FrameworkMapping] = []

        if system.human_in_the_loop or self._has_control(g, ["hitl", "human-in-the-loop", "approval"]):
            mappings.append(
                FrameworkMapping(
                    technical_guardrail="Aegis-SOC Human-in-the-Loop (HITL) Approval Gate",
                    iso_42001_ref="Clause 6.1.3 / Annex A.6.2.2 & A.9.2",
                    nist_ai_rmf_ref="MANAGE MG-2.2 & GOVERN GV-1.3",
                    audit_verification_artifact="Signed approval/rejection webhook logs with approver ID, timestamp, action payload hash, and rationale.",
                )
            )
        if self._has_control(g, ["t1698", "prompt injection", "input sanitization", "delimiter"]):
            mappings.append(
                FrameworkMapping(
                    technical_guardrail="T1698 Prompt-Injection Defense & Input Sanitization",
                    iso_42001_ref="Annex A.6.2.6 & A.7.2 (Data/Input Integrity)",
                    nist_ai_rmf_ref="MEASURE MS-2.5 & MAP MP-2.3",
                    audit_verification_artifact="Red-team adversarial test suite results (AML.T0051.000/.001) and blocked-prompt SIEM event logs.",
                )
            )
        if self._has_control(g, ["rbac", "policy-as-code", "least privilege", "scoped token"]):
            mappings.append(
                FrameworkMapping(
                    technical_guardrail="Deterministic Policy-as-Code & Scoped Tool RBAC",
                    iso_42001_ref="Annex A.4.2 & A.9.4 (Intended Use Boundaries)",
                    nist_ai_rmf_ref="GOVERN GV-1.2 & MANAGE MG-2.4",
                    audit_verification_artifact="OPA/Rego or Python policy bundle, IAM least-privilege role manifests, and denied-execution audit logs.",
                )
            )
        if self._has_control(g, ["log", "audit", "siem", "telemetry", "sqlite", "elastic", "wazuh"]):
            mappings.append(
                FrameworkMapping(
                    technical_guardrail="Immutable Agentic Telemetry & Action Audit Trail",
                    iso_42001_ref="Clause 9.1 & Annex A.6.2.8 (Event Logging)",
                    nist_ai_rmf_ref="MEASURE MS-4.1 & MANAGE MG-1.1",
                    audit_verification_artifact="Append-only SIEM/WORM logs capturing prompt hashes, tool calls, latency, and human override events.",
                )
            )
        if self._has_control(g, ["pii", "redaction", "dlp", "secret"]):
            mappings.append(
                FrameworkMapping(
                    technical_guardrail="Output DLP, PII Redaction & Secret Boundary Filter",
                    iso_42001_ref="Annex A.7.4 & A.8.2 (Data Privacy & Transparency)",
                    nist_ai_rmf_ref="MAP MP-2.3 & MEASURE MS-2.6",
                    audit_verification_artifact="Regex/NER redaction unit test reports and zero-leakage validation logs.",
                )
            )

        if not mappings:
            mappings.append(
                FrameworkMapping(
                    technical_guardrail="Baseline System Inventory & Logging (Minimum Required)",
                    iso_42001_ref="Clause 4.3 & Annex A.4.2",
                    nist_ai_rmf_ref="MAP MP-2.1 & GOVERN GV-1.1",
                    audit_verification_artifact="System architecture diagram, data-flow inventory, and initial AI Impact Assessment.",
                    status="Gap / Required",
                )
            )
        return mappings

    def build_gap_analysis(self, system: AISystemInput) -> GapAnalysis:
        g = system.existing_guardrails
        strengths: List[str] = []
        gaps: List[str] = []
        fixes: List[str] = []

        if system.human_in_the_loop or self._has_control(g, ["hitl", "human-in-the-loop", "approval"]):
            strengths.append("Human-in-the-Loop (HITL) approval hooks directly satisfy NIST MANAGE MG-2.2 and ISO/IEC 42001 A.9.2 human oversight for high-impact actions.")
        else:
            gaps.append("Missing HITL approval gate for state-changing or privileged agent actions (NIST MG-2.2 / ISO 42001 A.9.2).")
            fixes.append("Implement a cryptographic HITL approval queue (e.g., signed Slack/FastAPI webhook with 15-minute TTL) before any write/revoke tool executes.")

        if self._has_control(g, ["t1698", "prompt injection", "input sanitization"]):
            strengths.append("T1698 prompt-injection screening mitigates OWASP LLM01:2025 and MITRE ATLAS AML.T0051, supporting NIST MEASURE MS-2.5.")
        else:
            gaps.append("No dedicated prompt-injection or indirect telemetry sanitization layer (OWASP LLM01 / AML.T0051.001).")
            fixes.append("Deploy a dual-stage input sanitizer (structural XML/JSON delimiters + T1698 classifier) before passing external logs to the LLM.")

        if self._has_control(g, ["rbac", "policy-as-code"]):
            strengths.append("Deterministic Policy-as-Code guardrails enforce hard execution boundaries independent of LLM probabilistic output.")
        else:
            gaps.append("Unbounded tool permissions without deterministic Policy-as-Code enforcement (OWASP LLM06:2025).")
            fixes.append("Enforce OPA/Rego or Pydantic-validated allowlists per agent role, separating read-only triage tokens from write-capable IR tokens.")

        if not self._has_control(g, ["impact assessment", "aia", "drift"]):
            gaps.append("Missing formal AI System Impact Assessment (ISO/IEC 42001 Clause 6.1.4 / Annex A.5) and automated model-drift monitoring (NIST MS-3.1).")
            fixes.append("Author an ISO 42001 Annex A.5 AI Impact Assessment and schedule weekly golden-dataset regression tests to detect model/prompt drift.")

        assumptions = [
            f"Model provider ({system.model_provider}) operates under an enterprise zero-data-retention DPA unless otherwise evidenced.",
            f"Telemetry sources ({', '.join(system.telemetry_sources) if system.telemetry_sources else 'unspecified'}) require tamper-evident retention verification.",
        ]

        return GapAnalysis(
            control_strengths=strengths,
            identified_gaps=gaps,
            actionable_fixes=fixes,
            telemetry_assumptions=assumptions,
        )

    def audit(self, system: AISystemInput) -> AuditReport:
        autonomy = self.classify_autonomy(system)
        risk_tier, justification = self.classify_inherent_risk(system, autonomy)
        risk_register = self.build_risk_register(system, autonomy)
        mappings = self.build_framework_mappings(system)
        gaps = self.build_gap_analysis(system)

        return AuditReport(
            system_name=system.system_name,
            purpose=system.purpose,
            autonomy_level=autonomy,
            inherent_risk_tier=risk_tier,
            risk_justification=justification,
            risk_register=risk_register,
            framework_mappings=mappings,
            gap_analysis=gaps,
        )

    def render_markdown(self, report: AuditReport) -> str:
        lines = [
            f"# Aegis-GRC Audit Report: {report.system_name}",
            "",
            "### 1. AI System Inventory & Autonomy Classification",
            f"- **System Name & Purpose:** {report.system_name} — {report.purpose}",
            f"- **Autonomy Level:** {report.autonomy_level.value}",
            f"- **Inherent Risk Tier:** {report.inherent_risk_tier.value} — {report.risk_justification}",
            "",
            "### 2. AI Risk Register (Top Identified Risks)",
            "| Risk ID | Threat / Failure Mode (OWASP / ATLAS) | Technical Impact | Inherent Risk | Mapped Technical Control | Residual Risk |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for r in report.risk_register:
            lines.append(
                f"| {r.risk_id} | {r.threat_failure_mode} ({r.owasp_atlas_ref}) | {r.technical_impact} | {r.inherent_risk.value} | {r.mapped_technical_control} | {r.residual_risk.value} |"
            )

        lines.extend([
            "",
            "### 3. Framework Control Mapping (ISO/IEC 42001 & NIST AI RMF)",
            "| Technical Guardrail / Control | ISO/IEC 42001 Clause / Annex A | NIST AI RMF Function & Subcategory | Audit Verification Artifact |",
            "| :--- | :--- | :--- | :--- |",
        ])
        for m in report.framework_mappings:
            lines.append(
                f"| {m.technical_guardrail} | {m.iso_42001_ref} | {m.nist_ai_rmf_ref} | {m.audit_verification_artifact} |"
            )

        lines.extend(["", "### 4. Agentic Guardrail Gap Analysis & Remediation", "- **Control Strengths:**"])
        for s in report.gap_analysis.control_strengths:
            lines.append(f"  - {s}")
        lines.append("- **Identified Gaps:**")
        for g in report.gap_analysis.identified_gaps:
            lines.append(f"  - {g}")
        lines.append("- **Actionable Engineering Fixes:**")
        for f in report.gap_analysis.actionable_fixes:
            lines.append(f"  - {f}")
        lines.append("- **Audit Assumptions & Required Telemetry:**")
        for a in report.gap_analysis.telemetry_assumptions:
            lines.append(f"  - {a}")

        return "\n".join(lines)
