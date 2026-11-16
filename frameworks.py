"""Grounded compliance control catalog for ISO/IEC 42001:2023, NIST AI RMF 1.0 / AI 600-1, OWASP LLM Top 10, and MITRE ATLAS."""

from typing import Dict

ISO_42001_CONTROLS: Dict[str, str] = {
    "Clause 4.1-4.3": "Context of the organization and AIMS scope definition",
    "Clause 5.2 / A.2.2": "AI policy establishment, alignment, and periodic review",
    "Clause 5.3 / A.3.2": "AI governance roles, responsibilities, and authorities",
    "Clause 6.1.2 / 8.2": "AI risk assessment methodology and execution",
    "Clause 6.1.3 / 8.3": "AI risk treatment plan and Statement of Applicability (SoA)",
    "Clause 6.1.4 / 8.4 / A.5.2": "AI system impact assessment on individuals and groups",
    "Clause 9.1": "Monitoring, measurement, analysis, and evaluation of AI performance",
    "Clause 10.2": "Nonconformity and corrective action",
    "A.4.2-A.4.5": "AI system inventory, tooling, compute, and data resources",
    "A.6.1.2 / A.6.2.2": "AI system design, verification, and deployment approval",
    "A.6.2.6 / A.6.2.8": "AI system operation, continuous monitoring, and event logging",
    "A.7.2-A.7.4": "Data for AI systems: quality, provenance, and preparation",
    "A.8.2-A.8.4": "Information for interested parties and incident reporting",
    "A.9.2-A.9.4": "Responsible use of AI systems within intended scope",
    "A.10.2-A.10.3": "Third-party AI supplier governance and allocated responsibilities",
}

NIST_AI_RMF_SUBCATEGORIES: Dict[str, str] = {
    "GV-1.1": "GOVERN: Legal and regulatory requirements involving AI are understood and documented",
    "GV-1.2": "GOVERN: Trustworthy AI characteristics integrated into policies and practices",
    "GV-1.3": "GOVERN: Risk management activities calibrated to organizational risk tolerance",
    "GV-4.1": "GOVERN: Organizational culture and critical thinking in AI risk management",
    "GV-6.1": "GOVERN: Policies and procedures for third-party AI entities and data",
    "MP-2.1": "MAP: Scientific/technical context, intended use, and stakeholders documented",
    "MP-2.3": "MAP: Sensitive data, human-AI configuration, and failure modes identified",
    "MP-3.1": "MAP: Potential negative impacts and blast radius assessed",
    "MP-5.1": "MAP: Likelihood and magnitude of impacts characterized",
    "MS-1.1": "MEASURE: Appropriate metrics and evaluation methods established",
    "MS-2.1": "MEASURE: Pre-deployment testing and adversarial red-teaming executed",
    "MS-2.5": "MEASURE: AI system safety, security, and prompt-injection resilience evaluated",
    "MS-2.6": "MEASURE: Explainability, tool transparency, and confabulation checks",
    "MS-3.1": "MEASURE: Continuous post-deployment drift and anomaly monitoring",
    "MS-4.1": "MEASURE: Immutable audit trail and measurement feedback loops",
    "MG-1.1": "MANAGE: Risk treatment plans prioritized and tracked",
    "MG-2.2": "MANAGE: Human-in-the-loop (HITL) oversight, overrides, and circuit breakers",
    "MG-2.4": "MANAGE: Mechanisms to deactivate or roll back unsafe AI behaviors",
    "MG-3.2": "MANAGE: Third-party model/API supply-chain risk management",
}

OWASP_LLM_TOP_10_2025: Dict[str, str] = {
    "LLM01:2025": "Prompt Injection (Direct & Indirect)",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation (Confabulation / Hallucination)",
    "LLM10:2025": "Unbounded Consumption",
}

MITRE_ATLAS_REFS: Dict[str, str] = {
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak Injection",
    "T1698-Guardrail": "Command/Execution & Prompt-Injection Boundary Verification",
}
