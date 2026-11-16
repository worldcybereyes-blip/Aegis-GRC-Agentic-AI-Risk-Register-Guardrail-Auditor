"""Unit and integration tests for Aegis-GRC (compatible with unittest and pytest)."""

import json
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from aegis_grc.api import app
from aegis_grc.auditor import AegisGRCAuditor
from aegis_grc.models import AISystemInput, AutonomyLevel, RiskTier


class TestAegisGRCAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = AegisGRCAuditor()
        self.client = TestClient(app)

    def test_aegis_soc_audit_classification(self):
        example_path = Path(__file__).resolve().parents[1] / "examples" / "aegis_soc_architecture.json"
        data = json.loads(example_path.read_text(encoding="utf-8"))
        system = AISystemInput(**data)

        report = self.auditor.audit(system)
        self.assertEqual(report.autonomy_level, AutonomyLevel.LEVEL_2)
        self.assertEqual(report.inherent_risk_tier, RiskTier.HIGH)
        self.assertEqual(len(report.risk_register), 5)
        self.assertTrue(any("MG-2.2" in m.nist_ai_rmf_ref for m in report.framework_mappings))
        self.assertTrue(any("A.6.2.6" in m.iso_42001_ref for m in report.framework_mappings))

    def test_unbounded_level3_critical_risk(self):
        system = AISystemInput(
            system_name="Unbounded IR Bot",
            purpose="Fully autonomous firewall and IAM remediation.",
            has_pii_or_sensitive_data=True,
            has_write_or_exec_permissions=True,
            blast_radius="Enterprise",
            human_in_the_loop=False,
            existing_guardrails=[],
        )
        report = self.auditor.audit(system)
        self.assertEqual(report.autonomy_level, AutonomyLevel.LEVEL_3)
        self.assertEqual(report.inherent_risk_tier, RiskTier.CRITICAL)
        self.assertGreaterEqual(len(report.gap_analysis.identified_gaps), 3)

    def test_fastapi_endpoints(self):
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "healthy")

        frameworks = self.client.get("/v1/frameworks")
        self.assertEqual(frameworks.status_code, 200)
        self.assertIn("iso_42001_controls", frameworks.json())

        resp = self.client.post(
            "/v1/audit",
            json={
                "system_name": "Read-Only Triage Copilot",
                "purpose": "Summarizes SIEM alerts without tool execution.",
                "has_pii_or_sensitive_data": False,
                "has_write_or_exec_permissions": False,
                "blast_radius": "Local",
                "human_in_the_loop": False,
                "existing_guardrails": ["Pydantic schema validation"],
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["autonomy_level"], "Level 1: Human-Assisted")
        self.assertEqual(body["inherent_risk_tier"], "Low")


if __name__ == "__main__":
    unittest.main()
