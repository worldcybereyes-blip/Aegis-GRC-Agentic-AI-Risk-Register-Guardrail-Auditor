"""Command-line interface for Aegis-GRC."""

import argparse
import json
from pathlib import Path
from .auditor import AegisGRCAuditor
from .models import AISystemInput


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis-GRC: Agentic AI Risk Register & Guardrail Auditor CLI")
    parser.add_argument("--input", required=True, help="Path to JSON file describing the AI system architecture.")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format.")
    parser.add_argument("--output", required=False, help="Optional output file path.")
    args = parser.parse_args()

    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    system = AISystemInput(**payload)
    auditor = AegisGRCAuditor()
    report = auditor.audit(system)

    if args.format == "markdown":
        rendered = auditor.render_markdown(report)
    else:
        rendered = report.model_dump_json(indent=2) if hasattr(report, "model_dump_json") else report.json(indent=2)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
