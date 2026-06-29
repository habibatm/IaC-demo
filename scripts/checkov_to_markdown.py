#!/usr/bin/env python3
"""Convert Checkov JSON into a readable GitHub Actions Markdown report.

The script also optionally emits GitHub workflow annotation commands for failed
checks so the workflow run shows file-level security findings.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List


def workflow_escape(value: Any) -> str:
    text = str(value or "")
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def md_escape(value: Any) -> str:
    text = str(value or "")
    return text.replace("|", "\\|").replace("\n", " ").strip()


def repo_path(check: Dict[str, Any]) -> str:
    path = check.get("repo_file_path") or check.get("file_path") or ""
    path = str(path).lstrip("/")
    return path or "unknown"


def line_ref(check: Dict[str, Any]) -> str:
    rng = check.get("file_line_range") or []
    if len(rng) >= 2:
        return f"{rng[0]}-{rng[1]}"
    if len(rng) == 1:
        return str(rng[0])
    return "-"


def first_line(check: Dict[str, Any]) -> int:
    rng = check.get("file_line_range") or []
    if rng:
        try:
            return int(rng[0])
        except (TypeError, ValueError):
            return 1
    return 1


def area(check: Dict[str, Any]) -> str:
    name = (check.get("check_name") or "").lower()
    resource = (check.get("resource") or "").lower()
    combined = f"{name} {resource}"

    if "s3" in combined or "bucket" in combined:
        return "Data / S3"
    if "security group" in combined or "ingress" in combined or "egress" in combined or "0.0.0.0" in combined:
        return "Network exposure"
    if "ec2" in combined or "instance metadata" in combined or "imds" in combined or "public ip" in combined:
        return "Compute hardening"
    if "logging" in combined or "monitoring" in combined:
        return "Logging / monitoring"
    if "iam" in combined or "role" in combined:
        return "Identity / IAM"
    return "General"


def demo_priority(check: Dict[str, Any]) -> str:
    name = (check.get("check_name") or "").lower()
    resource = (check.get("resource") or "").lower()
    combined = f"{name} {resource}"

    high_terms = [
        "public", "0.0.0.0", "port 22", "port 3389", "any principal",
        "unencrypted", "encrypted", "metadata service version 1", "imdsv1"
    ]
    if any(term in combined for term in high_terms):
        return "High"
    medium_terms = ["logging", "monitoring", "versioning", "replication", "lifecycle"]
    if any(term in combined for term in medium_terms):
        return "Medium"
    return "Review"


def why_it_matters(check: Dict[str, Any]) -> str:
    name = (check.get("check_name") or "").lower()

    if "block public" in name or "any principal" in name or "public access" in name:
        return "Potential public data exposure."
    if "0.0.0.0" in name or "port 22" in name or "port 3389" in name or "ingress" in name:
        return "Administrative or network access may be exposed to the internet."
    if "egress" in name:
        return "Outbound traffic is too permissive."
    if "encrypted" in name or "kms" in name:
        return "Data may not be protected at rest."
    if "metadata service version 1" in name or "imds" in name:
        return "Instance metadata access uses weaker protections."
    if "public ip" in name:
        return "Compute resource may be internet reachable."
    if "logging" in name or "monitoring" in name:
        return "Reduced auditability and detection coverage."
    if "versioning" in name or "replication" in name or "lifecycle" in name:
        return "Reduced resilience, recovery, or data governance."
    if "iam role" in name:
        return "Instance may lack managed identity and least-privilege controls."
    return "Review against cloud security baseline."


def failed_checks(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return data.get("results", {}).get("failed_checks", []) or []


def passed_checks(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return data.get("results", {}).get("passed_checks", []) or []


def skipped_checks(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return data.get("results", {}).get("skipped_checks", []) or []


def build_markdown(data: Dict[str, Any], scan_path: str) -> str:
    summary = data.get("summary", {}) or {}
    failed = int(summary.get("failed", len(failed_checks(data))) or 0)
    passed = int(summary.get("passed", len(passed_checks(data))) or 0)
    skipped = int(summary.get("skipped", len(skipped_checks(data))) or 0)
    parsing_errors = int(summary.get("parsing_errors", 0) or 0)
    resource_count = int(summary.get("resource_count", 0) or 0)
    checkov_version = summary.get("checkov_version", "unknown")

    outcome = "Failed checks found" if failed else "No failed checks"
    icon = "❌" if failed else "✅"

    failures = failed_checks(data)
    area_counts = Counter(area(check) for check in failures)
    priority_counts = Counter(demo_priority(check) for check in failures)

    lines: List[str] = []
    lines.append("# Checkov IaC Security Report")
    lines.append("")
    lines.append(f"**Outcome:** {icon} {outcome}")
    lines.append(f"**Scan target:** `{md_escape(scan_path)}`")
    lines.append(f"**Checkov version:** `{md_escape(checkov_version)}`")
    lines.append("")
    lines.append("## Executive summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|---|---:|")
    lines.append(f"| Passed checks | {passed} |")
    lines.append(f"| Failed checks | {failed} |")
    lines.append(f"| Skipped checks | {skipped} |")
    lines.append(f"| Parsing errors | {parsing_errors} |")
    lines.append(f"| Resources scanned | {resource_count} |")
    lines.append("")

    if failures:
        lines.append("## Findings by area")
        lines.append("")
        lines.append("| Area | Failed checks |")
        lines.append("|---|---:|")
        for key, count in area_counts.most_common():
            lines.append(f"| {md_escape(key)} | {count} |")
        lines.append("")

        lines.append("## Demo priority view")
        lines.append("")
        lines.append("This is a demo-friendly grouping, not a formal severity rating.")
        lines.append("")
        lines.append("| Demo priority | Failed checks |")
        lines.append("|---|---:|")
        for key in ["High", "Medium", "Review"]:
            if priority_counts.get(key):
                lines.append(f"| {key} | {priority_counts[key]} |")
        lines.append("")

        lines.append("## Failed checks")
        lines.append("")
        lines.append("| # | Priority | Area | Check | Resource | File | Why it matters |")
        lines.append("|---:|---|---|---|---|---|---|")
        for idx, check in enumerate(failures, start=1):
            file_display = f"`{repo_path(check)}:{line_ref(check)}`"
            check_display = f"`{md_escape(check.get('check_id'))}` {md_escape(check.get('check_name'))}"
            lines.append(
                f"| {idx} | {demo_priority(check)} | {md_escape(area(check))} | "
                f"{check_display} | `{md_escape(check.get('resource'))}` | "
                f"{file_display} | {md_escape(why_it_matters(check))} |"
            )
        lines.append("")

        lines.append("## Suggested remediation themes")
        lines.append("")
        lines.append("- Block public S3 access and avoid wildcard principals unless explicitly justified.")
        lines.append("- Restrict SSH/RDP and other administrative access to approved private ranges or managed access paths.")
        lines.append("- Require encryption, logging, versioning, and appropriate monitoring for storage and compute resources.")
        lines.append("- Require IMDSv2 for EC2 metadata access and avoid public IP exposure where not needed.")
        lines.append("- Treat accepted exceptions as time-bound, approved risk decisions.")
    else:
        lines.append("## Result")
        lines.append("")
        lines.append("No failed Checkov checks were reported for this scan target.")

    lines.append("")
    lines.append("---")
    lines.append("Full JSON, SARIF, CLI output, and this Markdown report are attached to the workflow run as artifacts.")
    return "\n".join(lines) + "\n"


def emit_annotations(data: Dict[str, Any], limit: int = 30) -> None:
    for check in failed_checks(data)[:limit]:
        file_path = repo_path(check)
        line = first_line(check)
        title = f"{check.get('check_id')}: {check.get('check_name')}"
        message = f"{check.get('resource')} - {why_it_matters(check)}"
        print(
            f"::error file={workflow_escape(file_path)},line={line},"
            f"title={workflow_escape(title)}::{workflow_escape(message)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to Checkov JSON output")
    parser.add_argument("--output", required=True, help="Path to write Markdown summary")
    parser.add_argument("--scan-path", default="unknown", help="Folder scanned")
    parser.add_argument("--annotations", action="store_true", help="Emit GitHub workflow annotations to stdout")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        output_path.write_text(
            "# Checkov IaC Security Report\n\n"
            "No Checkov JSON result file was found. Check the workflow logs for scan failures.\n",
            encoding="utf-8",
        )
        return 0

    with input_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    output_path.write_text(build_markdown(data, args.scan_path), encoding="utf-8")

    if args.annotations:
        emit_annotations(data)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
