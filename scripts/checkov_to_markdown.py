#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def md_escape(value):
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def gh_escape(value):
    text = "" if value is None else str(value)
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def as_blocks(data):
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def line_ref(check):
    path = check.get("repo_file_path") or check.get("file_path") or ""
    if path.startswith("/"):
        path = path[1:]
    line_range = check.get("file_line_range") or []
    if len(line_range) >= 2:
        return f"{path}:{line_range[0]}-{line_range[1]}"
    if len(line_range) == 1:
        return f"{path}:{line_range[0]}"
    return path


def first_line(check):
    line_range = check.get("file_line_range") or []
    if line_range:
        return int(line_range[0])
    return 1


def file_path(check):
    path = check.get("repo_file_path") or check.get("file_path") or ""
    return path[1:] if path.startswith("/") else path


def load_results(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_markdown(data, scan_path, max_findings):
    blocks = as_blocks(data)
    summaries = [block.get("summary", {}) for block in blocks]
    passed = sum(int(s.get("passed", 0) or 0) for s in summaries)
    failed = sum(int(s.get("failed", 0) or 0) for s in summaries)
    skipped = sum(int(s.get("skipped", 0) or 0) for s in summaries)
    parsing_errors = sum(int(s.get("parsing_errors", 0) or 0) for s in summaries)
    resources = sum(int(s.get("resource_count", 0) or 0) for s in summaries)
    versions = sorted({str(s.get("checkov_version")) for s in summaries if s.get("checkov_version")})

    failed_checks = []
    passed_checks = []
    skipped_checks = []
    for block in blocks:
        results = block.get("results", {}) or {}
        failed_checks.extend(results.get("failed_checks", []) or [])
        passed_checks.extend(results.get("passed_checks", []) or [])
        skipped_checks.extend(results.get("skipped_checks", []) or [])

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []
    lines.append("# Checkov IaC Security Report")
    lines.append("")
    lines.append(f"Generated: **{now}**")
    lines.append("")
    lines.append("## Scan context")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Scan path | `{md_escape(scan_path)}` |")
    lines.append(f"| Checkov version | `{md_escape(', '.join(versions) if versions else 'unknown')}` |")
    lines.append("")
    lines.append("## Result summary")
    lines.append("")
    lines.append("| Passed | Failed | Skipped | Parsing errors | Resources scanned |")
    lines.append("|---:|---:|---:|---:|---:|")
    lines.append(f"| {passed} | {failed} | {skipped} | {parsing_errors} | {resources} |")
    lines.append("")

    if failed_checks:
        lines.append(f"## Failed findings - showing first {min(max_findings, len(failed_checks))} of {len(failed_checks)}")
        lines.append("")
        lines.append("| # | Check ID | Resource | Location | Finding |")
        lines.append("|---:|---|---|---|---|")
        for idx, check in enumerate(failed_checks[:max_findings], start=1):
            check_id = check.get("check_id", "")
            resource = check.get("resource", "")
            finding = check.get("check_name", "")
            location = line_ref(check)
            lines.append(
                f"| {idx} | `{md_escape(check_id)}` | `{md_escape(resource)}` | `{md_escape(location)}` | {md_escape(finding)} |"
            )
        lines.append("")
        lines.append("Full CLI, JSON and SARIF outputs are attached in the workflow artifact.")
    else:
        lines.append("## Failed findings")
        lines.append("")
        lines.append("No failed Checkov findings were detected.")

    return "\n".join(lines) + "\n", failed_checks, failed


def emit_annotations(failed_checks, max_annotations):
    for check in failed_checks[:max_annotations]:
        check_id = check.get("check_id", "Checkov")
        title = f"{check_id}: {check.get('resource', '')}"
        message = check.get("check_name", "Checkov policy failed")
        path = file_path(check)
        line = first_line(check)
        if path:
            print(
                f"::error file={gh_escape(path)},line={line},title={gh_escape(title)}::{gh_escape(message)}"
            )
        else:
            print(f"::error title={gh_escape(title)}::{gh_escape(message)}")


def main():
    parser = argparse.ArgumentParser(description="Convert Checkov JSON to a GitHub Actions Markdown summary.")
    parser.add_argument("json_path")
    parser.add_argument("--scan-path", default="unknown")
    parser.add_argument("--output", default="reports/checkov-summary.md")
    parser.add_argument("--max-findings", type=int, default=25)
    parser.add_argument("--max-annotations", type=int, default=20)
    parser.add_argument("--github-annotations", action="store_true")
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    json_path = Path(args.json_path)
    if not json_path.exists():
        output_path.write_text(
            "# Checkov IaC Security Report\n\nNo Checkov JSON result file was found. Check the workflow logs for scan failures.\n",
            encoding="utf-8",
        )
        return 0

    try:
        data = load_results(json_path)
        markdown, failed_checks, _failed = build_markdown(data, args.scan_path, args.max_findings)
        output_path.write_text(markdown, encoding="utf-8")
        if args.github_annotations:
            emit_annotations(failed_checks, args.max_annotations)
        return 0
    except Exception as exc:
        output_path.write_text(
            f"# Checkov IaC Security Report\n\nFailed to parse Checkov JSON results: `{md_escape(exc)}`\n",
            encoding="utf-8",
        )
        print(f"Failed to parse Checkov JSON results: {exc}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())