"""
scanx.tools.report_tools
===========================
Step 4 of the workflow: turn a ScanReport into durable artifacts —
a full-fidelity JSON report and a human-readable Markdown summary.
"""

from __future__ import annotations

from pathlib import Path

from scanx.logging_config import get_logger
from scanx.models import ScanReport, Severity

log = get_logger("tools.report")

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def write_json_report(report: ScanReport, output_dir: Path) -> Path:
    path = output_dir / "scanx-report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    log.info("Wrote JSON report: %s", path)
    return path


def _render_markdown(report: ScanReport) -> str:
    counts = report.severity_counts
    lines: list[str] = []
    lines.append("# Scanx Security Report")
    lines.append("")
    lines.append(f"- **Repository:** `{report.repo_source}`")
    lines.append(f"- **Model:** `{report.model_name}`")
    lines.append(f"- **Duration:** {report.duration_seconds}s")
    lines.append(
        f"- **Files:** {report.total_files_scanned} scanned, "
        f"{report.total_files_skipped} skipped, {report.total_files_errored} errored "
        f"(of {report.total_files_discovered} discovered)"
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in Severity:
        lines.append(f"| {_SEVERITY_EMOJI[sev]} {sev.value.upper()} | {counts[sev.value]} |")
    lines.append("")

    findings = report.all_findings
    if not findings:
        lines.append("No findings. 🎉")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    for f in findings:
        loc = ""
        if f.line_start:
            loc = f" (lines {f.line_start}-{f.line_end})" if f.line_end and f.line_end != f.line_start else f" (line {f.line_start})"
        lines.append(f"### {_SEVERITY_EMOJI[f.severity]} [{f.severity.value.upper()}] {f.title}")
        lines.append("")
        lines.append(f"- **File:** `{f.file_path}`{loc}")
        lines.append(f"- **Category:** {f.category}")
        if f.cwe_id:
            lines.append(f"- **CWE:** {f.cwe_id}")
        lines.append(f"- **Confidence:** {f.confidence}")
        lines.append("")
        lines.append(f"{f.description}")
        lines.append("")
        if f.code_snippet:
            lines.append("```")
            lines.append(f.code_snippet.strip()[:1000])
            lines.append("```")
            lines.append("")
        lines.append(f"**Recommendation:** {f.recommendation}")
        lines.append("")
        lines.append("---")
        lines.append("")

    errored_files = [r for r in report.results if r.error]
    if errored_files:
        lines.append("## Files with analysis errors")
        lines.append("")
        for r in errored_files:
            lines.append(f"- `{r.file_path}`: {r.error}")
        lines.append("")

    return "\n".join(lines)


def write_markdown_report(report: ScanReport, output_dir: Path) -> Path:
    path = output_dir / "scanx-report.md"
    path.write_text(_render_markdown(report), encoding="utf-8")
    log.info("Wrote Markdown report: %s", path)
    return path


def generate_reports(report: ScanReport, output_dir: str | Path) -> tuple[Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = write_json_report(report, out)
    md_path = write_markdown_report(report, out)
    return json_path, md_path
