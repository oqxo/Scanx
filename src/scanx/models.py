"""
scanx.models
============
Structured schemas shared across the pipeline. Using Pydantic models for
LLM output means we can validate/coerce the model's JSON instead of trusting
free text, and it gives us a stable contract for the report generator.
"""

from __future__ import annotations

import enum
import time

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return order[self]


class Finding(BaseModel):
    """A single vulnerability/weakness identified in a chunk of code."""

    title: str = Field(description="Short, specific title for the issue")
    severity: Severity = Field(description="Impact-based severity rating")
    category: str = Field(
        description="e.g. 'Injection', 'Hardcoded Secret', 'Auth', 'SSRF', "
        "'Insecure Deserialization', 'IaC Misconfiguration', 'XSS', 'Crypto'"
    )
    description: str = Field(description="What the issue is and why it's exploitable")
    line_start: int | None = Field(default=None, description="1-indexed start line, if known")
    line_end: int | None = Field(default=None, description="1-indexed end line, if known")
    code_snippet: str | None = Field(default=None, description="Minimal relevant snippet")
    recommendation: str = Field(description="Concrete remediation guidance")
    cwe_id: str | None = Field(default=None, description="e.g. 'CWE-89' if applicable")
    confidence: str = Field(default="medium", description="low | medium | high")

    # Filled in by the pipeline, not the model
    file_path: str = ""


class FileAnalysisResult(BaseModel):
    """Outcome of analyzing one file (possibly across multiple chunks)."""

    file_path: str
    language: str | None = None
    chunks_analyzed: int = 0
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
    duration_seconds: float = 0.0


class ScanReport(BaseModel):
    """Top-level report for an entire scan run."""

    repo_source: str
    repo_local_path: str
    model_name: str
    started_at: float = Field(default_factory=time.time)
    finished_at: float | None = None
    total_files_discovered: int = 0
    total_files_scanned: int = 0
    total_files_skipped: int = 0
    total_files_errored: int = 0
    results: list[FileAnalysisResult] = Field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for result in self.results:
            findings.extend(result.findings)
        return sorted(findings, key=lambda f: (f.severity.rank, f.file_path))

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return round(self.finished_at - self.started_at, 2)
