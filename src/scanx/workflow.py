"""
scanx.workflow
================
The deterministic pipeline that ties every tool together:

    acquire repo -> verify path -> discover files -> worker-pool analysis -> report

Each stage is a standalone, independently testable/callable tool (see
scanx.tools.*). This module is the "agent" in the sense that it autonomously
drives the whole audit end-to-end once given a repo — no per-file human
input required — while staying fully deterministic and auditable via logs,
which matters for a security tool.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from scanx.config import ScanConfig
from scanx.logging_config import get_logger
from scanx.models import ScanReport
from scanx.tools.analysis_tools import analyze_files_worker_pool
from scanx.tools.discovery_tools import discover_files_impl
from scanx.tools.report_tools import generate_reports
from scanx.tools.repo_tools import (
    RepoAcquisitionError,
    cleanup_cloned_repo,
    clone_repo,
    verify_local_path,
)

log = get_logger("workflow")


class ScanxWorkflow:
    """Orchestrates a full scan run from repo source to final report."""

    def __init__(
        self,
        config: ScanConfig,
        output_dir: str | Path = "reports",
        keep_clone: bool = False,
    ):
        self.config = config
        self.output_dir = Path(output_dir)
        self.keep_clone = keep_clone

    def resolve_repo(self, *, url: str | None, local_path: str | None) -> str:
        """Step 1: get a verified local path, cloning if a URL was given."""
        if url:
            log.info("Repo source is a URL: %s", url)
            return clone_repo.invoke({"url": url})
        if local_path:
            log.info("Repo source is a local path: %s", local_path)
            return verify_local_path.invoke({"path": local_path})
        raise RepoAcquisitionError("Either a repo URL or a local path must be provided.")

    def run(self, *, url: str | None = None, local_path: str | None = None) -> ScanReport:
        """Execute the full pipeline synchronously (wraps the async analysis stage)."""
        repo_root = self.resolve_repo(url=url, local_path=local_path)
        was_cloned = url is not None
        source_label = url or local_path or repo_root

        try:
            report = ScanReport(
                repo_source=source_label,
                repo_local_path=repo_root,
                model_name=self.config.model_name,
            )

            log.info("=== Stage: discovery ===")
            discovered = discover_files_impl(repo_root, self.config)
            report.total_files_discovered = len(discovered)

            if not discovered:
                log.warning("No files matched the scan policy — nothing to analyze.")
                report.finished_at = time.time()
                generate_reports(report, self.output_dir)
                return report

            log.info(
                "=== Stage: analysis (worker pool, concurrency=%d) ===", self.config.concurrency
            )
            results = asyncio.run(analyze_files_worker_pool(discovered, self.config))
            report.results = results
            report.total_files_scanned = sum(1 for r in results if r.error is None)
            report.total_files_errored = sum(1 for r in results if r.error is not None)
            report.total_files_skipped = report.total_files_discovered - len(results)
            report.finished_at = time.time()

            log.info("=== Stage: reporting ===")
            generate_reports(report, self.output_dir)

            counts = report.severity_counts
            log.info(
                "Scan complete in %.2fs — critical=%d high=%d medium=%d low=%d info=%d",
                report.duration_seconds,
                counts["critical"],
                counts["high"],
                counts["medium"],
                counts["low"],
                counts["info"],
            )
            return report
        finally:
            if was_cloned and not self.keep_clone:
                cleanup_cloned_repo(repo_root)
            elif was_cloned and self.keep_clone:
                log.info("Keeping cloned repo at %s (--keep-clone)", repo_root)
