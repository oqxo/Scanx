"""
scanx.cli
==========
Command-line entry point. Supports two modes:
  - Flags: `scanx --url https://github.com/org/repo` or `scanx --path ./myrepo`
  - Interactive: run `scanx` with no source flags and it will prompt.
"""

from __future__ import annotations

import argparse
import os
import sys

from scanx.config import (
    DEFAULT_CONCURRENCY,
    DEFAULT_LLM_MAX_RETRIES,
    DEFAULT_LLM_TIMEOUT_SECONDS,
    DEFAULT_MODEL_NAME,
    DEFAULT_OLLAMA_HOST,
    ScanConfig,
)
from scanx.logging_config import get_logger, setup_logging
from scanx.tools.repo_tools import RepoAcquisitionError
from scanx.workflow import ScanxWorkflow

log = get_logger("cli")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanx",
        description="Scanx — autonomous local-LLM security scanner for source repositories.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--url", help="Git URL to clone and scan.")
    source.add_argument("--path", help="Local path to an existing repository/directory to scan.")
    parser.add_argument(
        "--output-dir", default="reports", help="Directory to write reports/logs into."
    )
    parser.add_argument(
        "--provider",
        choices=["ollama", "openai"],
        default="ollama",
        help="Model backend to use (default: ollama).",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL_NAME,
        help=f"Model tag/name (default: {DEFAULT_MODEL_NAME}). For OpenAI use e.g. gpt-4o-mini.",
    )
    parser.add_argument(
        "--ollama-host", default=DEFAULT_OLLAMA_HOST, help=f"Ollama server URL (default: {DEFAULT_OLLAMA_HOST})"
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="OpenAI API key. If omitted, reads the OPENAI_API_KEY environment variable.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Max concurrent worker tasks hitting the model (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="Include test directories/files in the scan (excluded by default).",
    )
    parser.add_argument(
        "--keep-clone",
        action="store_true",
        help="Keep the cloned repo on disk after scanning (default: deleted automatically).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_LLM_TIMEOUT_SECONDS,
        help=f"Per-chunk model call timeout in seconds (default: {DEFAULT_LLM_TIMEOUT_SECONDS}). "
        "Raise this for larger/slower local models.",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=DEFAULT_LLM_MAX_RETRIES,
        help=f"Retries per chunk on timeout/failure before giving up (default: {DEFAULT_LLM_MAX_RETRIES}).",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug-level console logging.")
    return parser


def _prompt_for_source() -> tuple[str | None, str | None]:
    print("Scanx — Autonomous Security Scanner")
    print("What would you like to scan?")
    print("  1) A git repository URL (will be cloned)")
    print("  2) A local path already on disk")
    choice = input("Choose 1 or 2: ").strip()
    if choice == "1":
        url = input("Enter the git repository URL: ").strip()
        return url, None
    if choice == "2":
        path = input("Enter the local path: ").strip()
        return None, path
    print("Invalid choice.")
    sys.exit(1)


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose, log_dir=args.output_dir)

    url, path = args.url, args.path
    if not url and not path:
        url, path = _prompt_for_source()

    config = ScanConfig(
        provider=args.provider,
        model_name=args.model,
        ollama_host=args.ollama_host,
        openai_api_key=args.api_key or os.environ.get("OPENAI_API_KEY"),
        concurrency=args.concurrency,
        include_tests=args.include_tests,
        llm_timeout_seconds=args.timeout,
        llm_max_retries=args.max_retries,
    )

    workflow = ScanxWorkflow(config=config, output_dir=args.output_dir, keep_clone=args.keep_clone)

    try:
        report = workflow.run(url=url, local_path=path)
    except RepoAcquisitionError as exc:
        log.error("%s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        log.warning("Scan interrupted by user.")
        return 130

    counts = report.severity_counts
    print()
    print(f"Scan complete in {report.duration_seconds}s")
    print(
        f"Findings — critical: {counts['critical']}, high: {counts['high']}, "
        f"medium: {counts['medium']}, low: {counts['low']}, info: {counts['info']}"
    )
    print(f"Reports written to: {args.output_dir}/scanx-report.{{json,md}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
