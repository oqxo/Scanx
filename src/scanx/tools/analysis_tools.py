"""
scanx.tools.analysis_tools
=============================
Step 3 of the workflow: the actual "agent" part. Each discovered file is
split into chunks (scanx.tools.chunking) and every chunk is sent to the
local Ollama model concurrently, bounded by a worker-pool semaphore so we
don't overwhelm a single local model server.

Robustness notes:
  - The model is asked for STRICT JSON output. We still defensively extract
    the first well-formed JSON object/array from the response, because not
    every local model obeys formatting instructions perfectly.
  - Each chunk call is retried with exponential backoff on transient
    failures (timeouts, connection errors).
  - A failure on one file/chunk never aborts the run — it's recorded as an
    error on that FileAnalysisResult and the pool keeps going.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI

from scanx.config import ScanConfig
from scanx.logging_config import get_logger
from scanx.models import FileAnalysisResult, Finding, Severity
from scanx.tools.chunking import chunk_source, detect_language
from scanx.tools.discovery_tools import DiscoveredFile

log = get_logger("tools.analysis")

SYSTEM_PROMPT = """You are Scanx, an expert application security auditor performing static \
analysis on a single code chunk. You review code across all languages and infrastructure-as-\
code formats for real, exploitable security vulnerabilities and dangerous misconfigurations.

Focus areas: injection (SQL/command/LDAP/NoSQL/template), hardcoded credentials or secrets, \
broken authentication/authorization, insecure deserialization, SSRF, XSS, path traversal, \
insecure cryptography or randomness, unsafe use of eval/exec/reflection, XXE, insecure IaC \
(open security groups, public storage buckets, missing encryption, overly permissive IAM), \
CI/CD pipeline injection, and unsafe dependency/version pinning where evident in-file.

Rules:
- Only report issues you can actually justify from the given code. Do not invent line numbers \
you cannot see in the snippet.
- Do not report generic style/lint issues — security impact only.
- If you find nothing, return an empty findings list. An empty list is a valid, good result.
- Respond with STRICT JSON ONLY — no markdown fences, no prose before or after — matching \
exactly this schema:
{"findings": [{"title": str, "severity": "critical"|"high"|"medium"|"low"|"info", \
"category": str, "description": str, "line_start": int|null, "line_end": int|null, \
"code_snippet": str|null, "recommendation": str, "cwe_id": str|null, \
"confidence": "low"|"medium"|"high"}]}
"""

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json(raw_text: str) -> dict:
    """Defensively pull a JSON object out of a model response."""
    text = raw_text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).rstrip("`").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = _JSON_OBJECT_RE.search(text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    raise ValueError(f"Could not parse JSON from model response: {text[:200]!r}")


def _coerce_findings(payload: dict) -> list[Finding]:
    raw_findings = payload.get("findings", [])
    findings: list[Finding] = []
    for item in raw_findings:
        try:
            severity_raw = str(item.get("severity", "info")).lower()
            if severity_raw not in {s.value for s in Severity}:
                severity_raw = "info"
            findings.append(
                Finding(
                    title=str(item.get("title", "Untitled finding")),
                    severity=Severity(severity_raw),
                    category=str(item.get("category", "Uncategorized")),
                    description=str(item.get("description", "")),
                    line_start=item.get("line_start"),
                    line_end=item.get("line_end"),
                    code_snippet=item.get("code_snippet"),
                    recommendation=str(item.get("recommendation", "")),
                    cwe_id=item.get("cwe_id"),
                    confidence=str(item.get("confidence", "medium")),
                )
            )
        except Exception as exc:  # noqa: BLE001 - defensive, one bad item shouldn't drop the rest
            log.warning("Dropping malformed finding item %r: %s", item, exc)
    return findings


async def _analyze_chunk(
    llm: ChatOllama,
    file_rel_path: str,
    language: str | None,
    chunk_content: str,
    chunk_label: str,
    line_offset: int,
    config: ScanConfig,
) -> list[Finding]:
    user_prompt = (
        f"File: {file_rel_path}\n"
        f"Language: {language or 'unknown'}\n"
        f"Chunk: {chunk_label} (source lines start at {line_offset})\n\n"
        f"```\n{chunk_content}\n```"
    )

    last_exc: Exception | None = None
    for attempt in range(1, config.llm_max_retries + 2):
        try:
            response = await asyncio.wait_for(
                llm.ainvoke(
                    [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ]
                ),
                timeout=config.llm_timeout_seconds,
            )
            payload = _extract_json(response.content)
            findings = _coerce_findings(payload)
            for f in findings:
                f.file_path = file_rel_path
            return findings
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            wait = min(2**attempt, 20)
            log.warning(
                "Chunk analysis attempt %d/%d failed for %s (%s): %s — retrying in %ds",
                attempt,
                config.llm_max_retries + 1,
                file_rel_path,
                chunk_label,
                exc,
                wait,
            )
            await asyncio.sleep(wait)
    raise RuntimeError(f"Analysis failed after retries: {last_exc}") from last_exc


async def _analyze_file(
    llm: ChatOllama,
    file: DiscoveredFile,
    config: ScanConfig,
) -> FileAnalysisResult:
    start_time = time.monotonic()
    log.info("Analyzing %s (%d bytes)", file.relative_path, file.size_bytes)
    try:
        content = Path(file.absolute_path).read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        log.error("Could not read %s: %s", file.relative_path, exc)
        return FileAnalysisResult(file_path=file.relative_path, error=str(exc))

    language = detect_language(file.relative_path)
    chunks = chunk_source(
        content,
        language_hint=language,
        max_lines=config.chunk_max_lines,
        overlap_lines=config.chunk_overlap_lines,
    )

    all_findings: list[Finding] = []
    error: str | None = None
    for chunk in chunks:
        try:
            findings = await _analyze_chunk(
                llm,
                file.relative_path,
                language,
                chunk.content,
                chunk.label,
                chunk.line_start,
                config,
            )
            all_findings.extend(findings)
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
            log.error("Giving up on chunk %s of %s: %s", chunk.label, file.relative_path, exc)

    duration = round(time.monotonic() - start_time, 2)
    log.info(
        "Finished %s in %.2fs — %d chunk(s), %d finding(s)%s",
        file.relative_path,
        duration,
        len(chunks),
        len(all_findings),
        f" (with errors: {error})" if error else "",
    )
    return FileAnalysisResult(
        file_path=file.relative_path,
        language=language,
        chunks_analyzed=len(chunks),
        findings=all_findings,
        error=error,
        duration_seconds=duration,
    )


def _build_llm(config: ScanConfig) -> BaseChatModel:
    if config.provider == "openai":
        return ChatOpenAI(model=config.model_name, api_key=config.openai_api_key, temperature=0.1)
    return ChatOllama(model=config.model_name, base_url=config.ollama_host, temperature=0.1)


async def analyze_files_worker_pool(
    files: list[DiscoveredFile],
    config: ScanConfig,
) -> list[FileAnalysisResult]:
    """
    Analyze every discovered file concurrently, bounded by config.concurrency.
    This is the async worker-pool: a fixed number of "workers" (semaphore
    permits) pull files through _analyze_file at once.
    """
    llm = _build_llm(config)
    semaphore = asyncio.Semaphore(config.concurrency)

    async def _bounded(file: DiscoveredFile) -> FileAnalysisResult:
        async with semaphore:
            return await _analyze_file(llm, file, config)

    log.info(
        "Starting worker pool: %d file(s), concurrency=%d, model=%s",
        len(files),
        config.concurrency,
        config.model_name,
    )
    results = await asyncio.gather(*(_bounded(f) for f in files))
    return list(results)
