"""
scanx.tools.chunking
======================
Large files are split into smaller, semantically-bounded chunks before
being handed to the model:
  - Keeps each request within the model's effective context window.
  - Splitting on function/class boundaries (where we can parse them) gives
    the model coherent units instead of arbitrary line cuts through the
    middle of a function, improving finding quality.
  - For files under the line threshold, or languages we can't parse
    structurally, we fall back to a simple line-window chunker with a small
    overlap so a vulnerability spanning a chunk boundary isn't missed.

Only Python gets true AST-based splitting here (via the stdlib `ast` module,
no extra dependency). Everything else uses the line-window fallback — this
is intentionally extensible: add a language-specific splitter and register
it in AST_SPLITTERS to get the same treatment for other languages.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from scanx.logging_config import get_logger

log = get_logger("tools.chunking")


@dataclass
class CodeChunk:
    content: str
    line_start: int
    line_end: int
    label: str = ""  # e.g. "function foo", "class Bar", "lines 1-300"


def _python_ast_chunks(source: str, max_lines: int) -> list[CodeChunk] | None:
    """Split Python source on top-level function/class boundaries."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        log.debug("AST parse failed, falling back to line chunking: %s", exc)
        return None

    lines = source.splitlines()
    top_level_nodes = [
        n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    if not top_level_nodes:
        return None

    chunks: list[CodeChunk] = []
    top_level_nodes.sort(key=lambda n: n.lineno)

    # Anything before the first def/class (imports, module-level constants,
    # config) is security-relevant too (e.g. hardcoded secrets) — keep it
    # as its own leading chunk.
    first_start = top_level_nodes[0].lineno
    if first_start > 1:
        preamble = "\n".join(lines[: first_start - 1]).strip()
        if preamble:
            chunks.append(CodeChunk(preamble, 1, first_start - 1, "module preamble"))

    for node in top_level_nodes:
        start = node.lineno
        end = getattr(node, "end_lineno", None) or start
        segment = "\n".join(lines[start - 1 : end])
        kind = "class" if isinstance(node, ast.ClassDef) else "function"
        chunks.append(CodeChunk(segment, start, end, f"{kind} {node.name}"))

    # Merge tiny adjacent chunks so we don't fire off 40 requests for 40
    # three-line functions; cap merged size at max_lines.
    merged: list[CodeChunk] = []
    for c in chunks:
        if merged and (merged[-1].line_end - merged[-1].line_start) + (
            c.line_end - c.line_start
        ) < max_lines:
            prev = merged[-1]
            merged[-1] = CodeChunk(
                prev.content + "\n\n" + c.content,
                prev.line_start,
                c.line_end,
                f"{prev.label}, {c.label}",
            )
        else:
            merged.append(c)

    return merged


def _line_window_chunks(source: str, max_lines: int, overlap: int) -> list[CodeChunk]:
    lines = source.splitlines()
    if not lines:
        return []
    chunks: list[CodeChunk] = []
    start = 0
    n = len(lines)
    while start < n:
        end = min(start + max_lines, n)
        segment = "\n".join(lines[start:end])
        chunks.append(CodeChunk(segment, start + 1, end, f"lines {start + 1}-{end}"))
        if end == n:
            break
        start = end - overlap if end - overlap > start else end
    return chunks


def chunk_source(
    source: str,
    *,
    language_hint: str | None,
    max_lines: int,
    overlap_lines: int,
) -> list[CodeChunk]:
    """Split source into analyzable chunks. Returns a single chunk if small enough."""
    total_lines = source.count("\n") + 1
    if total_lines <= max_lines:
        return [CodeChunk(source, 1, total_lines, "whole file")]

    if language_hint == "python":
        ast_chunks = _python_ast_chunks(source, max_lines)
        if ast_chunks:
            log.debug("AST-chunked python file into %d chunk(s).", len(ast_chunks))
            return ast_chunks

    return _line_window_chunks(source, max_lines, overlap_lines)


LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".m": "objective-c",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".html": "html",
    ".htm": "html",
}


def detect_language(file_path: str) -> str | None:
    from pathlib import Path

    suffix = Path(file_path).suffix.lower()
    if suffix:
        return LANGUAGE_BY_EXTENSION.get(suffix)
    name = Path(file_path).name.lower()
    if name == "dockerfile":
        return "dockerfile"
    return None
