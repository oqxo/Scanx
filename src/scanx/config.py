"""
scanx.config
============
Single source of truth for every "what NOT to scan" rule, plus tunables
(concurrency, chunk sizes, model name, etc).

Design principle: Scanx is an ALLOWLIST-first scanner for source code, layered
with explicit DENYLISTS for directories/files that commonly slip through an
extension-only filter (lockfiles with source-like extensions, vendored trees,
etc). A file only gets scanned if it survives both filters *and* isn't
excluded by .gitignore.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Directories we NEVER descend into, regardless of language/ecosystem.
# Matched by directory *name* (case-sensitive), anywhere in the tree.
# --------------------------------------------------------------------------
EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        # VCS internals
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        # Virtual envs / package caches (Python)
        ".venv",
        "venv",
        "env",
        ".env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "site-packages",
        # Node / JS / TS
        "node_modules",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".angular",
        ".parcel-cache",
        ".turbo",
        "bower_components",
        # Java / Kotlin / Scala / Gradle / Maven
        "target",
        ".gradle",
        "out",
        # Rust
        # ("target" already covered above — also used by Rust/Cargo)
        # Go
        "vendor",
        # .NET / C#
        "bin",
        "obj",
        "packages",
        # C / C++
        "cmake-build-debug",
        "cmake-build-release",
        # Swift / iOS / macOS
        "Pods",
        "DerivedData",
        ".build",
        # Dart / Flutter
        ".dart_tool",
        ".pub-cache",
        # PHP
        # ("vendor" already covered above)
        # IDE / editor
        ".idea",
        ".vscode",
        ".vs",
        ".fleet",
        # Build / dist output (generic, cross-language)
        "dist",
        "build",
        "builds",
        "out-tsc",
        "coverage",
        ".coverage",
        # IaC / infra tool caches
        ".terraform",
        ".terragrunt-cache",
        ".serverless",
        ".pulumi",
        "cdk.out",
        ".aws-sam",
        # Docs / non-source content the user explicitly called out
        "docs",
        "doc",
        "documentation",
        # Tests — excluded by default, toggle via --include-tests
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        # Misc caches
        ".cache",
        ".sass-cache",
        "tmp",
        "temp",
    }
)

# Directory-name patterns handled separately because they're prefix-based
# (e.g. CLion/CMake build dirs are often "cmake-build-*").
EXCLUDED_DIR_NAME_PREFIXES: tuple[str, ...] = ("cmake-build-",)

# Any directory whose name starts with "." is hidden -> always excluded,
# EXCEPT the ones explicitly allowlisted here because they routinely contain
# security-relevant config (CI pipelines, GitHub Actions workflows, etc).
HIDDEN_DIR_ALLOWLIST: frozenset[str] = frozenset(
    {
        ".github",  # GitHub Actions workflows — common source of CI/CD secrets & injection bugs
        ".azure-pipelines",
        ".circleci",
        ".gitlab",
    }
)

# --------------------------------------------------------------------------
# Exact filenames we never scan — dependency manifests / lockfiles / non-code.
# These describe dependencies, not logic, and are SCA (software composition
# analysis) territory, not SAST — explicitly out of scope per project spec.
# --------------------------------------------------------------------------
EXCLUDED_FILE_NAMES: frozenset[str] = frozenset(
    {
        # JS/Node
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
        # Python
        "requirements.txt",
        "requirements-dev.txt",
        "poetry.lock",
        "pipfile.lock",
        "uv.lock",
        # Rust
        "cargo.lock",
        # Go
        "go.sum",
        # Java / Maven / Gradle
        "pom.xml",
        "gradle.lockfile",
        # Ruby
        "gemfile.lock",
        # PHP
        "composer.lock",
        # .NET
        "packages.lock.json",
        # Dart/Flutter
        "pubspec.lock",
        # Misc
        ".ds_store",
        "thumbs.db",
    }
)

# --------------------------------------------------------------------------
# Extensions we never scan (binary, media, docs, generated data).
# --------------------------------------------------------------------------
EXCLUDED_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Docs / text
        ".md",
        ".markdown",
        ".rst",
        ".txt",
        ".adoc",
        # Images
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".svg",
        ".webp",
        ".tiff",
        # Audio/video
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
        ".wav",
        # Fonts
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        # Archives / binaries
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".rar",
        ".7z",
        ".jar",
        ".war",
        ".class",
        ".pyc",
        ".pyo",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".bin",
        ".o",
        ".a",
        # Data dumps / logs (rarely "logic", high noise)
        ".log",
        ".csv",
        ".tsv",
        ".parquet",
        # Lockfile-ish extension caught generically
        ".lock",
        # PDFs
        ".pdf",
    }
)

# --------------------------------------------------------------------------
# Allowlisted source-code / IaC / config extensions. If a file survives the
# deny rules above, it must ALSO match one of these to be scanned.
# Bare filenames without an extension (Dockerfile, Makefile, Jenkinsfile) are
# handled via EXTENSIONLESS_ALLOWLIST below.
# --------------------------------------------------------------------------
INCLUDED_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Python
        ".py",
        ".pyi",
        # JS/TS
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        # JVM
        ".java",
        ".kt",
        ".kts",
        ".scala",
        ".groovy",
        # Go
        ".go",
        # Rust
        ".rs",
        # Ruby
        ".rb",
        ".erb",
        # PHP
        ".php",
        # C family
        ".c",
        ".h",
        ".cpp",
        ".cc",
        ".cxx",
        ".hpp",
        ".hxx",
        # C#
        ".cs",
        ".razor",
        ".cshtml",
        # Swift / Obj-C
        ".swift",
        ".m",
        ".mm",
        # Shell
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        # Perl
        ".pl",
        ".pm",
        # SQL
        ".sql",
        # Terraform / IaC
        ".tf",
        ".tfvars",
        ".bicep",
        # Config / CI-CD / IaC-as-YAML (Kubernetes, Azure Pipelines, GitHub
        # Actions, Ansible, Helm, docker-compose, etc). High signal for
        # secrets & misconfig, deliberately NOT excluded like other config.
        ".yaml",
        ".yml",
        # App/service configs — deliberately narrow; package manifests are
        # excluded by exact filename above even though they share ".json".
        ".json",
        ".env",
        ".ini",
        ".cfg",
        ".conf",
        # HTML/templates (XSS surface)
        ".html",
        ".htm",
        ".ejs",
        ".hbs",
    }
)

# Extensionless filenames that are still very much "source" for our purposes.
EXTENSIONLESS_ALLOWLIST: frozenset[str] = frozenset(
    {
        "dockerfile",
        "makefile",
        "jenkinsfile",
        "vagrantfile",
        "rakefile",
        "gemfile",
    }
)

# --------------------------------------------------------------------------
# Tunables
# --------------------------------------------------------------------------
DEFAULT_MODEL_NAME = "ornith:9b"
DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_CONCURRENCY = 4
DEFAULT_MAX_FILE_BYTES = 1_500_000  # skip anything absurdly large (likely generated/data)
DEFAULT_CHUNK_MAX_LINES = 300       # above this, a file gets AST/line chunked
DEFAULT_CHUNK_OVERLAP_LINES = 15
DEFAULT_LLM_TIMEOUT_SECONDS = 120
DEFAULT_LLM_MAX_RETRIES = 2


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Runtime-tunable scan configuration (CLI flags map onto this)."""

    provider: str = "ollama"  # "ollama" | "openai"
    model_name: str = DEFAULT_MODEL_NAME
    ollama_host: str = DEFAULT_OLLAMA_HOST
    openai_api_key: str | None = None
    concurrency: int = DEFAULT_CONCURRENCY
    include_tests: bool = False
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    chunk_max_lines: int = DEFAULT_CHUNK_MAX_LINES
    chunk_overlap_lines: int = DEFAULT_CHUNK_OVERLAP_LINES
    llm_timeout_seconds: int = DEFAULT_LLM_TIMEOUT_SECONDS
    llm_max_retries: int = DEFAULT_LLM_MAX_RETRIES
    extra_exclude_dirs: frozenset[str] = field(default_factory=frozenset)
    extra_exclude_globs: frozenset[str] = field(default_factory=frozenset)

    def effective_excluded_dirs(self) -> frozenset[str]:
        base = set(EXCLUDED_DIR_NAMES)
        if self.include_tests:
            base -= {"test", "tests", "__tests__", "spec", "specs"}
        return frozenset(base | self.extra_exclude_dirs)
