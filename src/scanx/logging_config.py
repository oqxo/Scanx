"""
scanx.logging_config
=====================
Centralized, auditable logging setup. Every stage of the pipeline logs
through the "scanx.*" logger hierarchy so a single log file gives a full,
timestamped audit trail of what was scanned, skipped, and found — important
for a security tool where "what did it actually look at" must be answerable.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    verbose: bool = False,
    log_dir: str | Path = "reports",
    log_filename: str = "scanx.log",
) -> logging.Logger:
    """Configure root 'scanx' logger with console + rotating file handlers.

    Idempotent: calling this more than once won't duplicate handlers.
    """
    logger = logging.getLogger("scanx")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger  # already configured

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    try:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path / log_filename, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # If we can't write logs to disk, still proceed with console-only logging.
        logger.warning("Could not set up file logging in %s; continuing console-only.", log_dir)

    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"scanx.{name}")
