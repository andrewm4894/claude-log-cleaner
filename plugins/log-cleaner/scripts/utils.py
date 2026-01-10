"""
Utility functions for Claude Code Log Cleaner.
Provides logging and formatting helpers.
"""

import sys

# ANSI colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"  # No Color


def log_info(msg: str) -> None:
    """Log an info message to stderr."""
    print(f"{GREEN}[INFO]{NC} {msg}", file=sys.stderr)


def log_warn(msg: str) -> None:
    """Log a warning message to stderr."""
    print(f"{YELLOW}[WARN]{NC} {msg}", file=sys.stderr)


def log_error(msg: str) -> None:
    """Log an error message to stderr."""
    print(f"{RED}[ERROR]{NC} {msg}", file=sys.stderr)


def format_size(size_bytes: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"
