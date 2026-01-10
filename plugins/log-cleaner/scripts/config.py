"""
Configuration management for Claude Code Log Cleaner.
Handles config file I/O and default values.
"""

import json
from pathlib import Path
from typing import Dict

from utils import log_error, log_info, log_warn

# Configuration paths
CLAUDE_DIR = Path.home() / ".claude"
CONFIG_FILE = CLAUDE_DIR / "log-cleaner-config.json"
DEFAULT_RETENTION_HOURS = 24

# Directories to clean (relative to CLAUDE_DIR)
CLEAN_DIRS = [
    "debug",
    "file-history",
    "projects",
    "todos",
    "plans",
    "shell-snapshots",
]


def load_config() -> Dict:
    """Load config from file, returning defaults if not found."""
    default_config = {
        "retention_hours": DEFAULT_RETENTION_HOURS,
        "clean_on_session_end": True,
        "dry_run": False,
    }

    if not CONFIG_FILE.exists():
        return default_config

    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            # Merge with defaults to handle missing keys
            return {**default_config, **config}
    except (json.JSONDecodeError, IOError) as e:
        log_warn(f"Could not read config: {e}")
        return default_config


def save_config(config: Dict) -> None:
    """Save config to file with atomic write."""
    # Ensure parent directory exists
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Write to temp file then rename for atomicity
    tmp_file = CONFIG_FILE.with_suffix(".tmp")
    try:
        with open(tmp_file, "w") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
        tmp_file.rename(CONFIG_FILE)
    except IOError as e:
        log_error(f"Could not save config: {e}")
        if tmp_file.exists():
            tmp_file.unlink()


def create_default_config() -> None:
    """Create default config if it doesn't exist."""
    if not CONFIG_FILE.exists():
        config = {
            "retention_hours": DEFAULT_RETENTION_HOURS,
            "clean_on_session_end": True,
            "dry_run": False,
        }
        save_config(config)
        log_info(f"Created default config at {CONFIG_FILE}")
