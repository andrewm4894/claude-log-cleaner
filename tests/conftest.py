"""Pytest fixtures for claude-log-cleaner tests."""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add the scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "plugins" / "log-cleaner" / "scripts"))


@pytest.fixture
def temp_claude_dir(tmp_path, monkeypatch):
    """Create a temporary .claude directory structure for testing."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()

    # Create subdirectories
    for subdir in ["debug", "file-history", "projects", "todos", "plans", "shell-snapshots"]:
        (claude_dir / subdir).mkdir()

    # Patch the CLAUDE_DIR in the cleanup module
    import cleanup
    monkeypatch.setattr(cleanup, "CLAUDE_DIR", claude_dir)
    monkeypatch.setattr(cleanup, "CONFIG_FILE", claude_dir / "log-cleaner-config.json")

    return claude_dir


@pytest.fixture
def sample_config():
    """Return a sample config dict."""
    return {
        "retention_hours": 24,
        "clean_on_session_end": True,
        "dry_run": False,
    }
