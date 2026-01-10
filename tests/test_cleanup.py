"""Tests for cleanup.py functionality."""

import json
import os
import time
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "plugins" / "log-cleaner" / "scripts"))

import cleanup
import config
import utils
import secret_scanner


class TestFormatSize:
    """Tests for format_size function."""

    def test_bytes(self):
        assert utils.format_size(0) == "0 B"
        assert utils.format_size(100) == "100 B"
        assert utils.format_size(1023) == "1023 B"

    def test_kilobytes(self):
        assert utils.format_size(1024) == "1.0 KB"
        assert utils.format_size(1536) == "1.5 KB"
        assert utils.format_size(10240) == "10.0 KB"

    def test_megabytes(self):
        assert utils.format_size(1024 * 1024) == "1.0 MB"
        assert utils.format_size(1024 * 1024 * 5) == "5.0 MB"

    def test_gigabytes(self):
        assert utils.format_size(1024 * 1024 * 1024) == "1.0 GB"


class TestConfig:
    """Tests for config loading and saving."""

    def test_load_config_default_when_missing(self, temp_claude_dir):
        """Should return defaults when config file doesn't exist."""
        loaded_config = config.load_config()
        assert loaded_config["retention_hours"] == 24
        assert loaded_config["clean_on_session_end"] is True
        assert loaded_config["dry_run"] is False

    def test_save_and_load_config(self, temp_claude_dir):
        """Should save and load config correctly."""
        test_config = {
            "retention_hours": 48,
            "clean_on_session_end": False,
            "dry_run": True,
        }
        config.save_config(test_config)

        loaded = config.load_config()
        assert loaded["retention_hours"] == 48
        assert loaded["clean_on_session_end"] is False
        assert loaded["dry_run"] is True

    def test_create_default_config(self, temp_claude_dir):
        """Should create default config file."""
        assert not config.CONFIG_FILE.exists()
        config.create_default_config()
        assert config.CONFIG_FILE.exists()

        with open(config.CONFIG_FILE) as f:
            loaded_config = json.load(f)
        assert loaded_config["retention_hours"] == 24


class TestFindOldFiles:
    """Tests for find_old_files function."""

    def test_empty_directory(self, temp_claude_dir):
        """Should return empty list for empty directory."""
        files = cleanup.find_old_files(temp_claude_dir / "debug", 24)
        assert files == []

    def test_finds_old_files(self, temp_claude_dir):
        """Should find files older than retention period."""
        debug_dir = temp_claude_dir / "debug"

        # Create a file and backdate it
        old_file = debug_dir / "old.log"
        old_file.write_text("old content")

        # Set mtime to 2 days ago
        old_time = time.time() - (48 * 3600)
        os.utime(old_file, (old_time, old_time))

        files = cleanup.find_old_files(debug_dir, 24)
        assert len(files) == 1
        assert files[0].name == "old.log"

    def test_ignores_new_files(self, temp_claude_dir):
        """Should ignore files newer than retention period."""
        debug_dir = temp_claude_dir / "debug"

        # Create a new file
        new_file = debug_dir / "new.log"
        new_file.write_text("new content")

        files = cleanup.find_old_files(debug_dir, 24)
        assert files == []

    def test_nonexistent_directory(self, temp_claude_dir):
        """Should return empty list for nonexistent directory."""
        files = cleanup.find_old_files(temp_claude_dir / "nonexistent", 24)
        assert files == []


class TestCleanDirectory:
    """Tests for clean_directory function."""

    def test_clean_old_files(self, temp_claude_dir):
        """Should delete old files."""
        debug_dir = temp_claude_dir / "debug"

        # Create and backdate a file
        old_file = debug_dir / "old.log"
        old_file.write_text("old content")
        old_time = time.time() - (48 * 3600)
        os.utime(old_file, (old_time, old_time))

        count, size = cleanup.clean_directory("debug", 24, dry_run=False)

        assert count == 1
        assert not old_file.exists()

    def test_dry_run_preserves_files(self, temp_claude_dir):
        """Should not delete files in dry run mode."""
        debug_dir = temp_claude_dir / "debug"

        # Create and backdate a file
        old_file = debug_dir / "old.log"
        old_file.write_text("old content")
        old_time = time.time() - (48 * 3600)
        os.utime(old_file, (old_time, old_time))

        count, size = cleanup.clean_directory("debug", 24, dry_run=True)

        assert count == 1
        assert old_file.exists()  # File should still exist

    def test_preserves_new_files(self, temp_claude_dir):
        """Should preserve files newer than retention period."""
        debug_dir = temp_claude_dir / "debug"

        # Create a new file
        new_file = debug_dir / "new.log"
        new_file.write_text("new content")

        count, size = cleanup.clean_directory("debug", 24, dry_run=False)

        assert count == 0
        assert new_file.exists()


class TestSecretPatterns:
    """Tests for built-in secret detection patterns."""

    def test_openai_key_pattern(self):
        """Should match OpenAI API keys."""
        import re
        pattern = re.compile(secret_scanner.BUILTIN_PATTERNS["OpenAI/Anthropic API Keys"])

        assert pattern.search("sk-1234567890abcdefghij")
        assert pattern.search("sk-proj-" + "a" * 50)
        assert pattern.search("sk-ant-api03-" + "a" * 20)
        assert not pattern.search("sk-short")

    def test_github_token_pattern(self):
        """Should match GitHub tokens."""
        import re
        pattern = re.compile(secret_scanner.BUILTIN_PATTERNS["GitHub Tokens"])

        assert pattern.search("ghp_" + "a" * 36)
        assert pattern.search("gho_" + "a" * 36)
        assert pattern.search("github_pat_" + "a" * 22)
        assert not pattern.search("ghp_short")

    def test_aws_key_pattern(self):
        """Should match AWS access keys."""
        import re
        pattern = re.compile(secret_scanner.BUILTIN_PATTERNS["AWS Keys"])

        assert pattern.search("AKIAIOSFODNN7EXAMPLE")
        assert not pattern.search("AKIA123")  # Too short

    def test_posthog_key_pattern(self):
        """Should match PostHog keys."""
        import re
        pattern = re.compile(secret_scanner.BUILTIN_PATTERNS["PostHog Keys"])

        assert pattern.search("phc_" + "a" * 30)
        assert pattern.search("phx_" + "a" * 30)
        assert not pattern.search("phc_short")


class TestDirectoryStats:
    """Tests for get_directory_stats function."""

    def test_empty_directory(self, temp_claude_dir):
        """Should return zeros for empty directory."""
        count, size = cleanup.get_directory_stats(temp_claude_dir / "debug")
        assert count == 0
        assert size == 0

    def test_counts_files_and_size(self, temp_claude_dir):
        """Should count files and sum sizes."""
        debug_dir = temp_claude_dir / "debug"

        # Create some files
        (debug_dir / "file1.log").write_text("content1")
        (debug_dir / "file2.log").write_text("content2content2")

        count, size = cleanup.get_directory_stats(debug_dir)
        assert count == 2
        assert size == len("content1") + len("content2content2")

    def test_nonexistent_directory(self, temp_claude_dir):
        """Should return zeros for nonexistent directory."""
        count, size = cleanup.get_directory_stats(temp_claude_dir / "nonexistent")
        assert count == 0
        assert size == 0
