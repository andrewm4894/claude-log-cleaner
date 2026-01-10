"""
End-to-end tests for secret detection with realistic Claude log files.

These tests create mock log files that resemble actual Claude Code session logs
and verify that the secret detection correctly identifies exposed credentials.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Set

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "plugins" / "log-cleaner" / "scripts"))

import cleanup


# =============================================================================
# Helper functions
# =============================================================================


def secret_found_in_results(secret: str, results: Dict[str, Set[str]]) -> bool:
    """Check if a secret is found anywhere in the results dict."""
    for key, values in results.items():
        if secret in values:
            return True
    return False


def any_secrets_found(results: Dict[str, Set[str]]) -> int:
    """Count total secrets found across all result keys."""
    total = 0
    for key, values in results.items():
        total += len(values)
    return total


# =============================================================================
# Fake secrets for testing (these are NOT real credentials)
# These are intentionally constructed to match our detection patterns
# but are clearly fake/example values that won't work with any service.
# =============================================================================

# Build fake secrets dynamically to avoid triggering GitHub push protection
# while still matching our detection regex patterns
# Note: These use mixed characters to satisfy detect-secrets entropy checks
FAKE_SECRETS = {
    "openai_key": "sk-proj-" + "TESTKEY" * 8,  # 56 chars after prefix
    "anthropic_key": "sk-ant-api03-" + "FAKEKEY" * 4,  # Matches pattern
    "github_pat": "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xYz",  # 36 mixed chars after prefix
    "github_oauth": "gho_Za9Yb8Xc7Wd6Ve5Uf4Tg3Sh2Ri1Qj0Pk9OlN",  # 36 mixed chars after prefix
    "aws_access_key": "AKIAZ9Y8X7W6V5U4T3S2",  # 20 chars, starts with AKIA
    "posthog_key": "phc_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tUv",  # 30 mixed chars after prefix
    "slack_bot_token": "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    "bearer_token": "Bearer aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3x",  # 36 mixed chars
    "private_key": """-----BEGIN RSA PRIVATE KEY-----
FAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEY
This is a fake key for testing secret detection only
FAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEY
-----END RSA PRIVATE KEY-----""",
}


# =============================================================================
# Realistic Claude log file content generators
# =============================================================================


def create_jsonl_session_log(messages: List[Dict]) -> str:
    """Create a JSONL session log file content."""
    return "\n".join(json.dumps(msg) for msg in messages)


def create_conversation_message(role: str, content: str) -> Dict:
    """Create a conversation message entry."""
    return {
        "type": "message",
        "role": role,
        "content": content,
        "timestamp": "2024-01-15T10:30:00Z",
    }


def create_tool_use_message(tool_name: str, input_data: Dict, output: str) -> Dict:
    """Create a tool use entry (like Bash command execution)."""
    return {
        "type": "tool_use",
        "tool": tool_name,
        "input": input_data,
        "output": output,
        "timestamp": "2024-01-15T10:31:00Z",
    }


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_claude_logs(tmp_path):
    """
    Create a realistic mock Claude log directory structure with various log files.

    Returns the base claude directory and a dict of what secrets are in which files.
    """
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()

    # Create all standard directories
    for subdir in ["debug", "file-history", "projects", "todos", "plans", "shell-snapshots"]:
        (claude_dir / subdir).mkdir()

    # Track what secrets are where
    secret_locations = {}

    # === 1. Session log with OpenAI key in environment variable discussion ===
    projects_dir = claude_dir / "projects" / "my-project"
    projects_dir.mkdir(parents=True)

    session_with_openai = create_jsonl_session_log([
        create_conversation_message("user", "Can you help me set up the OpenAI API?"),
        create_conversation_message("assistant", "Sure! First, set your API key as an environment variable."),
        create_tool_use_message("Bash", {"command": "echo $OPENAI_API_KEY"}, FAKE_SECRETS["openai_key"]),
        create_conversation_message("assistant", "I see your API key is configured. Let me test it."),
    ])
    log_file = projects_dir / "session-abc123.jsonl"
    log_file.write_text(session_with_openai)
    secret_locations["openai"] = str(log_file)

    # === 2. Debug log with Anthropic key leaked in error message ===
    debug_log_content = f"""[DEBUG] 2024-01-15 10:30:00 - Starting session
[DEBUG] 2024-01-15 10:30:01 - Loading configuration
[ERROR] 2024-01-15 10:30:02 - API request failed with key: {FAKE_SECRETS["anthropic_key"]}
[DEBUG] 2024-01-15 10:30:03 - Retrying request...
"""
    debug_file = claude_dir / "debug" / "debug-2024-01-15.log"
    debug_file.write_text(debug_log_content)
    secret_locations["anthropic"] = str(debug_file)

    # === 3. Session with GitHub token in git command ===
    session_with_github = create_jsonl_session_log([
        create_conversation_message("user", "Push my changes to GitHub"),
        create_tool_use_message(
            "Bash",
            {"command": "git push"},
            f"remote: Invalid credentials for 'https://{FAKE_SECRETS['github_pat']}@github.com/user/repo.git'"
        ),
        create_conversation_message("assistant", "It looks like there was an authentication issue."),
    ])
    github_log = projects_dir / "session-def456.jsonl"
    github_log.write_text(session_with_github)
    secret_locations["github"] = str(github_log)

    # === 4. File history with AWS credentials ===
    file_history_content = f"""
# AWS Configuration backup
[default]
aws_access_key_id = {FAKE_SECRETS["aws_access_key"]}
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
    file_history = claude_dir / "file-history" / "aws-credentials.backup"
    file_history.write_text(file_history_content)
    secret_locations["aws"] = str(file_history)

    # === 5. Session with PostHog analytics key ===
    session_with_posthog = create_jsonl_session_log([
        create_conversation_message("user", "Set up PostHog analytics"),
        create_conversation_message("assistant", "I'll configure PostHog with your project key."),
        create_tool_use_message(
            "Write",
            {"path": "analytics.js"},
            f"posthog.init('{FAKE_SECRETS['posthog_key']}')"
        ),
    ])
    posthog_log = projects_dir / "session-ghi789.jsonl"
    posthog_log.write_text(session_with_posthog)
    secret_locations["posthog"] = str(posthog_log)

    # === 6. Slack token in shell snapshot ===
    shell_snapshot = f"""
SLACK_BOT_TOKEN={FAKE_SECRETS["slack_bot_token"]}
PATH=/usr/bin:/bin
HOME=/Users/developer
"""
    snapshot_file = claude_dir / "shell-snapshots" / "env-snapshot.txt"
    snapshot_file.write_text(shell_snapshot)
    secret_locations["slack"] = str(snapshot_file)

    # === 7. Bearer token in API response ===
    session_with_bearer = create_jsonl_session_log([
        create_conversation_message("user", "Test the API endpoint"),
        create_tool_use_message(
            "Bash",
            {"command": "curl -H 'Authorization: ...' https://api.example.com"},
            f"Authorization header: {FAKE_SECRETS['bearer_token']}"
        ),
    ])
    bearer_log = projects_dir / "session-jkl012.jsonl"
    bearer_log.write_text(session_with_bearer)
    secret_locations["bearer"] = str(bearer_log)

    # === 8. Private key in plans directory ===
    plan_with_key = f"""
# Deployment Plan

## SSH Key for server access
{FAKE_SECRETS["private_key"]}

## Steps
1. Connect to server
2. Deploy application
"""
    plan_file = claude_dir / "plans" / "deployment-plan.md"
    plan_file.write_text(plan_with_key)
    secret_locations["private_key"] = str(plan_file)

    # === 9. Clean file (no secrets) - for comparison ===
    clean_session = create_jsonl_session_log([
        create_conversation_message("user", "Help me write a hello world program"),
        create_conversation_message("assistant", "Here's a simple Python hello world:"),
        create_tool_use_message("Write", {"path": "hello.py"}, "print('Hello, World!')"),
    ])
    clean_log = projects_dir / "session-clean.jsonl"
    clean_log.write_text(clean_session)

    return claude_dir, secret_locations


# =============================================================================
# Tests
# =============================================================================


class TestSecretDetectionEndToEnd:
    """End-to-end tests for secret detection in realistic log files."""

    def test_detects_openai_key(self, mock_claude_logs):
        """Should detect OpenAI API key in session log."""
        claude_dir, _ = mock_claude_logs
        results = cleanup.find_secrets_in_directories([claude_dir / "projects"])

        assert secret_found_in_results(FAKE_SECRETS["openai_key"], results)

    def test_detects_anthropic_key(self, mock_claude_logs):
        """Should detect Anthropic API key in debug log."""
        claude_dir, _ = mock_claude_logs
        results = cleanup.find_secrets_in_directories([claude_dir / "debug"])

        assert secret_found_in_results(FAKE_SECRETS["anthropic_key"], results)

    def test_detects_github_token(self, mock_claude_logs):
        """Should detect GitHub PAT in git error output."""
        claude_dir, _ = mock_claude_logs
        results = cleanup.find_secrets_in_directories([claude_dir / "projects"])

        assert secret_found_in_results(FAKE_SECRETS["github_pat"], results)

    def test_detects_aws_key(self, mock_claude_logs):
        """Should detect AWS access key in file history."""
        claude_dir, _ = mock_claude_logs
        results = cleanup.find_secrets_in_directories([claude_dir / "file-history"])

        assert secret_found_in_results(FAKE_SECRETS["aws_access_key"], results)

    def test_detects_posthog_key(self, mock_claude_logs):
        """Should detect PostHog project key."""
        claude_dir, _ = mock_claude_logs
        results = cleanup.find_secrets_in_directories([claude_dir / "projects"])

        assert secret_found_in_results(FAKE_SECRETS["posthog_key"], results)

    def test_detects_slack_token(self, mock_claude_logs):
        """Should detect Slack bot token in shell snapshot."""
        claude_dir, _ = mock_claude_logs
        results = cleanup.find_secrets_in_directories([claude_dir / "shell-snapshots"])

        assert secret_found_in_results(FAKE_SECRETS["slack_bot_token"], results)

    def test_detects_bearer_token(self, mock_claude_logs):
        """Should detect Bearer token in API response."""
        claude_dir, _ = mock_claude_logs
        results = cleanup.find_secrets_in_directories([claude_dir / "projects"])

        assert secret_found_in_results(FAKE_SECRETS["bearer_token"], results)

    def test_detects_private_key_file(self, mock_claude_logs):
        """Should detect file containing private key."""
        claude_dir, secret_locations = mock_claude_logs
        results = cleanup.find_secrets_in_directories([claude_dir / "plans"])

        assert secret_locations["private_key"] in results["Private Key Files"]

    def test_scans_all_directories(self, mock_claude_logs):
        """Should find secrets across all Claude directories."""
        claude_dir, _ = mock_claude_logs

        # Scan all directories at once
        all_dirs = [claude_dir / d for d in cleanup.CLEAN_DIRS]
        results = cleanup.find_secrets_in_directories(all_dirs)

        # Verify we found multiple types of secrets
        # With detect-secrets, keys may be under different names
        assert secret_found_in_results(FAKE_SECRETS["openai_key"], results)
        assert secret_found_in_results(FAKE_SECRETS["github_pat"], results)
        assert secret_found_in_results(FAKE_SECRETS["aws_access_key"], results)
        assert secret_found_in_results(FAKE_SECRETS["posthog_key"], results)
        assert secret_found_in_results(FAKE_SECRETS["slack_bot_token"], results)
        assert len(results["Private Key Files"]) >= 1

    def test_empty_directory_returns_empty_results(self, tmp_path):
        """Should return empty sets for directory with no secrets."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        (empty_dir / "clean.txt").write_text("No secrets here, just regular content.")

        results = cleanup.find_secrets_in_directories([empty_dir])

        assert any_secrets_found(results) == 0

    def test_nonexistent_directory_handled(self, tmp_path):
        """Should handle nonexistent directories gracefully."""
        results = cleanup.find_secrets_in_directories([tmp_path / "nonexistent"])

        assert any_secrets_found(results) == 0


class TestSecretPatternEdgeCases:
    """Test edge cases and pattern boundaries."""

    def test_short_key_not_matched(self, tmp_path):
        """Keys shorter than minimum length should not match."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "short.txt").write_text("sk-short ghp_short AKIA123")

        results = cleanup.find_secrets_in_directories([test_dir])

        # Short keys shouldn't match any pattern
        assert any_secrets_found(results) == 0

    def test_bearer_redacted_filtered(self, tmp_path):
        """Bearer tokens marked as Redacted should be filtered out."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "redacted.txt").write_text("Bearer [Redacted-token-placeholder-here]")

        results = cleanup.find_secrets_in_directories([test_dir])

        # Redacted tokens should not be found
        assert not secret_found_in_results("Bearer [Redacted-token-placeholder-here]", results)

    def test_multiple_secrets_same_file(self, tmp_path):
        """Should find multiple different secrets in the same file."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        content = f"""
API_KEY={FAKE_SECRETS["openai_key"]}
GITHUB_TOKEN={FAKE_SECRETS["github_pat"]}
AWS_KEY={FAKE_SECRETS["aws_access_key"]}
"""
        (test_dir / "multi.env").write_text(content)

        results = cleanup.find_secrets_in_directories([test_dir])

        assert secret_found_in_results(FAKE_SECRETS["openai_key"], results)
        assert secret_found_in_results(FAKE_SECRETS["github_pat"], results)
        assert secret_found_in_results(FAKE_SECRETS["aws_access_key"], results)

    def test_deduplicates_same_secret(self, tmp_path):
        """Same secret in multiple files should appear once in results."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()

        # Write same secret to multiple files
        for i in range(3):
            (test_dir / f"file{i}.txt").write_text(FAKE_SECRETS["openai_key"])

        results = cleanup.find_secrets_in_directories([test_dir])

        # Should only appear once (it's a set)
        assert secret_found_in_results(FAKE_SECRETS["openai_key"], results)
        # Count occurrences across all result keys - should be 1
        count = sum(1 for vals in results.values() if FAKE_SECRETS["openai_key"] in vals)
        assert count == 1


class TestRealisticScenarios:
    """Test scenarios that mimic real-world usage."""

    def test_env_file_leaked_in_session(self, tmp_path):
        """Simulate a user accidentally cat'ing their .env file."""
        test_dir = tmp_path / "projects"
        test_dir.mkdir()

        session = create_jsonl_session_log([
            create_conversation_message("user", "Show me my environment variables"),
            create_tool_use_message("Bash", {"command": "cat .env"}, f"""
DATABASE_URL=postgres://localhost/mydb
OPENAI_API_KEY={FAKE_SECRETS["openai_key"]}
GITHUB_TOKEN={FAKE_SECRETS["github_pat"]}
SECRET_KEY=not-a-real-pattern-match
"""),
        ])
        (test_dir / "session.jsonl").write_text(session)

        results = cleanup.find_secrets_in_directories([test_dir])

        assert secret_found_in_results(FAKE_SECRETS["openai_key"], results)
        assert secret_found_in_results(FAKE_SECRETS["github_pat"], results)

    def test_curl_command_with_auth(self, tmp_path):
        """Simulate a curl command that includes auth token."""
        test_dir = tmp_path / "projects"
        test_dir.mkdir()

        session = create_jsonl_session_log([
            create_conversation_message("user", "Test the Anthropic API"),
            create_tool_use_message(
                "Bash",
                {"command": "curl https://api.anthropic.com/v1/messages"},
                f"x-api-key: {FAKE_SECRETS['anthropic_key']}"
            ),
        ])
        (test_dir / "session.jsonl").write_text(session)

        results = cleanup.find_secrets_in_directories([test_dir])

        assert secret_found_in_results(FAKE_SECRETS["anthropic_key"], results)

    def test_git_credential_helper_output(self, tmp_path):
        """Simulate git credential helper leaking tokens."""
        test_dir = tmp_path / "debug"
        test_dir.mkdir()

        debug_log = f"""
[DEBUG] git credential-helper output:
protocol=https
host=github.com
username=x-access-token
password={FAKE_SECRETS["github_pat"]}
"""
        (test_dir / "debug.log").write_text(debug_log)

        results = cleanup.find_secrets_in_directories([test_dir])

        assert secret_found_in_results(FAKE_SECRETS["github_pat"], results)


class TestFalsePositiveFiltering:
    """Test that known false positives are filtered out."""

    def test_aws_example_key_filtered(self, tmp_path):
        """AWS documented example key should be filtered out."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "example.txt").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE")

        results = cleanup.find_secrets_in_directories([test_dir])

        assert not secret_found_in_results("AKIAIOSFODNN7EXAMPLE", results)

    def test_css_class_names_filtered(self, tmp_path):
        """CSS class names like sk-*-component should be filtered."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        content = """
        class="sk-execution-component-dark"
        class="sk-button-container-light"
        class="sk-icon-wrapper-primary"
        """
        (test_dir / "styles.txt").write_text(content)

        results = cleanup.find_secrets_in_directories([test_dir])

        # CSS class names should not be detected as secrets
        assert not secret_found_in_results("sk-execution-component-dark", results)

    def test_placeholder_patterns_filtered(self, tmp_path):
        """Placeholder patterns like sk-xxxx should be filtered."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        content = """
        sk-xxxxxxxxxxxxxxxxxxxx
        sk-1234567890abcdefghij
        sk-test1234567890abcdef
        """
        (test_dir / "placeholders.txt").write_text(content)

        results = cleanup.find_secrets_in_directories([test_dir])

        # Placeholder patterns should not be detected
        assert not secret_found_in_results("sk-xxxxxxxxxxxxxxxxxxxx", results)
        assert not secret_found_in_results("sk-1234567890abcdefghij", results)

    def test_real_key_not_filtered(self, tmp_path):
        """Real-looking keys should not be filtered."""
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "real.txt").write_text(FAKE_SECRETS["openai_key"])

        results = cleanup.find_secrets_in_directories([test_dir])

        assert secret_found_in_results(FAKE_SECRETS["openai_key"], results)

    def test_is_false_positive_function(self):
        """Test the is_false_positive function directly."""
        # Should be filtered
        assert cleanup.is_false_positive("AKIAIOSFODNN7EXAMPLE") is True
        assert cleanup.is_false_positive("sk-1234567890abcdefghij") is True
        assert cleanup.is_false_positive("sk-xxxxxxxxxxxxxxxxxxxx") is True
        assert cleanup.is_false_positive("sk-test-component-dark") is True
        assert cleanup.is_false_positive("sk-execution-container-light") is True
        assert cleanup.is_false_positive("sk-testkey1234567890abc") is True

        # Should not be filtered (real-looking keys)
        assert cleanup.is_false_positive(FAKE_SECRETS["openai_key"]) is False
        assert cleanup.is_false_positive(FAKE_SECRETS["anthropic_key"]) is False
        assert cleanup.is_false_positive(FAKE_SECRETS["aws_access_key"]) is False
