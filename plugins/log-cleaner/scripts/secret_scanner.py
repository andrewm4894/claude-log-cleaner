"""
Secret scanning functionality for Claude Code Log Cleaner.
Detects potential secrets in log files using multiple scanners.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Set

from config import CLAUDE_DIR, CLEAN_DIRS

# Try to import detect-secrets for enhanced scanning
try:
    from detect_secrets.core.scan import scan_file
    from detect_secrets.settings import transient_settings

    DETECT_SECRETS_AVAILABLE = True
except ImportError:
    DETECT_SECRETS_AVAILABLE = False

# Check for TruffleHog CLI (installed via brew or binary)
TRUFFLEHOG_AVAILABLE = shutil.which("trufflehog") is not None

# =============================================================================
# Secret Scanning Configuration
# =============================================================================

# detect-secrets plugins to use (when available)
DETECT_SECRETS_PLUGINS = [
    {"name": "AWSKeyDetector"},
    {"name": "AzureStorageKeyDetector"},
    {"name": "BasicAuthDetector"},
    {"name": "GitHubTokenDetector"},
    {"name": "GitLabTokenDetector"},
    {"name": "JwtTokenDetector"},
    {"name": "OpenAIDetector"},
    {"name": "PrivateKeyDetector"},
    {"name": "SendGridDetector"},
    {"name": "SlackDetector"},
    {"name": "StripeDetector"},
    {"name": "TwilioKeyDetector"},
]

# Built-in regex patterns - always run as baseline detection
# These catch secrets that TruffleHog/detect-secrets might miss
BUILTIN_PATTERNS = {
    "OpenAI/Anthropic API Keys": r"(sk-[a-zA-Z0-9_-]{20,}|sk-proj-[a-zA-Z0-9_-]{50,}|sk-ant-[a-zA-Z0-9_-]{20,})",
    "PostHog Keys": r"(phc_[a-zA-Z0-9]{30,}|phx_[a-zA-Z0-9_-]{30,})",
    "GitHub Tokens": r"((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}|github_pat_[a-zA-Z0-9_]{22,})",
    "AWS Keys": r"(AKIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}|ACCA[0-9A-Z]{16})",
    "Slack Tokens": r"(xox[baprs]-[0-9a-zA-Z-]{10,})",
    "Bearer Tokens": r"Bearer [a-zA-Z0-9_-]{30,}",
}

PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN .* PRIVATE KEY-----")

# Known false positives to exclude
FALSE_POSITIVE_EXACT = {
    # AWS documented example keys
    "AKIAIOSFODNN7EXAMPLE",
    "AKIATESTFAKEKEY12345",
    # Common test/placeholder patterns
    "sk-1234567890abcdefghij",
    "sk-test1234567890abcdef",
    "sk-xxxxxxxxxxxxxxxxxxxx",
}

# Patterns that indicate false positives (CSS classes, test values, etc.)
FALSE_POSITIVE_PATTERNS = [
    # CSS class names (sk-*-component, sk-execution-*, etc.)
    re.compile(r"sk-[a-z]+-(?:component|container|wrapper|button|icon|text|dark|light|primary|secondary)"),
    # Repeating placeholder characters
    re.compile(r"sk-[x]{10,}"),
    re.compile(r"sk-[0-9]{20,}$"),  # All numeric after prefix
    # Test file markers
    re.compile(r"sk-(?:test|fake|mock|example|dummy|sample)[a-zA-Z0-9_-]*"),
    # Our own scan output (truncated prefixes ending in ...)
    re.compile(r".*\.\.\.$"),
]


def is_false_positive(secret: str) -> bool:
    """Check if a detected secret is a known false positive."""
    # Check exact matches
    if secret in FALSE_POSITIVE_EXACT:
        return True

    # Check pattern matches
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.search(secret):
            return True

    return False


def scan_file_with_detect_secrets(file_path: Path) -> Dict[str, Dict[str, Set[str]]]:
    """Scan a single file using detect-secrets library.

    Returns:
        Dict mapping secret_type -> secret_value -> set of file paths
    """
    results: Dict[str, Dict[str, Set[str]]] = {}

    try:
        with transient_settings({"plugins_used": DETECT_SECRETS_PLUGINS}):
            for secret in scan_file(str(file_path)):
                secret_type = secret.type
                secret_value = secret.secret_value

                if secret_type not in results:
                    results[secret_type] = {}

                if not is_false_positive(secret_value):
                    if secret_value not in results[secret_type]:
                        results[secret_type][secret_value] = set()
                    results[secret_type][secret_value].add(str(file_path))
    except Exception:
        # If detect-secrets fails on a file, skip it
        pass

    return results


def scan_file_with_patterns(
    file_path: Path, patterns: Dict[str, str]
) -> Dict[str, Dict[str, Set[str]]]:
    """Scan a single file using regex patterns (fallback method).

    Returns:
        Dict mapping secret_type -> secret_value -> set of file paths
    """
    results: Dict[str, Dict[str, Set[str]]] = {name: {} for name in patterns}

    try:
        content = file_path.read_text(errors="ignore")
        compiled = {name: re.compile(pattern) for name, pattern in patterns.items()}

        for pattern_name, pattern in compiled.items():
            matches = pattern.findall(content)
            for match in matches:
                # Filter out "Redacted" for bearer tokens
                if "Bearer" in pattern_name and "Redacted" in match:
                    continue
                if not is_false_positive(match):
                    if match not in results[pattern_name]:
                        results[pattern_name][match] = set()
                    results[pattern_name][match].add(str(file_path))
    except (OSError, IOError):
        pass

    return results


def scan_with_trufflehog(
    directories: List[Path], verify: bool = False
) -> Dict[str, Dict[str, Set[str]]]:
    """
    Scan directories using TruffleHog CLI.

    Args:
        directories: List of directory paths to scan
        verify: Whether to verify credentials against APIs (slower but more accurate)

    Returns:
        Dict mapping detector types -> secret values -> sets of file paths
    """
    results: Dict[str, Dict[str, Set[str]]] = {}
    results["Private Key Files"] = {}

    # Build command
    cmd = ["trufflehog", "filesystem", "--json", "--no-update"]
    if not verify:
        cmd.append("--no-verification")
    cmd.extend(str(d) for d in directories if d.exists())

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in proc.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                finding = json.loads(line)
                # Use DetectorName for human-readable name, fall back to DetectorType
                detector = finding.get("DetectorName", finding.get("DetectorType", "Unknown"))
                raw = finding.get("Raw", "")

                # Extract file path from TruffleHog metadata
                file_path = (
                    finding.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("file", "")
                )

                # Handle private keys specially
                if detector == "PrivateKey" or "private" in str(detector).lower():
                    if file_path:
                        # Use file path as both key and value for private keys
                        if file_path not in results["Private Key Files"]:
                            results["Private Key Files"][file_path] = set()
                        results["Private Key Files"][file_path].add(file_path)
                elif raw and not is_false_positive(raw):
                    if detector not in results:
                        results[detector] = {}
                    if raw not in results[detector]:
                        results[detector][raw] = set()
                    if file_path:
                        results[detector][raw].add(file_path)
            except json.JSONDecodeError:
                continue
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return results


def _merge_results(
    target: Dict[str, Dict[str, Set[str]]], source: Dict[str, Dict[str, Set[str]]]
) -> None:
    """Merge source results into target, combining file path sets for matching secrets."""
    for secret_type, secrets_dict in source.items():
        if secret_type not in target:
            target[secret_type] = {}
        for secret_value, file_paths in secrets_dict.items():
            if secret_value not in target[secret_type]:
                target[secret_type][secret_value] = set()
            target[secret_type][secret_value].update(file_paths)


def find_secrets_in_directories(directories: List[Path]) -> Dict[str, Dict[str, Set[str]]]:
    """
    Scan directories for secrets using all available scanners.

    Runs all available scanners and merges results for maximum coverage:
    - TruffleHog (if installed via brew)
    - detect-secrets (if installed via pip)
    - Built-in regex patterns (always)

    Args:
        directories: List of directory paths to scan

    Returns:
        Dict mapping secret types -> secret values -> sets of file paths.
        Special key "Private Key Files" maps file paths to themselves.
    """
    results: Dict[str, Dict[str, Set[str]]] = {}
    results["Private Key Files"] = {}

    # 1. Run TruffleHog if available (scans whole directories at once)
    if TRUFFLEHOG_AVAILABLE:
        trufflehog_results = scan_with_trufflehog(directories)
        _merge_results(results, trufflehog_results)

    # 2. Scan files with detect-secrets and/or built-in patterns
    for scan_dir in directories:
        if not scan_dir.exists():
            continue

        try:
            for file_path in scan_dir.rglob("*"):
                if not file_path.is_file():
                    continue

                # Run detect-secrets if available
                if DETECT_SECRETS_AVAILABLE:
                    ds_results = scan_file_with_detect_secrets(file_path)
                    _merge_results(results, ds_results)

                # Always run built-in patterns for maximum coverage
                builtin_results = scan_file_with_patterns(file_path, BUILTIN_PATTERNS)
                _merge_results(results, builtin_results)

                # Check for private keys with our pattern
                try:
                    content = file_path.read_text(errors="ignore")
                    if PRIVATE_KEY_PATTERN.search(content):
                        fp_str = str(file_path)
                        if fp_str not in results["Private Key Files"]:
                            results["Private Key Files"][fp_str] = set()
                        results["Private Key Files"][fp_str].add(fp_str)
                except (OSError, IOError):
                    pass

        except OSError:
            continue

    return results


def _extract_context_from_path(file_path: str) -> str:
    """Extract the path relative to ~/.claude for display."""
    path = Path(file_path)
    parts = path.parts

    # Find the .claude directory index
    try:
        claude_idx = parts.index(".claude")
    except ValueError:
        return file_path

    # Return path relative to .claude
    rel_parts = parts[claude_idx + 1 :]
    if not rel_parts:
        return file_path

    return str(Path(*rel_parts))


def _get_unique_locations(file_paths: Set[str]) -> List[str]:
    """Get unique location contexts from file paths, sorted and deduplicated."""
    contexts = set()
    for fp in file_paths:
        contexts.add(_extract_context_from_path(fp))
    return sorted(contexts)


def _get_secret_prefix(secret: str, prefix_len: int = 12) -> str:
    """Get a safe prefix of a secret for display.

    Shows first N characters followed by ellipsis to help identify the key
    without exposing the full secret.
    """
    if len(secret) <= prefix_len:
        return secret
    return secret[:prefix_len] + "..."


def _extract_project_context(file_path: str) -> str:
    """Extract project/session context from a file path for triage.

    Returns a human-readable context string like:
    - 'projects/my-repo/session-abc123.json'
    - 'debug/2024-01-15-abc123.log'
    """
    path = Path(file_path)
    parts = path.parts

    # Find the .claude directory index
    try:
        claude_idx = parts.index(".claude")
    except ValueError:
        # Fallback: just return the filename
        return path.name

    # Get path relative to .claude
    rel_parts = parts[claude_idx + 1 :]
    if not rel_parts:
        return path.name

    return str(Path(*rel_parts))


def scan_secrets() -> None:
    """Scan log directories for potential secrets and print results."""
    print("Scanning for potential secrets in Claude Code logs...")
    print("")

    # Show active scanners
    scanners = []
    if TRUFFLEHOG_AVAILABLE:
        scanners.append("TruffleHog")
    if DETECT_SECRETS_AVAILABLE:
        scanners.append("detect-secrets")
    scanners.append("built-in patterns")  # Always active

    print(f"Scanners: {' + '.join(scanners)}")
    if not TRUFFLEHOG_AVAILABLE and not DETECT_SECRETS_AVAILABLE:
        print("  (install trufflehog or detect-secrets for enhanced scanning)")
    print("")

    # Find existing directories
    scan_dirs = [CLAUDE_DIR / d for d in CLEAN_DIRS if (CLAUDE_DIR / d).exists()]

    if not scan_dirs:
        print("No Claude log directories found to scan.")
        return

    print(f"Scanning directories: {', '.join(d.name for d in scan_dirs)}")
    print("")

    # Get results
    results = find_secrets_in_directories(scan_dirs)

    # Count total secrets found
    total_secrets = 0
    total_files_with_secrets = set()

    # Print detailed results for each secret type found
    for secret_type in sorted(results.keys()):
        if secret_type == "Private Key Files":
            continue  # Handle separately

        secrets_dict = results[secret_type]
        if secrets_dict:
            print(f"=== {secret_type} ===")
            print("")

            for i, (secret, file_paths) in enumerate(sorted(secrets_dict.items())[:15]):
                # Show secret prefix for identification
                prefix = _get_secret_prefix(secret)
                print(f"  [{i + 1}] {prefix}")

                # Show all file locations for this secret
                locations = sorted(set(_extract_project_context(fp) for fp in file_paths))
                # Track ALL affected files, not just displayed ones
                total_files_with_secrets.update(locations)
                for loc in locations[:5]:
                    print(f"      └─ {loc}")
                if len(locations) > 5:
                    print(f"      └─ ... and {len(locations) - 5} more files")
                print("")

            if len(secrets_dict) > 15:
                print(f"  ... and {len(secrets_dict) - 15} more secrets of this type")
                print("")
            total_secrets += len(secrets_dict)

    # Print private key files
    key_files_dict = results.get("Private Key Files", {})
    if key_files_dict:
        print("=== Private Key Files ===")
        print("")
        # Track ALL affected files, not just displayed ones
        all_key_file_contexts = [
            _extract_project_context(fp) for fp in key_files_dict.keys()
        ]
        total_files_with_secrets.update(all_key_file_contexts)
        for i, context in enumerate(sorted(all_key_file_contexts)[:10]):
            print(f"  [{i + 1}] {context}")
        if len(key_files_dict) > 10:
            print(f"  ... and {len(key_files_dict) - 10} more files")
        print("")
        total_secrets += len(key_files_dict)

    # Summary
    print("=" * 50)
    print("SUMMARY")
    print("=" * 50)
    if total_secrets == 0:
        print("No secrets detected.")
    else:
        print(f"Secrets found: {total_secrets}")
        print(f"Files affected: {len(total_files_with_secrets)}")
        print("")
        print("Recommended actions:")
        print("  1. Rotate any exposed credentials immediately")
        print("  2. Run /log-cleaner:clean to remove old logs")
        print("  3. Review what data you paste into Claude Code")
