#!/usr/bin/env python3
"""
Claude Code Log Cleaner
Deletes session logs older than the configured retention period.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Try to import detect-secrets for enhanced scanning
try:
    from detect_secrets.core.scan import scan_file
    from detect_secrets.settings import transient_settings

    DETECT_SECRETS_AVAILABLE = True
except ImportError:
    DETECT_SECRETS_AVAILABLE = False

# Check for TruffleHog CLI (installed via brew or binary)
TRUFFLEHOG_AVAILABLE = shutil.which("trufflehog") is not None

# Configuration
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

# ANSI colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"  # No Color


def log_info(msg: str) -> None:
    print(f"{GREEN}[INFO]{NC} {msg}", file=sys.stderr)


def log_warn(msg: str) -> None:
    print(f"{YELLOW}[WARN]{NC} {msg}", file=sys.stderr)


def log_error(msg: str) -> None:
    print(f"{RED}[ERROR]{NC} {msg}", file=sys.stderr)


def format_size(size_bytes: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


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


def find_old_files(directory: Path, retention_hours: int) -> List[Path]:
    """Find files older than retention period."""
    if not directory.exists():
        return []

    cutoff_time = time.time() - (retention_hours * 3600)
    old_files = []

    try:
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                try:
                    if file_path.stat().st_mtime < cutoff_time:
                        old_files.append(file_path)
                except OSError:
                    continue
    except OSError:
        pass

    return old_files


def clean_directory(
    dir_name: str, retention_hours: int, dry_run: bool
) -> Tuple[int, int]:
    """Clean files older than retention period. Returns (files_deleted, bytes_freed)."""
    full_path = CLAUDE_DIR / dir_name

    if not full_path.exists():
        return 0, 0

    old_files = find_old_files(full_path, retention_hours)

    if not old_files:
        return 0, 0

    count = 0
    size_freed = 0

    for file_path in old_files:
        try:
            file_size = file_path.stat().st_size
        except OSError:
            file_size = 0

        if dry_run:
            log_info(f"[DRY RUN] Would delete: {file_path} ({format_size(file_size)})")
        else:
            try:
                file_path.unlink()
            except OSError:
                continue

        count += 1
        size_freed += file_size

    # Clean empty directories (but preserve top-level dir)
    if not dry_run:
        try:
            for dir_path in sorted(full_path.rglob("*"), reverse=True):
                if dir_path.is_dir():
                    try:
                        dir_path.rmdir()  # Only removes if empty
                    except OSError:
                        pass
        except OSError:
            pass

    if count > 0:
        size_str = format_size(size_freed)
        if dry_run:
            log_info(f"[DRY RUN] {dir_name}: Would delete {count} files ({size_str})")
        else:
            log_info(f"{dir_name}: Deleted {count} files ({size_str} freed)")

    return count, size_freed


def cleanup(dry_run: bool, retention_override: Optional[int] = None) -> None:
    """Main cleanup function."""
    config = load_config()
    retention_hours = retention_override if retention_override else config["retention_hours"]

    log_info(f"Starting cleanup (retention: {retention_hours}h, dry_run: {dry_run})")

    total_files = 0

    for dir_name in CLEAN_DIRS:
        cleaned, _ = clean_directory(dir_name, retention_hours, dry_run)
        total_files += cleaned

    if total_files == 0:
        log_info(f"No files older than {retention_hours}h found")
    else:
        log_info(f"Cleanup complete: {total_files} files processed")


def get_directory_stats(directory: Path) -> Tuple[int, int]:
    """Get file count and total size for a directory."""
    if not directory.exists():
        return 0, 0

    file_count = 0
    total_size = 0

    try:
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                file_count += 1
                try:
                    total_size += file_path.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass

    return file_count, total_size


def show_status() -> None:
    """Show current status and directory sizes."""
    config = load_config()
    retention_hours = config["retention_hours"]

    print("Claude Log Cleaner Status")
    print("=========================")
    print(f"Retention period: {retention_hours} hours")
    print(f"Config file: {CONFIG_FILE}")
    print("")
    print("Directory sizes:")

    for dir_name in CLEAN_DIRS:
        full_path = CLAUDE_DIR / dir_name
        if full_path.exists():
            file_count, total_size = get_directory_stats(full_path)
            size_str = format_size(total_size)
            print(f"  {dir_name}: {size_str} ({file_count} files)")


def set_retention(hours: int) -> None:
    """Set retention hours in config."""
    if hours < 0:
        log_error(f"Invalid hours value: {hours}")
        sys.exit(1)

    create_default_config()
    config = load_config()
    config["retention_hours"] = hours
    save_config(config)
    log_info(f"Retention period set to {hours} hours")


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


def scan_file_with_detect_secrets(file_path: Path) -> Dict[str, Set[str]]:
    """Scan a single file using detect-secrets library."""
    results: Dict[str, Set[str]] = {}

    try:
        with transient_settings({"plugins_used": DETECT_SECRETS_PLUGINS}):
            for secret in scan_file(str(file_path)):
                secret_type = secret.type
                secret_value = secret.secret_value

                if secret_type not in results:
                    results[secret_type] = set()

                if not is_false_positive(secret_value):
                    results[secret_type].add(secret_value)
    except Exception:
        # If detect-secrets fails on a file, skip it
        pass

    return results


def scan_file_with_patterns(
    file_path: Path, patterns: Dict[str, str]
) -> Dict[str, Set[str]]:
    """Scan a single file using regex patterns (fallback method)."""
    results: Dict[str, Set[str]] = {name: set() for name in patterns}

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
                    results[pattern_name].add(match)
    except (OSError, IOError):
        pass

    return results


def scan_with_trufflehog(directories: List[Path], verify: bool = False) -> Dict[str, Set[str]]:
    """
    Scan directories using TruffleHog CLI.

    Args:
        directories: List of directory paths to scan
        verify: Whether to verify credentials against APIs (slower but more accurate)

    Returns:
        Dict mapping detector types to sets of found secrets
    """
    results: Dict[str, Set[str]] = {}
    results["Private Key Files"] = set()

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

                # Handle private keys specially
                if detector == "PrivateKey" or "private" in str(detector).lower():
                    file_path = (
                        finding.get("SourceMetadata", {})
                        .get("Data", {})
                        .get("Filesystem", {})
                        .get("file", "")
                    )
                    if file_path:
                        results["Private Key Files"].add(file_path)
                elif raw and not is_false_positive(raw):
                    if detector not in results:
                        results[detector] = set()
                    results[detector].add(raw)
            except json.JSONDecodeError:
                continue
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return results


def _merge_results(target: Dict[str, Set[str]], source: Dict[str, Set[str]]) -> None:
    """Merge source results into target, combining sets for matching keys."""
    for secret_type, secrets in source.items():
        if secret_type not in target:
            target[secret_type] = set()
        target[secret_type].update(secrets)


def find_secrets_in_directories(directories: List[Path]) -> Dict[str, Set[str]]:
    """
    Scan directories for secrets using all available scanners.

    Runs all available scanners and merges results for maximum coverage:
    - TruffleHog (if installed via brew)
    - detect-secrets (if installed via pip)
    - Built-in regex patterns (always)

    Args:
        directories: List of directory paths to scan

    Returns:
        Dict mapping secret types to sets of found secrets.
        Special key "Private Key Files" contains file paths with private keys.
    """
    results: Dict[str, Set[str]] = {}
    results["Private Key Files"] = set()

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
                        results["Private Key Files"].add(str(file_path))
                except (OSError, IOError):
                    pass

        except OSError:
            continue

    return results


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

    # Print results for each secret type found
    for secret_type in sorted(results.keys()):
        if secret_type == "Private Key Files":
            continue  # Handle separately

        found = results[secret_type]
        if found:
            print(f"=== {secret_type} ===")
            for secret in sorted(found)[:10]:  # Limit to 10
                # Mask middle of secret for safety
                if len(secret) > 20:
                    masked = secret[:10] + "..." + secret[-6:]
                else:
                    masked = secret
                print(f"  {masked}")
            if len(found) > 10:
                print(f"  ... and {len(found) - 10} more")
            print("")
            total_secrets += len(found)

    # Print private key files
    key_files = results.get("Private Key Files", set())
    if key_files:
        print("=== Private Key Files ===")
        for f in sorted(key_files)[:5]:  # Limit to 5
            print(f"  {f}")
        if len(key_files) > 5:
            print(f"  ... and {len(key_files) - 5} more")
        print("")
        total_secrets += len(key_files)

    # Summary
    print("=== Summary ===")
    if total_secrets == 0:
        print("No secrets detected.")
    else:
        print(f"Found {total_secrets} potential secret(s).")
        print("")
        print("Recommended actions:")
        print("  1. Rotate any exposed credentials immediately")
        print("  2. Run /log-cleaner:clean to remove old logs")
        print("  3. Review what data you paste into Claude Code")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Claude Code Log Cleaner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                    # Clean with default settings
    %(prog)s clean --dry-run    # Preview what would be deleted
    %(prog)s clean --hours 1    # Clean files older than 1 hour
    %(prog)s set-retention 48   # Set retention to 48 hours
    %(prog)s status             # Show current status
    %(prog)s scan                # Scan for exposed secrets

Configuration:
    Edit ~/.claude/log-cleaner-config.json to customize behavior.
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Clean command
    clean_parser = subparsers.add_parser("clean", help="Clean old log files")
    clean_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be deleted without deleting"
    )
    clean_parser.add_argument(
        "--hours", type=int, help="Override retention period for this run"
    )
    clean_parser.add_argument(
        "--session-end", action="store_true", help="Called from session end hook"
    )

    # Status command
    subparsers.add_parser("status", help="Show current status and directory sizes")

    # Set retention command
    retention_parser = subparsers.add_parser(
        "set-retention", help="Set retention period in hours"
    )
    retention_parser.add_argument("hours", type=int, help="Number of hours to retain logs")

    # Scan secrets command
    subparsers.add_parser("scan", help="Scan for potential secrets in logs")

    args = parser.parse_args()

    # Default to clean if no command given
    if args.command is None:
        args.command = "clean"
        args.dry_run = False
        args.hours = None
        args.session_end = False

    # Create default config if needed
    create_default_config()

    # Handle session end hook
    if args.command == "clean" and getattr(args, "session_end", False):
        config = load_config()
        if not config.get("clean_on_session_end", True):
            log_info("Cleanup on session end is disabled in config")
            sys.exit(0)

    # Execute command
    if args.command == "clean":
        # Use config dry_run as default if CLI flag not provided
        dry_run = args.dry_run
        if not dry_run:
            config = load_config()
            dry_run = config.get("dry_run", False)
        cleanup(dry_run, args.hours)
    elif args.command == "status":
        show_status()
    elif args.command == "set-retention":
        set_retention(args.hours)
    elif args.command == "scan":
        scan_secrets()


if __name__ == "__main__":
    main()
