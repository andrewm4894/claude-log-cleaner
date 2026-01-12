#!/usr/bin/env python3
"""
Claude Code Log Cleaner
Deletes session logs older than the configured retention period.
"""

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

from config import (
    CLAUDE_DIR,
    CLEAN_DIRS,
    CONFIG_FILE,
    create_default_config,
    load_config,
    save_config,
)
from secret_scanner import scan_secrets
from utils import format_size, log_error, log_info


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


def cleanup(
    dry_run: bool, retention_override: Optional[int] = None
) -> Tuple[int, int, int]:
    """Main cleanup function.

    Returns:
        Tuple of (total_files, total_size, retention_hours)
    """
    config = load_config()
    retention_hours = retention_override if retention_override else config["retention_hours"]

    log_info(f"Starting cleanup (retention: {retention_hours}h, dry_run: {dry_run})")

    total_files = 0
    total_size = 0

    for dir_name in CLEAN_DIRS:
        cleaned, size_freed = clean_directory(dir_name, retention_hours, dry_run)
        total_files += cleaned
        total_size += size_freed

    if total_files == 0:
        log_info(f"No files older than {retention_hours}h found")
    else:
        log_info(f"Cleanup complete: {total_files} files processed")

    return total_files, total_size, retention_hours


def print_session_end_summary(files_cleaned: int, size_freed: int, dry_run: bool) -> None:
    """Print a summary message for session end hook output."""
    size_str = format_size(size_freed)
    if dry_run:
        if files_cleaned > 0:
            msg = f"[log-cleaner] Would clean {files_cleaned} files ({size_str})"
        else:
            msg = "[log-cleaner] No old files to clean"
    else:
        if files_cleaned > 0:
            msg = f"[log-cleaner] Cleaned {files_cleaned} files ({size_str} freed)"
        else:
            msg = "[log-cleaner] No old files found"
    # Try multiple output methods to ensure visibility on session end
    print(msg)
    print(msg, file=sys.stderr)
    # Also try writing directly to terminal
    try:
        with open("/dev/tty", "w") as tty:
            tty.write(f"\n{msg}\n")
    except (OSError, IOError):
        pass


def get_directory_stats(
    directory: Path, retention_hours: int
) -> Tuple[int, int, int, Optional[float]]:
    """Get file count, total size, violation count, and max age for a directory.

    Returns:
        Tuple of (file_count, total_size, violations, max_age_hours)
        - violations: count of files older than retention period
        - max_age_hours: age of oldest file in hours, or None if no files
    """
    if not directory.exists():
        return 0, 0, 0, None

    file_count = 0
    total_size = 0
    violations = 0
    oldest_mtime: Optional[float] = None
    now = time.time()
    cutoff_time = now - (retention_hours * 3600)

    try:
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                file_count += 1
                try:
                    stat = file_path.stat()
                    total_size += stat.st_size
                    mtime = stat.st_mtime
                    if oldest_mtime is None or mtime < oldest_mtime:
                        oldest_mtime = mtime
                    if mtime < cutoff_time:
                        violations += 1
                except OSError:
                    pass
    except OSError:
        pass

    max_age_hours = None
    if oldest_mtime is not None:
        max_age_hours = (now - oldest_mtime) / 3600

    return file_count, total_size, violations, max_age_hours


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

    total_violations = 0
    global_max_age: Optional[float] = None

    for dir_name in CLEAN_DIRS:
        full_path = CLAUDE_DIR / dir_name
        if full_path.exists():
            file_count, total_size, violations, max_age = get_directory_stats(
                full_path, retention_hours
            )
            size_str = format_size(total_size)

            # Build status line
            status = f"  {dir_name}: {size_str} ({file_count} files)"
            if violations > 0:
                status += f" ⚠️  {violations} violations"
            print(status)

            total_violations += violations
            if max_age is not None:
                if global_max_age is None or max_age > global_max_age:
                    global_max_age = max_age

    # Summary
    print("")
    if global_max_age is not None:
        print(f"Oldest file: {global_max_age:.1f} hours ago")

    if total_violations > 0:
        print(f"⚠️  Retention violations: {total_violations} files exceed {retention_hours}h")
        print("   Run /log-cleaner:clean to remove old files")
    else:
        print("✓ No retention violations")


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
        config = load_config()
        if not dry_run:
            dry_run = config.get("dry_run", False)
        files_cleaned, size_freed, _ = cleanup(dry_run, args.hours)

        # Print summary on session end if enabled
        if getattr(args, "session_end", False) and config.get("session_end_summary", True):
            print_session_end_summary(files_cleaned, size_freed, dry_run)
    elif args.command == "status":
        show_status()
    elif args.command == "set-retention":
        set_retention(args.hours)
    elif args.command == "scan":
        scan_secrets()


if __name__ == "__main__":
    main()
