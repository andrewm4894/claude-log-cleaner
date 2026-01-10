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
