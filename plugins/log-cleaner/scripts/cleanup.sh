#!/bin/bash
#
# Claude Code Log Cleaner
# Deletes session logs older than the configured retention period
#

set -euo pipefail

# Configuration
CLAUDE_DIR="${HOME}/.claude"
CONFIG_FILE="${CLAUDE_DIR}/log-cleaner-config.json"

# Default retention in hours (24 hours)
DEFAULT_RETENTION_HOURS=24

# Directories to clean (relative to CLAUDE_DIR)
CLEAN_DIRS=(
    "debug"
    "file-history"
)

# Optional directories (cleaned if --all flag is passed)
OPTIONAL_DIRS=(
    "projects"
    "todos"
    "plans"
    "shell-snapshots"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Get retention hours from config or use default
get_retention_hours() {
    if [[ -f "$CONFIG_FILE" ]]; then
        local hours
        hours=$(grep -o '"retention_hours"[[:space:]]*:[[:space:]]*[0-9]*' "$CONFIG_FILE" 2>/dev/null | grep -o '[0-9]*' || echo "")
        if [[ -n "$hours" ]]; then
            echo "$hours"
            return
        fi
    fi
    echo "$DEFAULT_RETENTION_HOURS"
}

# Create default config if it doesn't exist
create_default_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
  "retention_hours": ${DEFAULT_RETENTION_HOURS},
  "clean_on_session_end": true,
  "clean_optional_dirs": false,
  "dry_run": false
}
EOF
        log_info "Created default config at $CONFIG_FILE"
    fi
}

# Clean files older than retention period in a directory
clean_directory() {
    local dir="$1"
    local retention_hours="$2"
    local dry_run="${3:-false}"
    local full_path="${CLAUDE_DIR}/${dir}"

    if [[ ! -d "$full_path" ]]; then
        echo "0"
        return 0
    fi

    # Count files to delete
    local file_list
    file_list=$(find "$full_path" -type f -mmin +$((retention_hours * 60)) 2>/dev/null)

    if [[ -z "$file_list" ]]; then
        echo "0"
        return 0
    fi

    local count=0
    local size_freed=0

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue

        local file_size
        file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)

        if [[ "$dry_run" == "true" ]]; then
            local size_human
            size_human=$(numfmt --to=iec "$file_size" 2>/dev/null || echo "${file_size}B")
            log_info "[DRY RUN] Would delete: $file ($size_human)"
        else
            rm -f "$file"
        fi

        count=$((count + 1))
        size_freed=$((size_freed + file_size))
    done <<< "$file_list"

    # Clean empty directories
    if [[ "$dry_run" != "true" ]]; then
        find "$full_path" -type d -empty -delete 2>/dev/null || true
    fi

    if [[ $count -gt 0 ]]; then
        local size_str
        size_str=$(numfmt --to=iec "$size_freed" 2>/dev/null || echo "${size_freed}B")
        if [[ "$dry_run" == "true" ]]; then
            log_info "[DRY RUN] ${dir}: Would delete $count files ($size_str)"
        else
            log_info "${dir}: Deleted $count files ($size_str freed)"
        fi
    fi

    echo "$count"
}

# Main cleanup function
cleanup() {
    local dry_run="${1:-false}"
    local include_optional="${2:-false}"
    local retention_hours
    retention_hours=$(get_retention_hours)

    log_info "Starting cleanup (retention: ${retention_hours}h, dry_run: ${dry_run})"

    local total_files=0

    # Clean main directories
    for dir in "${CLEAN_DIRS[@]}"; do
        local cleaned
        cleaned=$(clean_directory "$dir" "$retention_hours" "$dry_run")
        total_files=$((total_files + cleaned))
    done

    # Clean optional directories if requested
    if [[ "$include_optional" == "true" ]]; then
        for dir in "${OPTIONAL_DIRS[@]}"; do
            local cleaned
            cleaned=$(clean_directory "$dir" "$retention_hours" "$dry_run")
            total_files=$((total_files + cleaned))
        done
    fi

    if [[ $total_files -eq 0 ]]; then
        log_info "No files older than ${retention_hours}h found"
    else
        log_info "Cleanup complete: $total_files files processed"
    fi
}

# Show current status
show_status() {
    local retention_hours
    retention_hours=$(get_retention_hours)

    echo "Claude Log Cleaner Status"
    echo "========================="
    echo "Retention period: ${retention_hours} hours"
    echo "Config file: $CONFIG_FILE"
    echo ""
    echo "Directory sizes:"

    for dir in "${CLEAN_DIRS[@]}" "${OPTIONAL_DIRS[@]}"; do
        local full_path="${CLAUDE_DIR}/${dir}"
        if [[ -d "$full_path" ]]; then
            local size
            size=$(du -sh "$full_path" 2>/dev/null | cut -f1)
            local file_count
            file_count=$(find "$full_path" -type f 2>/dev/null | wc -l | tr -d ' ')
            echo "  $dir: $size ($file_count files)"
        fi
    done
}

# Set retention hours
set_retention() {
    local hours="$1"

    if ! [[ "$hours" =~ ^[0-9]+$ ]]; then
        log_error "Invalid hours value: $hours"
        exit 1
    fi

    create_default_config

    # Update config file
    if [[ -f "$CONFIG_FILE" ]]; then
        local tmp_file
        tmp_file=$(mktemp)
        sed "s/\"retention_hours\"[[:space:]]*:[[:space:]]*[0-9]*/\"retention_hours\": $hours/" "$CONFIG_FILE" > "$tmp_file"
        mv "$tmp_file" "$CONFIG_FILE"
        log_info "Retention period set to ${hours} hours"
    fi
}

# Usage information
usage() {
    cat << EOF
Claude Code Log Cleaner

Usage: $(basename "$0") [command] [options]

Commands:
    clean           Clean old log files (default)
    status          Show current status and directory sizes
    set-retention   Set retention period in hours
    help            Show this help message

Options:
    --dry-run       Show what would be deleted without deleting
    --all           Include optional directories (projects, todos, plans, etc.)
    --hours N       Override retention period for this run

Examples:
    $(basename "$0")                    # Clean with default settings
    $(basename "$0") --dry-run          # Preview what would be deleted
    $(basename "$0") --all              # Clean all directories
    $(basename "$0") set-retention 48   # Set retention to 48 hours
    $(basename "$0") status             # Show current status

Configuration:
    Edit $CONFIG_FILE to customize behavior.

EOF
}

# Parse command line arguments
main() {
    local command="clean"
    local dry_run="false"
    local include_optional="false"
    local custom_hours=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            clean)
                command="clean"
                shift
                ;;
            status)
                command="status"
                shift
                ;;
            set-retention)
                command="set-retention"
                shift
                if [[ $# -gt 0 ]]; then
                    custom_hours="$1"
                    shift
                else
                    log_error "set-retention requires a number of hours"
                    exit 1
                fi
                ;;
            help|--help|-h)
                usage
                exit 0
                ;;
            --dry-run)
                dry_run="true"
                shift
                ;;
            --all)
                include_optional="true"
                shift
                ;;
            --hours)
                shift
                if [[ $# -gt 0 ]]; then
                    custom_hours="$1"
                    shift
                else
                    log_error "--hours requires a number"
                    exit 1
                fi
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Create default config if needed
    create_default_config

    # Execute command
    case "$command" in
        clean)
            if [[ -n "$custom_hours" ]]; then
                # Temporarily override retention
                local orig_config
                orig_config=$(cat "$CONFIG_FILE")
                set_retention "$custom_hours"
                cleanup "$dry_run" "$include_optional"
                echo "$orig_config" > "$CONFIG_FILE"
            else
                cleanup "$dry_run" "$include_optional"
            fi
            ;;
        status)
            show_status
            ;;
        set-retention)
            set_retention "$custom_hours"
            ;;
    esac
}

main "$@"
