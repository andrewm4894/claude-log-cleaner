---
description: Manually run the log cleaner to delete old session files
allowed-tools: Bash
---

# Clean Logs Command

Run the log cleaner script to delete old Claude Code session logs.

Arguments: $ARGUMENTS

Run the cleanup script located at the plugin root:

```bash
${CLAUDE_PLUGIN_ROOT}/scripts/cleanup.sh $ARGUMENTS
```

Available options:
- `--dry-run` - Preview what would be deleted without actually deleting
- `--hours N` - Override retention period for this run

Examples the user might want:
- No arguments: Run with default settings
- `--dry-run`: See what would be deleted
- `--hours 1`: Delete files older than 1 hour
