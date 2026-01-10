---
description: Show the current status of Claude Code log files and cleanup configuration
allowed-tools: Bash
---

# Log Cleaner Status Command

Show the current status of Claude Code session logs, including directory sizes and current configuration.

Run the status command:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cleanup.py" status
```

After showing the status, offer to help the user:
1. Run a cleanup if there's a lot of data
2. Adjust the retention period if needed
3. Run a dry-run to preview what would be deleted
