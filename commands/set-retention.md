---
description: Set the retention period (in hours) for log cleanup
allowed-tools: Bash
---

# Set Retention Command

Set the retention period for log cleanup. Files older than this will be deleted.

Arguments: $ARGUMENTS (number of hours)

If the user provided a number, run:

```bash
${CLAUDE_PLUGIN_ROOT}/scripts/cleanup.sh set-retention $ARGUMENTS
```

If no argument was provided, ask the user how many hours they want to retain logs for. Common options:
- 1 hour (aggressive cleanup)
- 24 hours (1 day, default)
- 48 hours (2 days)
- 168 hours (1 week)
- 720 hours (30 days)
