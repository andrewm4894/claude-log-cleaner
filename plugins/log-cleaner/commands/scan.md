---
description: Scan Claude Code logs for potential secrets and API keys
allowed-tools: Bash
---

# Scan Command

Scan Claude Code session logs for potential secrets, API keys, and sensitive data.

Run the scan command:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cleanup.py" scan $@
```

After showing results, recommend running cleanup if secrets are found.
