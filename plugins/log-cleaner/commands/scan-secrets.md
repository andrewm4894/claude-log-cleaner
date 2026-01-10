---
description: Scan Claude Code logs for potential secrets and API keys
allowed-tools: Bash
---

# Scan Secrets Command

Scan Claude Code session logs for potential secrets, API keys, and sensitive data.

Run the scan-secrets command:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cleanup.py" scan-secrets
```

After showing results, recommend running cleanup if secrets are found.
