---
description: Scan Claude Code logs for potential secrets and API keys
allowed-tools: Bash
---

# Scan Secrets Command

Scan Claude Code session logs for potential secrets, API keys, and sensitive data.

Run the following command to scan for common secret patterns:

```bash
echo "Scanning for potential secrets in Claude Code logs..."
echo ""

CLAUDE_DIR="${HOME}/.claude"

echo "=== API Keys Found ==="
grep -rEoh '(sk-[a-zA-Z0-9_-]{20,}|sk-proj-[a-zA-Z0-9_-]{50,}|sk-ant-[a-zA-Z0-9_-]{20,})' "$CLAUDE_DIR/debug/" 2>/dev/null | sort -u | head -10 || echo "No OpenAI/Anthropic keys found"

echo ""
echo "=== PostHog Keys Found ==="
grep -rEoh '(phc_[a-zA-Z0-9]{30,}|phx_[a-zA-Z0-9_-]{30,})' "$CLAUDE_DIR/debug/" 2>/dev/null | sort -u | head -10 || echo "No PostHog keys found"

echo ""
echo "=== GitHub Tokens Found ==="
grep -rEoh '(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})' "$CLAUDE_DIR/debug/" 2>/dev/null | sort -u | head -5 || echo "No GitHub tokens found"

echo ""
echo "=== Bearer Tokens Found ==="
grep -rEo 'Bearer [a-zA-Z0-9_-]{30,}' "$CLAUDE_DIR/debug/" 2>/dev/null | grep -v "Redacted" | head -5 || echo "No Bearer tokens found"

echo ""
echo "=== Summary ==="
echo "If secrets were found above, consider running /log-cleaner:clean to remove old logs"
```

After showing results, recommend running cleanup if secrets are found.
