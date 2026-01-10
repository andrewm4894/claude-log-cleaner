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

# All directories where Claude stores data
SCAN_DIRS=(
    "$CLAUDE_DIR/debug"
    "$CLAUDE_DIR/file-history"
    "$CLAUDE_DIR/projects"
    "$CLAUDE_DIR/todos"
    "$CLAUDE_DIR/plans"
    "$CLAUDE_DIR/shell-snapshots"
)

# Build list of existing directories to scan
EXISTING_DIRS=()
for dir in "${SCAN_DIRS[@]}"; do
    [[ -d "$dir" ]] && EXISTING_DIRS+=("$dir")
done

if [[ ${#EXISTING_DIRS[@]} -eq 0 ]]; then
    echo "No Claude log directories found to scan."
    exit 0
fi

echo "Scanning directories: ${EXISTING_DIRS[*]}"
echo ""

echo "=== OpenAI/Anthropic API Keys ==="
grep -rEoh '(sk-[a-zA-Z0-9_-]{20,}|sk-proj-[a-zA-Z0-9_-]{50,}|sk-ant-[a-zA-Z0-9_-]{20,})' "${EXISTING_DIRS[@]}" 2>/dev/null | sort -u | head -10 || echo "None found"

echo ""
echo "=== PostHog Keys ==="
grep -rEoh '(phc_[a-zA-Z0-9]{30,}|phx_[a-zA-Z0-9_-]{30,})' "${EXISTING_DIRS[@]}" 2>/dev/null | sort -u | head -10 || echo "None found"

echo ""
echo "=== GitHub Tokens ==="
grep -rEoh '(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})' "${EXISTING_DIRS[@]}" 2>/dev/null | sort -u | head -5 || echo "None found"

echo ""
echo "=== AWS Keys ==="
grep -rEoh '(AKIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}|ACCA[0-9A-Z]{16})' "${EXISTING_DIRS[@]}" 2>/dev/null | sort -u | head -5 || echo "None found"

echo ""
echo "=== Slack Tokens ==="
grep -rEoh '(xox[baprs]-[0-9a-zA-Z-]{10,})' "${EXISTING_DIRS[@]}" 2>/dev/null | sort -u | head -5 || echo "None found"

echo ""
echo "=== Bearer Tokens ==="
grep -rEoh 'Bearer [a-zA-Z0-9_-]{30,}' "${EXISTING_DIRS[@]}" 2>/dev/null | grep -v "Redacted" | sort -u | head -5 || echo "None found"

echo ""
echo "=== Private Keys ==="
grep -rl '-----BEGIN .* PRIVATE KEY-----' "${EXISTING_DIRS[@]}" 2>/dev/null | head -5 || echo "None found"

echo ""
echo "=== Summary ==="
echo "If secrets were found above, consider:"
echo "  1. Rotate the exposed credentials immediately"
echo "  2. Run /log-cleaner:clean --all to remove old logs"
```

After showing results, recommend running cleanup if secrets are found.
