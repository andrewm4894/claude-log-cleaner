# Repository Guidelines

## Project Structure & Module Organization
This repository is a Claude Code plugin. Key paths:
- `plugins/log-cleaner/scripts/cleanup.py` holds the main cleanup logic (Python 3.8+, stdlib only).
- `plugins/log-cleaner/commands/` contains slash command definitions (`*.md`).
- `plugins/log-cleaner/hooks/hooks.json` registers the SessionEnd hook.
- `plugins/log-cleaner/.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` store plugin metadata.

## Build, Test, and Development Commands
There is no build step. For local testing, load the plugin in Claude Code:
```bash
claude --plugin-dir /path/to/claude-log-cleaner/plugins/log-cleaner
```
Then exercise commands:
```bash
/log-cleaner:status
/log-cleaner:clean --dry-run
/log-cleaner:set-retention 24
/log-cleaner:scan-secrets
```

## Coding Style & Naming Conventions
- Python: `cleanup.py` uses Python 3.8+ with stdlib only; use type hints, keep functions focused.
- Commands: markdown files in `plugins/log-cleaner/commands/` are kebab-case and map to `/log-cleaner:<command>`.
- Config: use `~/.claude/log-cleaner-config.json` keys like `retention_hours`.

## Testing Guidelines
No automated test suite is defined. Use the slash commands above to validate behavior, and prefer `--dry-run` when verifying deletion logic.

## Commit & Pull Request Guidelines
- Commits use short, imperative messages (e.g., “Add…”, “Update…”, “Bump…”).
- PRs should include a clear description, steps to test, and any behavior changes. Add screenshots only if the command output format changes.

## Security & Configuration Notes
Logs can contain secrets; validate that cleanup does not delete unintended paths and document config changes in `README.md` when adding options.
