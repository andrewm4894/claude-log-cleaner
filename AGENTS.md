# Claude Log Cleaner - Repository Guidelines

A Claude Code plugin that automatically deletes session log files from `~/.claude/` to prevent sensitive data exposure (API keys, tokens, credentials).

## Project Structure

```
.claude-plugin/marketplace.json    # Marketplace config for plugin distribution
plugins/log-cleaner/
├── .claude-plugin/plugin.json     # Plugin metadata (name, version, description)
├── commands/                      # Slash command definitions (markdown files)
├── hooks/hooks.json               # SessionEnd hook configuration
└── scripts/cleanup.py             # Main Python script (all cleanup logic)
```

## Architecture

- **All cleanup logic is in `cleanup.py`** - Python 3.8+, stdlib only. Handles cleanup, status, retention config, and secret scanning.
- **Commands are markdown files** - Each `.md` in `commands/` defines a slash command that delegates to `cleanup.py`
- **Hook runs on session end** - `hooks.json` triggers `cleanup.py clean` when Claude Code session ends
- **Config stored in `~/.claude/log-cleaner-config.json`** - Created on first run with defaults
- **Directories cleaned**: `debug`, `file-history`, `projects`, `todos`, `plans`, `shell-snapshots`

## Local Development

```bash
# Install dependencies
uv sync

# Load plugin in Claude Code
claude --plugin-dir /path/to/claude-log-cleaner/plugins/log-cleaner
```

Test slash commands:
- `/log-cleaner:status` - Verify status output
- `/log-cleaner:clean --dry-run` - Test cleanup without deletion
- `/log-cleaner:set-retention 24` - Test config modification
- `/log-cleaner:scan-secrets` - Test secret scanning

## Running Tests

```bash
# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -v

# Run with coverage
uv run pytest --cov=plugins/log-cleaner/scripts --cov-report=term-missing
```

## Coding Style

- **Python**: Use type hints, keep functions focused, stdlib only
- **Commands**: Markdown files in `commands/` are kebab-case, map to `/log-cleaner:<command>`
- **Config**: Keys use snake_case (e.g., `retention_hours`)

## Version Bumping

When releasing, update version in both:
1. `plugins/log-cleaner/.claude-plugin/plugin.json`
2. `.claude-plugin/marketplace.json`

## Commits & PRs

- Commits: short, imperative messages (e.g., "Add…", "Fix…", "Update…")
- PRs: clear description, steps to test, note behavior changes

## Security Notes

Logs can contain secrets. Validate that cleanup does not delete unintended paths. Document config changes in `README.md`.
