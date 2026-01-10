# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Claude Code plugin that automatically deletes session log files from `~/.claude/` to prevent sensitive data exposure (API keys, tokens, credentials). It hooks into Claude Code's `SessionEnd` event for automatic cleanup.

## Repository Structure

```
.claude-plugin/marketplace.json    # Marketplace config for plugin distribution
plugins/log-cleaner/
├── .claude-plugin/plugin.json     # Plugin metadata (name, version, description)
├── commands/                      # Slash command definitions (markdown files)
├── hooks/hooks.json               # SessionEnd hook configuration
└── scripts/cleanup.py             # Main Python script (all cleanup logic)
```

## Local Development

Test the plugin locally with Claude Code:
```bash
claude --plugin-dir /path/to/claude-log-cleaner/plugins/log-cleaner
```

## Testing Commands

After loading the plugin locally, test the slash commands:
- `/log-cleaner:status` - Verify status output
- `/log-cleaner:clean --dry-run` - Test cleanup without deletion
- `/log-cleaner:set-retention 24` - Test config modification
- `/log-cleaner:scan-secrets` - Test secret scanning

## Architecture Notes

- **All cleanup logic is in `cleanup.py`** - A single Python script (3.8+, stdlib only) handles cleanup, status, retention configuration, and secret scanning
- **Commands are markdown files** - Each `.md` file in `commands/` defines a slash command that delegates to `cleanup.py`
- **Hook runs on session end** - `hooks.json` triggers `cleanup.py clean` when Claude Code session ends
- **Config stored in `~/.claude/log-cleaner-config.json`** - Created on first run with defaults
- **All directories cleaned by default**: `debug`, `file-history`, `projects`, `todos`, `plans`, `shell-snapshots`

## Version Bumping

When releasing, update version in both:
1. `plugins/log-cleaner/.claude-plugin/plugin.json`
2. `.claude-plugin/marketplace.json`
