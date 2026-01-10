# Claude Log Cleaner

A Claude Code plugin that automatically deletes session log files after a configurable retention period to prevent sensitive data exposure.

## Why This Plugin?

Claude Code stores session logs in `~/.claude/` that can contain sensitive information from your chat sessions, including:

- API keys (OpenAI, Anthropic, PostHog, etc.)
- Bearer tokens and authentication headers
- Database credentials
- Environment variables
- Other secrets passed through commands

This plugin helps you maintain security hygiene by automatically cleaning up old logs.

## Installation

### Step 1: Add the marketplace

```
/plugin marketplace add andrewm4894/claude-log-cleaner
```

### Step 2: Install the plugin

```
/plugin install log-cleaner@log-cleaner-marketplace
```

### Updating

```
/plugin update log-cleaner@log-cleaner-marketplace
```

### Uninstalling

```
# Uninstall the plugin
/plugin uninstall log-cleaner

# Remove the marketplace (optional)
/plugin marketplace remove log-cleaner-marketplace
```

### Reinstalling (fresh install)

If updates aren't working, try a full reinstall:

```
# Remove everything
/plugin uninstall log-cleaner
/plugin marketplace remove log-cleaner-marketplace

# Reinstall
/plugin marketplace add andrewm4894/claude-log-cleaner
/plugin install log-cleaner@log-cleaner-marketplace
```

### Local Development

```bash
# Clone the repository
git clone https://github.com/andrewm4894/claude-log-cleaner.git

# In Claude Code, load the plugin for testing:
claude --plugin-dir /path/to/claude-log-cleaner/plugins/log-cleaner
```

## Commands

| Command | Description |
|---------|-------------|
| `/log-cleaner:clean` | Manually run cleanup |
| `/log-cleaner:status` | Show directory sizes and config |
| `/log-cleaner:set-retention <hours>` | Set retention period |
| `/log-cleaner:scan-secrets` | Scan logs for exposed secrets |

### Examples

```bash
# Check current status
/log-cleaner:status

# Preview what would be deleted (dry run)
/log-cleaner:clean --dry-run

# Set retention to 48 hours
/log-cleaner:set-retention 48

# Delete files older than 1 hour
/log-cleaner:clean --hours 1

# Scan for secrets in your logs
/log-cleaner:scan-secrets
```

## Configuration

The plugin creates a config file at `~/.claude/log-cleaner-config.json`:

```json
{
  "retention_hours": 24,
  "clean_on_session_end": true,
  "dry_run": false
}
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `retention_hours` | 24 | Hours to retain files before deletion |
| `clean_on_session_end` | true | Auto-clean when Claude Code session ends |
| `dry_run` | false | Preview mode (no actual deletion) |

**Note:** Config values are used as defaults. The `--dry-run` CLI flag overrides the config value for that run.

## What Gets Cleaned

The plugin cleans all Claude Code data directories:

- `~/.claude/debug/` - Session debug logs
- `~/.claude/file-history/` - File edit history
- `~/.claude/projects/` - Project-specific data
- `~/.claude/todos/` - Todo lists
- `~/.claude/plans/` - Planning data
- `~/.claude/shell-snapshots/` - Shell state snapshots

## Automatic Cleanup

The plugin hooks into Claude Code's `SessionEnd` event to automatically clean old logs when you finish a session. This ensures cleanup happens regularly without manual intervention.

To disable automatic cleanup, edit the config:

```json
{
  "clean_on_session_end": false
}
```

## Security Considerations

- Logs may contain sensitive data from your conversations
- This plugin helps but is not a complete security solution
- Consider also:
  - Rotating API keys regularly
  - Using environment variables instead of hardcoded secrets
  - Reviewing what data you paste into Claude Code

## License

MIT

## Contributing

Issues and PRs welcome at https://github.com/andrewm4894/claude-log-cleaner
