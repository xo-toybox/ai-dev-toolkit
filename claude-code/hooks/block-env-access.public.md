# block-env-access.sh

A global [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) for Claude Code that prevents accidental secret leakage. It intercepts tool calls before execution and blocks any that would read, print, or exfiltrate secret values.

## Why

AI coding assistants can inadvertently expose secrets by running commands like `cat .env.local`, `printenv`, or `supabase projects api-keys`. Once a secret appears in the conversation context, it's compromised. This hook prevents that class of errors entirely.

## How It Works

Three layers of defense, applied in order:

| Layer | What it does | Latency |
|-------|-------------|---------|
| **String matching** | Scans command text for references to `.env` files, secret directories, env dumps, and known dangerous patterns | ~5 ms |
| **Obfuscation blocklist** | Blocks patterns with zero legitimate use (e.g., `base64 -d \| bash`, `eval` + `base64`) | ~5 ms |
| **Canary dry-run** | For suspicious commands (inline scripts, eval), executes against dummy `.env` files containing a randomized canary token. If the canary appears in output, the command would have leaked secrets. | ~200 ms |

The canary layer catches novel obfuscation that string matching can't anticipate (e.g., `python3 -c "open('.e'+'nv').read()"`).

## What It Blocks

- **File reads**: `cat .env.local`, `Read .env`, `head .env.production`
- **Env dumps**: `printenv`, `env`, `set`, `echo $SECRET_KEY`
- **Sensitive directories**: Configurable list (e.g., `~/.ssh`, `~/.aws`)
- **Programmatic access**: `process.env.X`, `os.environ['X']`
- **Encoding/exfiltration**: `base64 .env`, `curl -d @.env`
- **Obfuscated reads**: String concatenation, eval chains, decoded shell pipes

## What It Allows

The hook includes escape hatches for legitimate development workflows that reference `.env` files without leaking values:

- **List key names**: `grep ... .env | cut -d= -f1`
- **Check key exists**: `grep -qc '^KEY=' .env && echo SET`
- **Check key length**: `grep '^KEY=' .env | cut -d= -f2 | wc -c`
- **Count keys**: `grep -cv '^#' .env`
- **Sourced subshell**: `(set -a && source .env && <command>)` — secrets stay in subshell
- **Connectivity test**: `curl -s -o /dev/null -w "%{http_code}" ...`
- **Copy from template**: `cp .env.example .env.local`
- **Git operations**: `git diff/log/status/show` on `.env` files
- **Docker env-file**: `docker run --env-file .env.local`
- **Safe files**: `.env.example` and `.env.shared` are always allowed

## Installation

### 1. Copy files

```bash
# Create hooks directory
mkdir -p ~/.claude/hooks

# Copy the hook script
cp block-env-access.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/block-env-access.sh

# Create your config files from examples
cp blocked-dirs.example.conf ~/.claude/hooks/blocked-dirs.conf
cp canary-keys.example.conf ~/.claude/hooks/canary-keys.conf
```

### 2. Customize configs

Edit `~/.claude/hooks/blocked-dirs.conf` — add directories you want protected:
```
~/.ssh
~/.aws
~/.gnupg
~/.config/gcloud
```

Edit `~/.claude/hooks/canary-keys.conf` — add env var names used in your projects:
```
DATABASE_URL
STRIPE_SECRET_KEY
OPENAI_API_KEY
```

### 3. Register the hook

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Write|Edit|Bash|Grep",
        "hooks": [
          {
            "type": "command",
            "command": "bash ~/.claude/hooks/block-env-access.sh"
          }
        ]
      }
    ]
  }
}
```

### 4. Verify

Start a new Claude Code session and try:
```
cat .env.local
```

You should see a block message with guidance on safe alternatives.

## Configuration Files

| File | Published | Purpose |
|------|-----------|---------|
| `block-env-access.sh` | Yes | The hook script |
| `blocked-dirs.example.conf` | Yes | Example directory blocklist |
| `canary-keys.example.conf` | Yes | Example canary key names |
| `blocked-dirs.conf` | No (private) | Your actual directory blocklist |
| `canary-keys.conf` | No (private) | Your actual canary key names |

The `.conf` files are loaded at runtime from the same directory as the script. If missing, the script falls back to minimal defaults.

## Known Limitations

- **Canary uses relative paths**: Commands using absolute paths to real `.env` files rely on string matching (Layer 1) rather than the canary.
- **Silent exfiltration**: Commands that read secrets without producing stdout (e.g., write to a file) bypass the canary. Mitigated by Layer 1 blocking network tools combined with `.env` references.
- **Fail-open for missing interpreters**: If a suspicious command uses an interpreter not installed on your system, the canary can't verify it. A warning is shown instead of a block.

## Requirements

- Bash 4+
- `jq` (for parsing hook input)
- macOS or Linux (uses `perl` alarm fallback if `timeout`/`gtimeout` unavailable)
