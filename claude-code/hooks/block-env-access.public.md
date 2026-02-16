# block-env-access.sh

A global [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) for Claude Code that prevents accidental secret leakage. Sandbox-first design: enables OS-level isolation as the primary defense layer, with hook-based string matching, obfuscation blocking, and canary detection for threats the sandbox can't see.

## Why

AI coding assistants can inadvertently expose secrets by running commands like `cat .env.local`, `printenv`, or `supabase projects api-keys`. Once a secret appears in the conversation context, it's compromised. This hook prevents that class of errors entirely.

## How It Works

Four layers of defense:

| Layer | What it does | Latency |
|-------|-------------|---------|
| **Sandbox (OS-level)** | Filesystem/network isolation via macOS Seatbelt or Linux bubblewrap. Blocks reads outside cwd and network to unapproved domains. | 0 ms (kernel) |
| **String matching** | Scans command text for `.env` files in cwd, env dumps (`printenv`, `env`), variable expansion (`$SECRET`), and programmatic access (allowlist: only safe env vars like `NODE_ENV` allowed) | ~5 ms |
| **Obfuscation blocklist** | Blocks patterns with zero legitimate use (e.g., `base64 -d \| bash`, `eval` + `base64`) | ~5 ms |
| **Canary dry-run** | For suspicious commands (inline scripts, eval), executes against dummy `.env` files containing a randomized canary token. If the canary appears in output, the command would have leaked secrets. | ~200 ms |

The hook auto-detects whether sandbox is enabled by reading `.claude/settings.local.json` and `.claude/settings.json`. When sandbox is active, redundant checks (blocked-dirs loop, exfiltration detection) are skipped automatically — saving ~44 subprocess spawns per Bash call.

The canary layer catches novel obfuscation that string matching can't anticipate (e.g., `python3 -c "open('.e'+'nv').read()"`).

## What It Blocks

- **File reads**: `cat .env.local`, `Read .env`, `head .env.production`
- **Env dumps**: `printenv`, `env`, `set`, `echo $SECRET_KEY`
- **Programmatic access**: `process.env.DATABASE_URL`, `os.environ['STRIPE_SK']`, `ENV['REDIS_URL']`, `awk ENVIRON`, bare `process.env` dumps — any env var not in the safe allowlist
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
- **Git operations**: `git diff/log/status/show/add/commit/stash/...` on `.env` files
- **Docker env-file**: `docker run --env-file .env.local`
- **Safe files**: `.env.example` and `.env.shared` are always allowed
- **Safe env vars**: `process.env.NODE_ENV`, `os.environ.get('HOME')`, `ENV['PATH']` — vars listed in `safe-env-vars.conf` are allowed

## Installation

### Recommended: Enable Sandbox

Add sandbox configuration to your `~/.claude/settings.json`:

```json
{
  "sandbox": {
    "enabled": true,
    "autoAllowBashIfSandboxed": true,
    "excludedCommands": ["docker", "docker-compose"],
    "allowUnsandboxedCommands": true,
    "network": {
      "allowedDomains": [
        "registry.npmjs.org",
        "github.com",
        "api.github.com",
        "pypi.org",
        "files.pythonhosted.org",
        "api.anthropic.com"
      ],
      "allowLocalBinding": true
    }
  }
}
```

The hook will auto-detect sandbox mode and skip redundant checks. You can override per-repo with `.claude/settings.local.json` containing `"sandbox": { "enabled": false }`.

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
cp safe-env-vars.example.conf ~/.claude/hooks/safe-env-vars.conf
```

### 2. Customize configs

Edit `~/.claude/hooks/blocked-dirs.conf` — add directories you want protected (only used when sandbox is not enabled):
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

Edit `~/.claude/hooks/safe-env-vars.conf` — add env var names that are safe to access programmatically (everything else is blocked):
```
NODE_ENV
PORT
DEBUG
PATH
HOME
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

## With Sandbox vs Without Sandbox

The hook auto-detects sandbox mode at startup and adapts its behavior:

| Check | With Sandbox | Without Sandbox |
|-------|-------------|-----------------|
| `.env`/`.secret` in cwd | Runs | Runs |
| Env dumps, var expansion | Runs | Runs |
| Programmatic access | Runs | Runs |
| Obfuscation blocklist | Runs | Runs |
| Canary dry-run | Runs | Runs |
| Blocked-dirs loop | **Skipped** | Runs |
| Exfiltration checks | **Skipped** | Runs |

No manual mode switching required — the script reads your settings and adapts.

## Configuration Files

| File | Published | Purpose |
|------|-----------|---------|
| `block-env-access.sh` | Yes | The hook script |
| `blocked-dirs.example.conf` | Yes | Example directory blocklist |
| `canary-keys.example.conf` | Yes | Example canary key names |
| `safe-env-vars.example.conf` | Yes | Example safe env var allowlist |
| `blocked-dirs.conf` | No (private) | Your actual directory blocklist (only used without sandbox) |
| `canary-keys.conf` | No (private) | Your actual canary key names |
| `safe-env-vars.conf` | No (private) | Your actual safe env var allowlist |

The `.conf` files are loaded at runtime from the same directory as the script. If missing, the script falls back to minimal defaults.

## Known Limitations

- **Canary uses relative paths**: Commands using absolute paths to real `.env` files rely on string matching (Layer 1) rather than the canary.
- **Silent exfiltration**: Commands that read secrets without producing stdout (e.g., write to a file) bypass the canary. With sandbox enabled, the OS blocks network exfiltration. Without sandbox, mitigated by Layer 1 blocking network tools combined with `.env` references.
- **Fail-open for missing interpreters**: If a suspicious command uses an interpreter not installed on your system, the canary can't verify it. A warning is shown instead of a block.
- **Sandbox cwd gap**: The sandbox allows full read/write to the current working directory, which is where `.env` files live. This is exactly the gap the hook covers.

## Requirements

- Bash 4+
- `jq` (for parsing hook input and sandbox detection)
- macOS or Linux (uses `perl` alarm fallback if `timeout`/`gtimeout` unavailable)
