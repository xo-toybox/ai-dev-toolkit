#!/bin/bash
# Block access to secrets across all tools and attack vectors
# Full documentation: ~/.claude/hooks/block-env-access.md
#
# Four-layer defense:
#   Layer 0 — Sandbox (OS-level): filesystem/network isolation via macOS Seatbelt
#             or Linux bubblewrap. Blocks reads outside cwd and network to unapproved
#             domains. Enabled only with trusted runtime sandbox signals.
#   Layer 1 — String matching: catches .env/.secret refs in cwd, env dumps, variable
#             expansion, programmatic access (allowlist: only safe vars allowed)
#   Layer 2 — Obfuscation patterns: blocks base64|bash, eval+base64 (zero legit use)
#   Layer 3 — Canary dry-run: for suspicious commands (python -c, ruby -e, etc.),
#             executes against dummy .env with canary values, blocks if output leaks
#
# When sandbox is enabled (Layer 0), the hook skips redundant checks:
#   - blocked-dirs.conf directory loop (sandbox blocks filesystem reads outside cwd)
#   - Exfiltration checks (sandbox blocks network to unapproved domains)
#   This saves ~44 subprocess spawns per Bash call.
#
# Safe escape hatches (allowed):
#   - List key names:        grep ... .env | cut -d= -f1
#   - Check key exists:      grep -qc '^KEY=' .env && echo SET
#   - Check key length:      grep '^KEY=' .env | cut -d= -f2 | wc -c
#   - Validate format:       grep '^KEY=' .env | cut -d= -f2 | grep -qc '^prefix' && echo OK
#   - Sourced subshell:      (set -a && source .env && <command>)
#   - Connectivity test:     curl -s -o /dev/null -w "%{http_code}" ...
#   - Count keys:            grep -cv '^#' .env
#   - Copy from template:    cp .env.example .env.local
#   - Git operations:        git diff/log/status/show on .env files
#   - Docker env-file:       docker run --env-file .env.local
#
# Known accepted risks:
#   - Canary runs in tmpdir with relative paths; commands using absolute paths to
#     real .env files rely on Layer 1 string matching (which does catch them)
#   - Commands that read secrets and exfil silently (no stdout) bypass canary,
#     but are caught by L1 if they reference .env/.secret in the command string
#   - Sophisticated canary evasion (hostname/timing detection) is theoretical
#     and impractical for an AI model to construct unintentionally

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')

# --- Detect sandbox mode from trusted runtime signals ---
# Do not trust repo-local config files to disable protections.
SANDBOX_ENABLED=false
if [[ "${CLAUDE_SANDBOX_ENABLED:-}" == "1" ||
      "${CLAUDE_CODE_SANDBOXED:-}" == "1" ||
      "${CODEX_SANDBOX_ENABLED:-}" == "1" ]]; then
  SANDBOX_ENABLED=true
fi

# Load blocked dirs from private config (only needed without sandbox)
BLOCKED_DIRS=()
if [[ "$SANDBOX_ENABLED" == false ]]; then
  BLOCKED_DIRS_FILE="${BASH_SOURCE[0]%/*}/blocked-dirs.conf"
  if [[ -f "$BLOCKED_DIRS_FILE" ]]; then
    while IFS= read -r line; do
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      [[ -z "${line// }" ]] && continue
      BLOCKED_DIRS+=("${line/#\~/$HOME}")
    done < "$BLOCKED_DIRS_FILE"
  fi
fi

# Load safe env vars from config (allowlist for programmatic access)
SAFE_ENV_VARS_FILE="${BASH_SOURCE[0]%/*}/safe-env-vars.conf"
SAFE_ENV_RE=""
if [[ -f "$SAFE_ENV_VARS_FILE" ]]; then
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// }" ]] && continue
    [[ -n "$SAFE_ENV_RE" ]] && SAFE_ENV_RE+="|"
    SAFE_ENV_RE+="$line"
  done < "$SAFE_ENV_VARS_FILE"
fi
# Fallback if config missing
[[ -z "$SAFE_ENV_RE" ]] && SAFE_ENV_RE="NODE_ENV|PORT|DEBUG|PATH|HOME|SHELL|TERM|USER|CI|EDITOR|LANG|TZ|PWD|TMPDIR"

GUIDANCE="You never need to read or print secret values. Reference secrets by name in code and config — they are resolved at runtime. Safe alternatives: list key names (cut -d= -f1), check existence (grep -qc), validate format (grep -qc pattern), run with env loaded (set -a && source .env && cmd), test connectivity (curl -s -o /dev/null -w status_code)."

block() {
  cat <<EOF
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "BLOCKED: $1 $GUIDANCE"
  }
}
EOF
  exit 0
}

is_blocked_path() {
  local filepath="$1"
  local basename=$(basename "$filepath")

  # Allow safe files
  [[ "$basename" == ".env.example" || "$basename" == ".env.shared" ]] && return 1

  # Block .env* and .secret* by basename
  [[ "$basename" == .env || "$basename" == .env.* || "$basename" == .secret || "$basename" == .secret.* ]] && return 0

  # Block any path containing secret/secrets as a component
  [[ "$filepath" =~ /(\.?secrets?|\.?credentials?)/ ]] && return 0

  # Block direct process environment pseudo-files.
  [[ "$filepath" =~ ^/proc/(self|[0-9]+)/environ$ ]] && return 0

  # Block known sensitive directories (only in full mode)
  if [[ "$SANDBOX_ENABLED" == false ]]; then
    for dir in "${BLOCKED_DIRS[@]}"; do
      [[ "$filepath" == "$dir"* ]] && return 0
    done
  fi

  return 1
}

# Check if command string references .env or .secret files (including absolute paths)
refs_env_files() {
  local cmd="$1"
  # Scrub programmatic env access that looks like .env file references
  local scrubbed
  scrubbed=$(echo "$cmd" | sed -E 's/process\.env\.[A-Za-z_]+/PROC_ENV_VAR/g; s/process\.env([^.])/PROC_ENV\1/g; s/process\.env$//g; s/os\.environ/OS_ENVIRON/g')
  # Match .env/.secret as filename in any context (relative, absolute, quoted)
  echo "$scrubbed" | grep -qE '(^|[\s/'"'"'"])\.env(\.[a-z]+)?(\s|$|'"'"'|")' && return 0
  echo "$scrubbed" | grep -qE '(^|[\s/'"'"'"])\.secret(\.[a-z]+)?(\s|$|'"'"'|")' && return 0
  # Catch shell-built file names such as .$(printf env)
  echo "$scrubbed" | grep -qE '\.\$\([^)]*env[^)]*\)' && return 0
  # Also match the word boundary version for inline references
  echo "$scrubbed" | grep -qE '\.(env|secret)\b' && return 0
  return 1
}

# Check whether command references any unsafe env file (anything except
# .env.example/.env.shared/.env.template).
refs_unsafe_env_files() {
  local cmd="$1"
  local scrubbed
  # Scrub safe env files and programmatic env access patterns
  scrubbed=$(echo "$cmd" | sed -E 's/\.env\.(example|shared|template)([^a-zA-Z0-9]|$)/SAFE_ENV_FILE\2/g; s/process\.env\.[A-Za-z_]+/PROC_ENV_VAR/g; s/process\.env([^.])/PROC_ENV\1/g; s/process\.env$//g; s/os\.environ/OS_ENVIRON/g')

  echo "$scrubbed" | grep -qE '(^|[\s/'"'"'"])\.env(\.[a-zA-Z0-9_.-]+)?(\s|$|'"'"'|")' && return 0
  echo "$scrubbed" | grep -qE '(^|[\s/'"'"'"])\.secret(\.[a-zA-Z0-9_.-]+)?(\s|$|'"'"'|")' && return 0
  # Catch shell-built file names such as .$(printf env)
  echo "$scrubbed" | grep -qE '\.\$\([^)]*env[^)]*\)' && return 0
  echo "$scrubbed" | grep -qE '\.(env|secret)\b' && return 0
  return 1
}

# Catch simple quote-splitting obfuscations like .e''nv and .e"n"v.
refs_obfuscated_env_files() {
  local cmd="$1"
  echo "$cmd" | grep -qE '\.e['"'"'"'"'"'"'"'"']+n['"'"'"'"'"'"'"'"']*v\b' && return 0
  echo "$cmd" | grep -qE '\.e['"'"'"'"'"'"'"'"']*n['"'"'"'"'"'"'"'"']+v\b' && return 0
  echo "$cmd" | grep -qE '\.\$\([^)]*env[^)]*\)' && return 0
  return 1
}

has_high_risk_runtime_ops() {
  local cmd="$1"
  # Exfil and process-environment dumps are never safe in env-loaded shortcuts.
  if echo "$cmd" | grep -qE '(curl|wget|scp|rsync|nc|netcat)\s'; then
    return 0
  fi
  if echo "$cmd" | grep -qE '(printenv|(^|[;&|]\s*)env(\s|$)|export\s+-p|\bset\s*\)|process\.env|os\.environ|ENV\[|ENV\.|ENVIRON)'; then
    return 0
  fi
  # Explicit secret expansion from loaded env.
  if echo "$cmd" | grep -qE '\$[{(]?[A-Z_]*(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY|SERVICE_ROLE)\b'; then
    return 0
  fi
  # Redirecting output from env-loaded command may write secrets to disk.
  if echo "$cmd" | grep -qE '(^|[^>])>>?'; then
    return 0
  fi
  return 1
}

# Allow only documented boolean-chain safe patterns (single-purpose checks).
is_allowed_safe_chain() {
  local cmd="$1"

  # grep -qc '^KEY=' .env && echo SET
  if echo "$cmd" | grep -qE "^\s*grep\s+-qc?\s+['\"][^'\"]+['\"].*\.env([a-zA-Z0-9_.-]+)?\s*&&\s*echo\s+[A-Z_]+\s*$"; then
    return 0
  fi

  # grep '^KEY=' .env | cut -d= -f2 | grep -qc '^prefix' && echo OK
  if echo "$cmd" | grep -qE "^\s*grep\b.*\.env([a-zA-Z0-9_.-]+)?\s*\|\s*cut\s+-d=\s+-f2\s*\|\s*grep\s+-qc?\s+['\"][^'\"]+['\"]\s*&&\s*echo\s+[A-Z_]+\s*$"; then
    return 0
  fi

  return 1
}

is_safe_env_command() {
  local cmd="$1"

  # SAFE: sourced subshell — load env and run a command, but NOT if it dumps env
  # (checked before chain guard because subshells inherently use &&)
  if echo "$cmd" | grep -qE '^\s*\(set\s+-a\s+&&\s+source\s+\S*\.env'; then
    if has_high_risk_runtime_ops "$cmd"; then
      return 1
    fi
    return 0
  fi

  # SAFE: env-loaded command via env $(grep ...) targeting any .env path
  # (checked before chain guard because these inherently use subshells)
  if echo "$cmd" | grep -qE '^\s*env\s+\$\(grep\s+.*\S*\.env'; then
    if has_high_risk_runtime_ops "$cmd"; then
      return 1
    fi
    return 0
  fi

  # SAFE: docker/docker-compose with --env-file (passes file to container, no leak to Claude)
  # (checked before chain guard because docker commands may chain with &&)
  if echo "$cmd" | grep -qE '^\s*(docker|docker-compose|docker compose)\s+.*--env-file\s'; then
    echo "$cmd" | grep -qE '(&&|\|\|)\s*(cat|printenv|env\b|echo)' && return 1
    return 0
  fi

  # Reject arbitrary command chaining for env-referencing commands.
  if echo "$cmd" | grep -qE '(&&|\|\||;)'; then
    if ! is_allowed_safe_chain "$cmd"; then
      return 1
    fi
  fi

  if is_allowed_safe_chain "$cmd"; then
    return 0
  fi

  # Reject obviously risky tools in the "safe env" allowlist path.
  if echo "$cmd" | grep -qiE '(^|[^[:alnum:]_])(cat|head|tail|sed|awk|python3?|ruby|perl|node|php|lua|xxd|base64|hexdump|strings|od|curl|wget|scp|rsync|nc|netcat)([^[:alnum:]_]|$)'; then
    return 1
  fi

  # Reject explicit output redirection from env-referencing commands.
  if echo "$cmd" | grep -qE '(^|[^>])>>?'; then
    return 1
  fi

  # SAFE: list key names only (no values)
  echo "$cmd" | grep -qE '^\s*grep\b.*\.env([a-zA-Z0-9_.-]+)?\b.*\|\s*cut\s+-d=\s+-f1\s*$' && return 0

  # SAFE: count keys
  echo "$cmd" | grep -qE '^\s*grep\s+-cv?\s+.*\.env([a-zA-Z0-9_.-]+)?\s*$' && return 0

  # SAFE: existence check (grep -qc '^KEY=')
  echo "$cmd" | grep -qE "^\s*grep\s+-qc?\s+['\"]\\^[A-Z_]+=?['\"]\s+.*\.env([a-zA-Z0-9_.-]+)?\s*$" && return 0

  # SAFE: key length check (wc -c, no direct value output)
  echo "$cmd" | grep -qE '^\s*grep\b.*\.env([a-zA-Z0-9_.-]+)?\s*\|\s*cut\s+-d=\s+-f2\s*\|\s*wc\s+-c\s*$' && return 0

  # SAFE: format validation (grep -qc pattern — boolean only)
  echo "$cmd" | grep -qE "^\s*grep\b.*\.env([a-zA-Z0-9_.-]+)?\s*\|\s*cut\s+-d=\s+-f2\s*\|\s*grep\s+-qc?\s+['\"]\\^(sb_|sk_|AKIA|eyJ)" && return 0

  # SAFE: copy/move from template to create env files
  echo "$cmd" | grep -qE '^\s*(cp|mv)\s+\S*\.(env\.example|env\.shared|env\.template)\s+\S+\s*$' && return 0

  # SAFE: git operations on env files (secrets don't leak to Claude's context via git)
  echo "$cmd" | grep -qE '^\s*git\s+(diff|log|status|show|blame|ls-files|add|commit|stash|checkout|restore|switch|rm|mv|reset|rebase|merge|cherry-pick|branch|tag|push|pull|fetch|clone|init)\b' && return 0

  # SAFE: connectivity test (curl with -o /dev/null, only status code)
  if echo "$cmd" | grep -qE 'curl\s+.*-o\s+/dev/null.*-w\s+.*http_code' ||
     echo "$cmd" | grep -qE 'curl\s+.*-sf\s+.*-o\s+/dev/null'; then
    return 0
  fi

  return 1
}

### LAYER 3: Canary-based detection ###
# Runs the command in a temp dir with dummy .env containing canary values.
# If canary appears in output, the command would leak secrets.
canary_check() {
  local cmd="$1"
  local CANARY="__CANARY_$(head -c 16 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 12)__"
  local tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" EXIT INT TERM

  # Load canary key names from private config
  local CANARY_KEYS_FILE="${BASH_SOURCE[0]%/*}/canary-keys.conf"
  local canary_content=""
  if [[ -f "$CANARY_KEYS_FILE" ]]; then
    while IFS= read -r line; do
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      [[ -z "${line// }" ]] && continue
      canary_content+="${line}=${CANARY}"$'\n'
    done < "$CANARY_KEYS_FILE"
  else
    # Fallback: minimal generic keys if config missing
    canary_content="SECRET_KEY=${CANARY}"$'\n'"API_KEY=${CANARY}"$'\n'"TOKEN=${CANARY}"$'\n'
  fi

  # Create canary .env files
  for f in .env .env.local .env.production .env.development .env.staging .env.test; do
    echo "$canary_content" > "$tmpdir/$f"
  done

  # Also create decoy structure so environment-detecting commands behave normally
  mkdir -p "$tmpdir/.claude/hooks"
  touch "$tmpdir/.claude/hooks/block-env-access.sh"

  # Run command in temp dir with timeout (macOS compatible), capture output
  local output
  if command -v timeout >/dev/null 2>&1; then
    output=$(cd "$tmpdir" && timeout 3 bash -c "$cmd" 2>&1) || true
  elif command -v gtimeout >/dev/null 2>&1; then
    output=$(cd "$tmpdir" && gtimeout 3 bash -c "$cmd" 2>&1) || true
  else
    # Fallback: perl alarm-based timeout (works on macOS without coreutils)
    output=$(cd "$tmpdir" && perl -e 'alarm 3; exec @ARGV' -- bash -c "$cmd" 2>&1) || true
  fi

  # Check if canary leaked into output
  if echo "$output" | grep -q "$CANARY"; then
    block "Command would expose secret values (canary detected)."
  fi

  # Warn if canary couldn't verify (e.g., interpreter not installed in sandbox)
  if echo "$output" | grep -qiE 'command not found|No such file'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"WARNING: Canary could not verify this command (interpreter unavailable in sandbox). Review carefully before approving — it may access secret files."}}'
    exit 0
  fi
}

### LAYER 2: Obfuscation patterns with no legitimate use ###
check_obfuscation() {
  local cmd="$1"

  # Block decoded content piped to shell execution
  if echo "$cmd" | grep -qE 'base64\s+(-[dD]|--decode).*\|\s*(bash|sh|zsh|fish)'; then
    block "Cannot pipe decoded content to shell."
  fi

  # Block eval of decoded content
  if echo "$cmd" | grep -qE '\beval\s.*base64'; then
    block "Cannot eval decoded content."
  fi
}

### Suspicious command signals (triggers canary check) ###
is_suspicious() {
  local cmd="$1"

  # Always suspicious: inline code execution (can construct any attack)
  echo "$cmd" | grep -qE 'python3?\s+-[ce]|ruby\s+-e|perl\s+-[ep]|node\s+(-e|--eval)|lua\s+-e|php\s+-r|osascript\s+-e|tclsh|wish' && return 0

  # Shell evals are high-risk wrappers that can hide obfuscation.
  echo "$cmd" | grep -qE '(^|[;&|]\s*)(bash|sh|zsh|fish)\s+-[[:alpha:]]*c\s+' && return 0

  # Command substitution can hide secret-file references.
  echo "$cmd" | grep -qE '\.\$\([^)]*env[^)]*\)' && return 0

  # Suspicious only when combined with .env/.secret reference
  if echo "$cmd" | grep -qE '\.(env|secret)\b'; then
    echo "$cmd" | grep -qE 'base64|xxd|eval|awk\s|swift\s' && return 0
  fi

  return 1
}

check_bash_command() {
  local cmd="$1"

  # --- LAYER 2: Hard block zero-legit-use obfuscation ---
  check_obfuscation "$cmd"

  # --- Check safe patterns first (escape hatches) ---
  if refs_obfuscated_env_files "$cmd"; then
    block "Command obfuscates secret file references."
  fi

  if refs_unsafe_env_files "$cmd"; then
    if is_safe_env_command "$cmd"; then
      return 0
    fi
  fi

  # --- File-based attacks ---

  # Block commands referencing .env/.secret files (except .env.example/.env.shared/.env.template)
  if refs_unsafe_env_files "$cmd"; then
    block "Command references secret files."
  fi

  # Block generic secret/credentials path references in shell commands.
  if echo "$cmd" | grep -qE '(^|[[:space:]'"'"'"])[^[:space:]'"'"'"]*/(\.?secrets?|\.?credentials?)(/|[[:space:]'"'"'"]|$)'; then
    block "Command references sensitive directories."
  fi

  # Block direct process environment pseudo-files.
  if echo "$cmd" | grep -qE '/proc/(self|[0-9]+)/environ'; then
    block "Command references process environment files."
  fi

  # Block commands referencing sensitive dirs (only in full mode)
  if [[ "$SANDBOX_ENABLED" == false ]]; then
    for dir in "${BLOCKED_DIRS[@]}"; do
      local pattern="${dir/#$HOME/~}"          # ~/foo form
      local pattern2="${dir/#$HOME/\$HOME}"    # $HOME/foo form
      local basename_dir=$(basename "$dir")
      if echo "$cmd" | grep -qF "$dir" || echo "$cmd" | grep -qF "$pattern" || echo "$cmd" | grep -qF "$pattern2" || echo "$cmd" | grep -qF ".$basename_dir"; then
        block "Command references sensitive directories."
      fi
    done
  fi

  # --- Runtime env dumps (consolidated) ---

  if echo "$cmd" | grep -qE '(^|[;&|]\s*)(printenv|\/usr\/bin\/printenv)(\s|$)|(^|[;&|]\s*)env(\s+-[[:alnum:]-]+)*(\s*$|\s+\|)'; then
    block "Cannot dump environment variables."
  fi
  if echo "$cmd" | grep -qE '(^|[;&|]\s*)(bash|sh|zsh|fish)\s+-[[:alpha:]]*c\s+.*\benv(\s|$|["'"'"'])'; then
    block "Cannot dump environment variables."
  fi
  if echo "$cmd" | grep -qE '^\s*set\s*$|^\s*set\s*\||\|\s*set\s*$|\|\s*set\s*\|'; then
    block "Cannot dump shell variables."
  fi

  # Block variable expansion of known secret vars (consolidated)
  # Uses suffix matching: [A-Z_]*TOKEN catches $TOKEN, $GITHUB_TOKEN, $NPM_TOKEN, etc.
  if echo "$cmd" | grep -qE '\$(SUPABASE_SERVICE_ROLE_KEY|SECRET|[A-Z_]*TOKEN|[A-Z_]*PASSWORD|PRIVATE_KEY|API_KEY)\b|\$\{(SUPABASE_SERVICE_ROLE_KEY|SECRET|[A-Z_]*TOKEN|[A-Z_]*PASSWORD|PRIVATE_KEY|API_KEY)'; then
    block "Cannot expand secret variables."
  fi
  if echo "$cmd" | grep -qE 'echo\s+.*\$[A-Z_]*(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY|SERVICE_ROLE)'; then
    block "Cannot echo secret variables."
  fi

  # Block variable indirection
  if echo "$cmd" | grep -qE '\$\{![A-Z_]*\}'; then
    block "Cannot use variable indirection."
  fi

  # --- Programmatic access (allowlist: block all except safe vars) ---

  # process.env.VAR — scrub safe vars, block if any process.env. remain
  if echo "$cmd" | grep -qE 'process\.env\.[A-Za-z_]'; then
    local check_cmd
    check_cmd=$(echo "$cmd" | sed -E "s/process\.env\.($SAFE_ENV_RE)([^A-Za-z0-9_]|$)/SAFE_PROC_ENV\2/g")
    if echo "$check_cmd" | grep -qE 'process\.env\.[A-Za-z_]'; then
      block "Cannot access environment programmatically."
    fi
  fi
  # process.env[...] (dynamic — always block, can't determine var name)
  if echo "$cmd" | grep -qE 'process\.env\['; then
    block "Cannot access environment programmatically."
  fi
  # Bare process.env (dump via JSON.stringify, Object.keys, etc.)
  if echo "$cmd" | grep -qE 'process\.env([^.\[A-Za-z_]|$)'; then
    block "Cannot access environment programmatically."
  fi

  # os.environ dump methods — always block
  if echo "$cmd" | grep -qE 'os\.environ\.(items|values|copy|keys|pop|setdefault|to)'; then
    block "Cannot access environment programmatically."
  fi
  # os.environ[...] — scrub safe vars, block if any remain
  if echo "$cmd" | grep -qE "os\.environ\["; then
    local check_cmd
    check_cmd=$(echo "$cmd" | sed -E "s/os\.environ\[['\"]($SAFE_ENV_RE)['\"]\]/SAFE_OS_ENV/g")
    if echo "$check_cmd" | grep -qE "os\.environ\["; then
      block "Cannot access environment programmatically."
    fi
  fi
  # os.environ.get() — scrub safe vars, block if any remain
  if echo "$cmd" | grep -qE "os\.environ\.get\("; then
    local check_cmd
    check_cmd=$(echo "$cmd" | sed -E "s/os\.environ\.get\(['\"]($SAFE_ENV_RE)['\"]\)/SAFE_OS_ENV/g")
    if echo "$check_cmd" | grep -qE "os\.environ\.get\("; then
      block "Cannot access environment programmatically."
    fi
  fi
  # Bare os.environ (full dump)
  if echo "$cmd" | grep -qE 'os\.environ([^.\[[]|$)'; then
    block "Cannot access environment programmatically."
  fi

  # ENV (Ruby) dump methods — always block
  if echo "$cmd" | grep -qE 'ENV\.(to_h|to_hash|fetch|values|each|select|reject|map|filter|keys|sort)'; then
    block "Cannot access environment programmatically."
  fi
  # ENV[...] — scrub safe vars, block if any remain
  if echo "$cmd" | grep -qE "ENV\["; then
    local check_cmd
    check_cmd=$(echo "$cmd" | sed -E "s/ENV\[['\"]($SAFE_ENV_RE)['\"]\]/SAFE_RUBY_ENV/g")
    if echo "$check_cmd" | grep -qE "ENV\["; then
      block "Cannot access environment programmatically."
    fi
  fi

  # awk ENVIRON array — always block (dumps process env)
  if echo "$cmd" | grep -qE '\bENVIRON\b'; then
    block "Cannot access environment programmatically."
  fi

  # --- CLI tools that print keys ---

  if echo "$cmd" | grep -qiE 'api-keys|api_keys|env\s+pull|configure\s+list|secret\s+list'; then
    block "Command may print secrets."
  fi

  # --- Obfuscated file reads ---

  if echo "$cmd" | grep -qE '(base64|xxd|od|strings|hexdump)\s' &&
     refs_env_files "$cmd"; then
    block "Cannot use encoding tools on secret files."
  fi

  # --- Exfiltration (only in full mode — sandbox blocks network) ---

  if [[ "$SANDBOX_ENABLED" == false ]]; then
    if echo "$cmd" | grep -qE '(curl|wget|scp|rsync|nc|netcat)\s' &&
       refs_env_files "$cmd"; then
      block "Cannot exfiltrate secret files."
    fi
  fi

  # --- LAYER 3: Canary check for suspicious commands that passed all above ---
  if is_suspicious "$cmd"; then
    canary_check "$cmd"
  fi
}

case "$TOOL_NAME" in
  Read|Write|Edit)
    FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
    if is_blocked_path "$FILE_PATH"; then
      block "This path contains secrets."
    fi
    ;;
  Bash)
    COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
    check_bash_command "$COMMAND"
    ;;
  Grep)
    GREP_PATH=$(echo "$INPUT" | jq -r '.tool_input.path // empty')
    if [[ -n "$GREP_PATH" ]] && is_blocked_path "$GREP_PATH"; then
      block "Cannot search secret files."
    fi
    # Also check glob patterns targeting secret files
    GREP_GLOB=$(echo "$INPUT" | jq -r '.tool_input.glob // empty')
    if [[ -n "$GREP_GLOB" ]] && echo "$GREP_GLOB" | grep -qE '\.env|\.secret'; then
      if ! echo "$GREP_GLOB" | grep -qE '\.env\.example|\.env\.shared'; then
        block "Cannot use glob patterns targeting secret files."
      fi
    fi
    ;;
esac

exit 0
