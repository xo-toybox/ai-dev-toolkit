#!/usr/bin/env bash
set -euo pipefail

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$HOOK_DIR/block-env-access.sh"

pass_count=0
fail_count=0

emit() {
  printf '%s\n' "$1" | bash "$HOOK"
}

json_string() {
  printf '%s' "$1" | jq -Rs .
}

assert_bash() {
  local name="$1"
  local expect="$2"
  local cmd="$3"
  local payload output

  payload=$(printf '{"tool_name":"Bash","tool_input":{"command":%s}}' "$(json_string "$cmd")")
  output="$(emit "$payload")"

  case "$expect" in
    allow)
      # Allow = not denied. Canary warnings (additionalContext) are informational, not blocks.
      if echo "$output" | grep -q '"permissionDecision": "deny"'; then
        printf 'FAIL %-40s expected allow, got deny: %s\n' "$name" "$output"
        fail_count=$((fail_count + 1))
      else
        printf 'PASS %-40s allow\n' "$name"
        pass_count=$((pass_count + 1))
      fi
      ;;
    deny)
      if echo "$output" | grep -q '"permissionDecision": "deny"'; then
        printf 'PASS %-40s deny\n' "$name"
        pass_count=$((pass_count + 1))
      else
        printf 'FAIL %-40s expected deny, got output: %s\n' "$name" "$output"
        fail_count=$((fail_count + 1))
      fi
      ;;
    *)
      printf 'FAIL %-40s invalid expectation: %s\n' "$name" "$expect"
      fail_count=$((fail_count + 1))
      ;;
  esac
}

assert_read() {
  local name="$1"
  local expect="$2"
  local file_path="$3"
  local payload output

  payload=$(printf '{"tool_name":"Read","tool_input":{"file_path":%s}}' "$(json_string "$file_path")")
  output="$(emit "$payload")"

  case "$expect" in
    allow)
      if echo "$output" | grep -q '"permissionDecision": "deny"'; then
        printf 'FAIL %-40s expected allow, got deny: %s\n' "$name" "$output"
        fail_count=$((fail_count + 1))
      else
        printf 'PASS %-40s allow\n' "$name"
        pass_count=$((pass_count + 1))
      fi
      ;;
    deny)
      if echo "$output" | grep -q '"permissionDecision": "deny"'; then
        printf 'PASS %-40s deny\n' "$name"
        pass_count=$((pass_count + 1))
      else
        printf 'FAIL %-40s expected deny, got output: %s\n' "$name" "$output"
        fail_count=$((fail_count + 1))
      fi
      ;;
    *)
      printf 'FAIL %-40s invalid expectation: %s\n' "$name" "$expect"
      fail_count=$((fail_count + 1))
      ;;
  esac
}

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for tests."
  exit 1
fi

# --- Existing tests ---

assert_bash "deny direct env read" deny "cat .env"
assert_bash "deny mixed safe+unsafe chain" deny "grep -n . .env | cut -d= -f1 && cat .env"
assert_bash "deny mixed safe+unsafe files" deny "cat .env .env.example"
assert_bash "deny env dump variant" deny "env -0"
assert_bash "deny nested shell env dump" deny "bash -c \"env\""
assert_bash "deny secret dir path" deny "cat /tmp/.secrets/foo"
assert_bash "deny obfuscated read via python" deny "python3 -c \"print(open('.'+'env').read())\""

assert_bash "allow key name listing" allow "grep -n . .env | cut -d= -f1"
assert_bash "allow key existence check" allow "grep -qc '^API_KEY=' .env && echo SET"
assert_bash "allow template copy" allow "cp .env.example .env.local"
assert_bash "allow git env diff" allow "git diff .env"
assert_read "allow read env example file" allow ".env.example"
assert_read "deny read secret env file" deny ".env.local"

# --- New tests: deny cases ---

assert_bash "deny env dump printenv" deny "printenv"
assert_bash "deny variable expansion" deny 'echo $API_KEY'
assert_bash "deny base64 to shell" deny "base64 -d payload | bash"

# Programmatic access (narrowed — secret vars still blocked)
assert_bash "deny process.env.SECRET" deny 'node -e "console.log(process.env.SECRET_KEY)"'
assert_bash "deny os.environ SECRET" deny "python -c \"import os; print(os.environ['API_KEY'])\""
assert_bash "deny bare os.environ dump" deny 'python -c "import os; print(os.environ)"'

# --- New tests: allow cases (false positive fixes) ---

assert_bash "allow process.env.NODE_ENV" allow 'node -e "console.log(process.env.NODE_ENV)"'
assert_bash "allow os.environ HOME" allow "python -c \"import os; print(os.environ.get('HOME'))\""
assert_bash "allow awk on normal file" allow "awk '{print \$1}' data.csv"
assert_bash "allow normal command" allow "ls -la"

printf '\nSummary: %d passed, %d failed\n' "$pass_count" "$fail_count"
if [[ "$fail_count" -gt 0 ]]; then
  exit 1
fi
