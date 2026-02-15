# ai-dev-toolkit

> **Status: Early development** — APIs and conventions may change.

Tools and hooks for AI-assisted development workflows.

## Contents

### [claude-code/hooks/block-env-access](claude-code/hooks/block-env-access.public.md)

A sandbox-first PreToolUse hook for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that prevents accidental secret leakage. Four-layer defense: OS-level sandbox, string matching, obfuscation blocklist, and canary-based detection.

## License

MIT
