# AgentShield Guidelines for AI Agents (Claude Code, OpenAI Codex, Antigravity, Cursor)

AgentShield protects your repository against accidental secret leaks, PII exposure, and destructive terminal commands.

## Available Agent Commands
- **Scan Staged Changes**: `agentshield scan --cached`
- **Scan Working Tree**: `agentshield scan`
- **Verify Safe Command**: `agentshield check-cmd "<command>"`
- **System Health**: `agentshield doctor`

## Agent Protocols
1. Always run `agentshield scan --cached` before proposing git commits.
2. If secrets or PII are detected, redact or anonymize them before proceeding.
3. For destructive commands (`rm -rf`, `git push --force`), AgentShield blocks automated execution without explicit confirmation.
