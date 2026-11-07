# AgentShield Rules for Claude Code

@AGENTS.md

## Claude Code Specifics
- Run tests via `python -m pytest tests/ -v`.
- Before executing git commit or push, run `agentshield scan --cached --non-interactive`.
