<p align="center">
  <h1 align="center">🛡️ AgentShield</h1>
  <p align="center"><strong>The bulletproof safety harness for autonomous AI coding agents.</strong></p>
  <p align="center">Never let your AI coding agent leak API keys, stage <code>.env</code> files, or execute destructive commands.</p>
</p>

<p align="center">
  <a href="https://github.com/ATP0925/agent-shield/actions"><img src="https://img.shields.io/badge/tests-passing-brightgreen?style=flat-square" alt="Tests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <a href="https://github.com/ATP0925/agent-shield"><img src="https://img.shields.io/badge/python-3.8+-informational?style=flat-square" alt="Python Version"></a>
  <a href="https://github.com/ATP0925/agent-shield"><img src="https://img.shields.io/badge/status-production--ready-success?style=flat-square" alt="Status"></a>
</p>

---

## ⚡ The Problem: Autonomous Agents Have Sudo Over Your Repo

When running autonomous AI agents (like **Claude Code**, **Cursor Composer in YOLO mode**, **Cline**, or **Aider**), you give models permission to execute bash commands and git workflows.

Every developer has faced (or fears) an agent that:
- ❌ Runs `git add .` and accidentally commits your `.env` or `.pem` keys.
- ❌ Commits raw conversation transcripts (`.claude/`, `.cursor/`) containing sensitive tokens.
- ❌ Executes destructive terminal commands (`rm -rf`, `DROP TABLE`, `git push --force`).
- ❌ Exposes private developer emails in git author commits.

**Traditional static linters run too late.** AgentShield acts as a real-time command proxy and pre-commit gate tailored specifically for autonomous agent lifecycles.

---

## 🚀 Quickstart (< 10 Seconds)

### 1. Install
```bash
pip install -e .
```

### 2. Protect Your Repository
Run inside any project directory:
```bash
agentshield init
```
This automatically installs the **Git Pre-Commit** and **Pre-Push** security hooks and creates a customizable `shield.config.json`.

### 3. Verify Health
```bash
agentshield doctor
```

---

## 🌟 Why AgentShield?

| Feature | Gitleaks / TruffleHog | GitHub Push Protection | AgentShield 🛡️ |
| :--- | :---: | :---: | :---: |
| **Agent Tool Call Interception** | ❌ No | ❌ No | ✅ **Yes (Blocks destructive bash)** |
| **Agent Artifacts Protection** (`.claude`, `.cursor`) | ❌ No | ❌ No | ✅ **Yes (Auto-intercepted)** |
| **2-Step Confirmation Gate** | ❌ No | ❌ No | ✅ **Yes (Interactive verify)** |
| **Git Author Anonymization** | ❌ No | ❌ No | ✅ **Yes (Noreply enforcement)** |
| **Zero-Dependency Core** | ⚠️ Complex binaries | ❌ Cloud-only | ✅ **Pure Python / Zero-bloat** |

---

## 🧩 Key Capabilities

### 1. Pre-Commit / Pre-Push PII & Secret Scanner
AgentShield inspects `git diff --cached` and blocks:
* Private Keys (`RSA`, `EC`, `OPENSSH`)
* Cloud API Credentials (AWS `AKIA...`, Google Cloud, GitHub PATs `ghp_...`, Slack, JWTs)
* Unintended Personal Identifiers (customizable via `shield.config.json`)
* Automatically exempts verified GitHub noreply addresses (`*@users.noreply.github.com`).

### 2. Autonomous Command Interceptor
Intercepts agent bash calls before they touch your terminal:
```bash
# Example agent command evaluated before execution
agentshield check-cmd "rm -rf /"
# 🚫 [BLOCKED] AgentShield intercepted high-risk command:
#    Rule: recursive_root_deletion | Risk: CRITICAL
```

### 3. Interactive 2-Step Confirmation Gate
When potential security items or forced overrides are requested, AgentShield enforces a deterministic two-phase gate:
1. **Inspection Step:** Displays masked samples and requires file confirmation.
2. **Authorization Step:** Requires affirmative confirmation phrase before any push.

---

## ⚙️ Configuration (`shield.config.json`)

```json
{
  "version": "1.0.0",
  "security": {
    "block_on_secrets": true,
    "block_on_pii": true,
    "confirmation_steps": 2,
    "exempt_noreply_emails": true
  },
  "protected_patterns": {
    "files": [".env*", "*.pem", "*.key", "id_rsa*", "secrets.*"],
    "agent_artifacts": [".claude/*", ".cursor/*", ".gemini/*"],
    "destructive_commands": ["rm\\s+-rf\\s+[/~]", "git\\s+push\\s+.*--force"]
  },
  "custom_pii_patterns": [],
  "user_settings": {
    "user_alias": "Developer"
  }
}
```

---

## 🧪 Testing

Run comprehensive unit tests:
```bash
python -m unittest discover -s tests
```

---

## 🤝 Contributing & License

Contributions, rules, and ecosystem adapters are welcome!
Licensed under the [MIT License](LICENSE).
