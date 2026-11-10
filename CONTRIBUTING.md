# Contributing to AgentShield

Thank you for your interest in contributing to **AgentShield**! We welcome bug reports, security rules, new provider patterns, and documentation improvements.

## How to Contribute

### 1. Finding an Issue
Check out our open issues tagged with `good first issue` or `help wanted`.

### 2. Developing Locally
1. Fork the repository and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/agent-shield.git
   cd agent-shield
   ```
2. Create a virtual environment and install development dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e .
   ```
3. Run the automated test suite:
   ```bash
   python -m unittest discover -s tests
   ```

### 3. Submitting Pull Requests
- Keep PRs focused on a single bug or enhancement.
- Ensure all unit tests pass before opening your PR.
- Follow conventional commits (`feat:`, `fix:`, `docs:`, `test:`).
- Community PRs are reviewed and merged quickly!
