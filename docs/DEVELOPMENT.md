# AUDITFORGE DEVELOPER GUIDE

## 1. Local Environment Setup

### Prerequisites
- Python 3.12 (tested: CPython 3.12.13)
- `uv` package installer
- Docker engine running
- Ollama service running (`systemctl status ollama`) with `qwen3.5:9b` or `llama3.2:latest`
- Node.js >= 20 and npm >= 10

### Setup Commands
```bash
# Set up virtual environment using Python 3.12
uv venv --python /home/psw/.local/bin/python3.12 .venv
source .venv/bin/activate

# Install editable package with dev dependencies
uv pip install -e ".[dev]"

# Install dashboard frontend dependencies
cd dashboard && npm install && cd ..
```

---

## 2. Running Verification & Diagnostics

```bash
# Run system doctor to check runtime, Docker, Ollama, and SQLite
python -m auditforge.cli doctor

# Run fast unit tests
python -m pytest tests/unit/ -v

# Run the master verification script
bash scripts/verify.sh
```

---

## 3. Running Services Locally

### Starting the FastAPI Backend
```bash
python -m uvicorn auditforge.api.app:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be accessible at: `http://127.0.0.1:8000/docs`

### Starting the React Dashboard
```bash
cd dashboard
npm run dev
```
Dashboard will be accessible at: `http://localhost:3000` or `http://localhost:5173`

---

## 4. Git Worktree Workflow

When switching to an assigned feature branch, navigate to its dedicated worktree directory:
```bash
# Work on MCP client discovery
cd ../auditforge-mcp

# Work on Static AST & Qwen LLM
cd ../auditforge-analysis

# Work on Docker sandbox & Prober
cd ../auditforge-sandbox

# Work on Reports, FastAPI & Dashboard
cd ../auditforge-ui
```
All worktrees share the same underlying repository objects while keeping separate checkouts.
