#!/usr/bin/env bash
# ==============================================================================
# AUDITFORGE — ALL-IN-ONE SYSTEM LAUNCHER (KITTY / BASH TERMINAL)
# Starts FastAPI backend (port 8000) and Vite React dashboard (port 5173)
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

COLOR_RESET="\033[0m"
COLOR_BOLD="\033[1m"
COLOR_CYAN="\033[36m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"
COLOR_ORANGE="\033[38;5;208m"

echo -e "${COLOR_ORANGE}${COLOR_BOLD}"
cat << "EOF"
    ___             ___ __  ______                    
   /   | __  ______/ (_) /_/ ____/___  _________ ____ 
  / /| |/ / / / __  / / __/ /_  / __ \/ ___/ __ `/ _ \
 / ___ / /_/ / /_/ / / /_/ __/ / /_/ / /  / /_/ /  __/
/_/  |_\__,_/\__,_/_/\__/_/    \____/_/   \__, /\___/ 
                                         /____/       
EOF
echo -e "${COLOR_RESET}"
echo -e "${COLOR_BOLD}AuditForge — Evidence-First MCP Security Auditor${COLOR_RESET}"
echo -e "${COLOR_CYAN}Evaluation & Live Demonstration Cockpit Launcher${COLOR_RESET}"
echo -e "─────────────────────────────────────────────────────────────"

# 1. Clean up existing stale ports
echo -e "${COLOR_YELLOW}[1/4] Checking and clearing ports 8000 & 5173...${COLOR_RESET}"
fuser -k 8000/tcp > /dev/null 2>&1 || true
fuser -k 5173/tcp > /dev/null 2>&1 || true
sleep 1

# 2. Virtual environment check
PYTHON_BIN=".venv/bin/python"
if [ ! -f "${PYTHON_BIN}" ]; then
    echo -e "${COLOR_RED}[!] Virtualenv python not found at ${PYTHON_BIN}.${COLOR_RESET}"
    exit 1
fi

# Ensure clean child process exit on Ctrl+C
cleanup() {
    trap - EXIT SIGINT SIGTERM
    echo ""
    echo -e "${COLOR_YELLOW}[*] Shutting down AuditForge services gracefully...${COLOR_RESET}"
    [ -n "${BACKEND_PID}" ] && kill "${BACKEND_PID}" 2>/dev/null || true
    [ -n "${FRONTEND_PID}" ] && kill "${FRONTEND_PID}" 2>/dev/null || true
    exit 0
}
trap cleanup EXIT SIGINT SIGTERM

# 3. Launch FastAPI backend on port 8000
echo -e "${COLOR_YELLOW}[2/4] Starting FastAPI backend on http://127.0.0.1:8000...${COLOR_RESET}"
"${PYTHON_BIN}" -m uvicorn auditforge.api.app:app --host 127.0.0.1 --port 8000 > /tmp/auditforge_backend.log 2>&1 &
BACKEND_PID=$!

# Wait for backend health
echo -n "      Waiting for backend to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8000/api/health | grep -q "OK"; then
        echo -e " ${COLOR_GREEN}✔ READY!${COLOR_RESET}"
        break
    fi
    echo -n "."
    sleep 0.5
done

# 4. Launch Vite frontend dashboard on port 5173
echo -e "${COLOR_YELLOW}[3/4] Starting Vite dashboard on http://127.0.0.1:5173...${COLOR_RESET}"
npm --prefix dashboard run dev -- --host 127.0.0.1 --port 5173 > /tmp/auditforge_dashboard.log 2>&1 &
FRONTEND_PID=$!

# Wait for frontend
echo -n "      Waiting for dashboard dev server..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:5173 | grep -q "html"; then
        echo -e " ${COLOR_GREEN}✔ READY!${COLOR_RESET}"
        break
    fi
    echo -n "."
    sleep 0.5
done

echo -e "─────────────────────────────────────────────────────────────"
echo -e "${COLOR_GREEN}${COLOR_BOLD}✔ ALL AUDITFORGE SYSTEMS OPERATIONAL!${COLOR_RESET}"
echo -e "  • ${COLOR_BOLD}Dashboard UI:${COLOR_RESET}   ${COLOR_CYAN}http://127.0.0.1:5173${COLOR_RESET}"
echo -e "  • ${COLOR_BOLD}REST API Docs:${COLOR_RESET}  ${COLOR_CYAN}http://127.0.0.1:8000/docs${COLOR_RESET}"
echo -e "  • ${COLOR_BOLD}API Health:${COLOR_RESET}     ${COLOR_CYAN}http://127.0.0.1:8000/api/health${COLOR_RESET}"
echo -e "  • ${COLOR_BOLD}Intelligence:${COLOR_RESET}   ${COLOR_CYAN}http://127.0.0.1:8000/api/intelligence/status${COLOR_RESET}"
echo -e "  • ${COLOR_BOLD}Reports API:${COLOR_RESET}    ${COLOR_CYAN}http://127.0.0.1:8000/api/reports${COLOR_RESET}"
echo -e "─────────────────────────────────────────────────────────────"
echo -e "${COLOR_YELLOW}[4/4] Opening browser...${COLOR_RESET}"
if command -v xdg-open > /dev/null 2>&1; then
    xdg-open http://127.0.0.1:5173 > /dev/null 2>&1 &
fi

echo -e "${COLOR_BOLD}Press CTRL+C at any time to stop all services.${COLOR_RESET}"
echo -e "Tailing backend and dashboard logs below..."
echo -e "─────────────────────────────────────────────────────────────"

# Tail logs to terminal
tail -f /tmp/auditforge_backend.log /tmp/auditforge_dashboard.log
