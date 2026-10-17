#!/usr/bin/env bash
# Install the engineering runtime locally; credentials and external apps stay local.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
python_bin="${PYTHON:-python3}"
run_tests=true
full=false
for argument in "$@"; do
    case "$argument" in
        --skip-tests) run_tests=false ;;
        --full) full=true ;;
        --help|-h)
            echo 'Usage: bash setup.sh [--skip-tests] [--full]'
            echo 'Python 3.10+ with venv is required. Optional security tools: bash setup-security.sh'
            exit 0 ;;
        *) echo "Unknown option: $argument" >&2; exit 2 ;;
    esac
done
if ! command -v "$python_bin" >/dev/null; then
    echo 'Install Python 3.10+ and its venv package first (Debian/Ubuntu: sudo apt install python3 python3-venv).' >&2
    exit 1
fi
"$python_bin" -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ is required"'
if [[ ! -x .venv/bin/python ]]; then "$python_bin" -m venv .venv; fi
project_python="$PWD/.venv/bin/python"
"$project_python" -m pip install -r requirements-agent.txt
if $full; then "$project_python" -m pip install -r requirements.txt; fi
if [[ ! -e .env ]]; then (umask 077; cp .env.example .env); fi
"$project_python" -m pip check
if $run_tests; then
    "$project_python" -m pip install -r requirements-dev.txt
    "$project_python" -m pytest tests/ -q
fi
"$project_python" -m hydra providers
echo 'HYDRA is ready. Start: bash run.sh'
echo 'Provider keys go in .env. Ollama/models and Burp Suite + its MCP extension are separate applications.'
