#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv/bin/python ]]; then
    echo 'Run bash setup.sh first.' >&2
    exit 1
fi
export PATH="$PWD/.tools/bin:$PWD/.venv/bin:$PATH"
exec .venv/bin/python -m hydra "$@"
