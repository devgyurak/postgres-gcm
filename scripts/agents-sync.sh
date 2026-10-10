#!/usr/bin/env bash
# Regenerate tool adapters (Cursor .mdc, OpenCode/Codex agents, symlinks) from canonical sources.
# Usage: scripts/agents-sync.sh [--check]
set -euo pipefail
exec python3 "$(dirname "$0")/agents-sync.py" "$@"
