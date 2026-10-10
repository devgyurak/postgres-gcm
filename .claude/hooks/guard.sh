#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# PreToolUse(Bash) guard. Exit 2 blocks the tool call (message on stderr); exit 0 allows.
# Blocks: force-push, staging/committing key material, turning on statement logging.
# Logic lives in guard.py so the hook JSON on stdin is not shadowed by a heredoc.
set -euo pipefail
exec python3 "$(dirname "$0")/guard.py"
