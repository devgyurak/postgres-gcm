---
paths:
  - "scripts/**/*.py"
  - "tests/e2e/**/*.py"
  - "tests/load/**/*.py"
  - "**/*.py"
---
# Python conventions

- 3.10+, as few dependencies as possible. Python is for internal tools and SQL test runners only.
- Vector checks use `cryptography`. The E2E and load runners use `psycopg` (3.x), and encrypt and
  decrypt only through the server's SQL functions.
- Keys travel as **bind parameters**, never interpolated into SQL text (docs/ops-constraints.md item 1).
- `ruff` (lint + format) and `mypy --strict`. A `# type: ignore` needs a reason.
- No public encrypt/decrypt/parse API.
- Load and E2E scripts: `argparse`, JSON results on stdout, the human summary on stderr, the gate
  result in the exit code.
- Connection details from environment variables (`PGHOST` and friends) only. No password in code.
