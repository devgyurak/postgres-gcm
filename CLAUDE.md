@AGENTS.md

# Claude Code supplement

- Rule sources live in `.agents/rules/*.md`. Claude reads the `.claude/rules/*.md` that
  `scripts/agents-sync.sh` generates from them (the `paths:` front matter and the body are preserved).
  Never edit a generated file.
- Skill sources live in `.agents/skills/` (`.claude/skills/` is a symlink to it). Subagent sources live
  in `.claude/agents/`. Edit the source, then re-run `scripts/agents-sync.sh` to regenerate the
  per-tool adapters.
- Permissions and hooks are in `.claude/settings.json`. The `.claude/hooks/guard.sh` hook blocks
  force-pushes, the staging of key files and turning on statement logging. Do not work around it —
  tell the user it fired.
- Delegate investigation that parallelises — confirming a server header, checking vectors, reading
  build logs — to a subagent and take only the conclusion.
- Show a plan with EnterPlanMode before a large change: the envelope format, a GUC name, a function
  signature, or the CI matrix.
- Report build and test results as they are. A failing test is not written off as "an environment
  problem".
