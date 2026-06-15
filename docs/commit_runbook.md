# Commit Runbook

Use this runbook before every commit so project history remains reviewable and traceable.

## Pre-Commit Checklist

1. Review the worktree with `git status --short`.
2. Review the relevant diffs with `git diff -- <paths>`.
3. Split unrelated changes into separate commits.
4. Update `CHANGELOG.md` with a dated entry for user-visible behavior, workflow changes, report changes, or operational fixes.
5. Run targeted validation for the changed area.
6. Run `git diff --check`.
7. Stage only the files that belong to the intended commit.
8. Use a specific commit message that states the change and scope.

## Message Guidance

Prefer concise imperative messages:

- `Improve VA scan ingestion performance`
- `Add Rapid7 category parity`
- `Expose VA credential mode selection`

Avoid vague messages such as:

- `updates`
- `fixes`
- `misc changes`

## Commit Flow

```bash
git status --short
git diff --check
git add <relevant-files>
git commit -m "Specific change summary"
git status --short
```

## Push Flow

Push only after all intended commits are present and local validation has passed:

```bash
git log --oneline --decorate -5
git push origin <branch>
```
