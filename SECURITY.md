# Security Policy

## Scope
This repository is a penetration-testing framework. Security controls are mandatory for every code change.

## Per-Change Security Checklist (Mandatory)
Every change must satisfy all items below:

- [ ] Threat-model input paths and trust boundaries before editing.
- [ ] Validate/sanitize all external or user-controlled inputs.
- [ ] Avoid `shell=True` and unsafe subprocess patterns. <!-- security-gate: allow-shell-true -->
- [ ] Use least-privilege file handling and safe path resolution.
- [ ] Prevent traversal and symlink clobbering on file writes.
- [ ] Avoid leaking secrets in logs/output/errors.
- [ ] Keep dependency and cryptographic usage safe and modern.
- [ ] Add guardrails for failure modes (timeouts, bounds, size limits).
- [ ] Run targeted checks/tests and capture security-impact notes.

## Commit Requirements (Mandatory)
Every commit message must include non-empty trailers:

- `Security-Checklist: done`
- `Security-Impact: <summary>`
- `Security-Tests: <commands/results>`

These trailers are enforced by the tracked `.githooks/commit-msg` hook and CI.

## Pull Request Requirements (Mandatory)
Every pull request must include:

- A checked security checklist in the PR body.
- A concrete `Security impact` summary.
- Targeted test/check evidence for the change.

This is enforced by `.github/workflows/security-gate.yml`.

## Mandatory Security Gate
Every commit and pull request must pass the security gate:

- Local staged-code gate: `.githooks/pre-commit` -> `scripts/security_gate.py --staged`
- Local commit metadata gate: `.githooks/commit-msg` -> `scripts/security_gate.py --check-commit-msg-file`
- CI gate (push + PR): `.github/workflows/security-gate.yml`

## Local Setup
Enable tracked hooks once per clone:

```bash
git config core.hooksPath .githooks
```

Run staged-code checks manually:

```bash
./.venv/bin/python scripts/security_gate.py --staged
```

Run commit-message checks manually:

```bash
./.venv/bin/python scripts/security_gate.py --check-commit-msg-file .git/COMMIT_EDITMSG
```

If no project venv is available:

```bash
python3 scripts/security_gate.py --staged
```

## Responsible Disclosure
If you find a security issue, do not open a public issue with exploit details. Report privately to maintainers with:

- impact and affected components,
- reproduction steps,
- proposed remediation.
