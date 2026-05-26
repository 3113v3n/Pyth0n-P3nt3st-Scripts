## Summary

Describe the change and why it is needed.

## Security Checklist (Mandatory)

- [ ] Threat-model input paths and trust boundaries
- [ ] Validate/sanitize all external or user-controlled inputs
- [ ] Avoid shell=True and unsafe subprocess patterns <!-- security-gate: allow-shell-true -->
- [ ] Use least-privilege file handling and safe path resolution
- [ ] Prevent traversal and symlink clobbering on file writes
- [ ] Avoid leaking secrets in logs/output/errors
- [ ] Keep dependency and cryptographic usage safe and modern
- [ ] Add guardrails for failure modes
- [ ] Run targeted checks/tests and capture security-impact notes

## Security Notes (Mandatory)

Security impact: <none|low|medium|high + summary>
Security tests: <commands/results>
