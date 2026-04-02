# Skill Safety Checklist

Use this checklist when the target skill needs deeper review than the scanner output alone.

## High-risk areas

### Destructive operations

Look for instructions or scripts that can:

- delete data or directories
- rewrite git history
- overwrite system files
- modify credentials or authentication state

These are usually blocking unless the skill clearly limits scope and requires explicit approval.

### Privilege escalation

Look for:

- `sandbox_permissions: require_escalated`
- instructions that ask for elevated access without a narrow justification
- commands that write outside the workspace or touch user-global config

Escalation is not automatically wrong, but unclear escalation is.

### Secret handling and exfiltration

Look for:

- requests for API keys, tokens, passwords, cookies, or SSH material
- scripts that print secrets, upload them, or pass them to third parties
- environment dumps and credential file reads

Skills should avoid collecting secrets unless the task truly requires it and the workflow is explicit about scope.

### Remote execution

Look for:

- download-and-run shell pipelines
- dynamic execution through `eval`, `exec`, or shell interpolation
- helper scripts that fetch remote content and execute it locally

This is a common blocking category.

### Network egress

Look for outbound HTTP requests, uploads, webhooks, or hidden telemetry.

If network access is necessary, the skill should make the destination and purpose obvious.

## Medium-risk areas

### Overbroad instructions

Look for workflows that:

- do more than the user's request
- push, deploy, merge, publish, or modify live systems by default
- assume destructive cleanup is acceptable

### Hidden automation

Look for scripts or helper files that the main `SKILL.md` does not disclose clearly.

### Safety ambiguity

Look for instructions that are underspecified around scope, target path, branch, account, or environment.

## Low-risk but worth noting

- unnecessary noise or generated artifacts
- poor validation steps
- missing rollback notes for risky workflows
- missing mention of side effects
