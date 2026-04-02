---
name: review-skill-safety
description: Review a Codex skill or skill-style folder for safety risks, including dangerous scripts, privilege escalation, secret handling, network exfiltration, destructive commands, and unsafe workflow instructions.
---

# Review Skill Safety

Use this skill when the user asks to audit a skill for safety, review whether a skill should be merged, or check a skill folder for destructive behavior, secret exposure, or unsafe tool usage.

Do not use it for general code review unless the main subject is a skill folder or `SKILL.md`-driven automation.

## What to review

Audit the target skill for:

- destructive commands or irreversible workflow steps
- privilege escalation and `require_escalated` usage
- secret collection, token handling, or credential exfiltration
- remote code execution patterns and dangerous shell pipelines
- network egress hidden inside helper scripts
- instructions that exceed the user's stated intent
- vague or misleading instructions that could cause unsafe execution

## Workflow

1. Identify the target skill directory.
2. List the files with `rg --files <skill-dir>`.
3. Run the bundled scanner:
   `python review-skill-safety/scripts/scan_skill_risks.py <skill-dir>`
4. Read `SKILL.md` first, then only the suspicious files or files named by the scanner.
5. If needed, read [references/checklist.md](references/checklist.md) for the review rubric.
6. Produce findings ordered by severity with file and line references.

## Review rules

- Treat the scanner as a prefilter, not as proof.
- Only report issues you can defend from the actual file contents.
- Distinguish between:
  - explicit dangerous behavior
  - risky defaults
  - non-blocking residual risk
- If a risky operation is intentional, check whether the skill clearly scopes it, explains why it is needed, and requires explicit user approval where appropriate.
- Flag hidden side effects harder than obvious ones. A dangerous operation buried in a helper script is worse than one stated plainly in the workflow.

## Output format

Use this structure:

```md
## Verdict
`BLOCK|NEEDS_ATTENTION|NO_BLOCKING_FINDINGS`
One-line conclusion.

## Findings
1. [severity] path:line - title
   Evidence: ...
   Risk: ...
   Fix: ...

## Residual Risks
- ...
```

If there are no findings, say `没有发现足以阻塞合并的明确安全问题。`
