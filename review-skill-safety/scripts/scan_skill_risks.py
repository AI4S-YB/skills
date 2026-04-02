#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
}


@dataclass(frozen=True)
class Rule:
    severity: str
    rule_id: str
    regex: re.Pattern[str]
    message: str


RULES = [
    Rule("high", "shell-true", re.compile(r"shell\s*=\s*True"), "Uses `shell=True`, which can open command injection paths."),
    Rule("high", "eval-call", re.compile(r"\beval\s*\("), "Uses `eval(...)`, which can execute dynamic content."),
    Rule("high", "exec-call", re.compile(r"\bexec\s*\("), "Uses `exec(...)`, which can execute dynamic content."),
    Rule("high", "curl-pipe-shell", re.compile(r"curl\s+[^|\n]+\|\s*(sh|bash)\b", re.IGNORECASE), "Downloads content and pipes it directly to a shell."),
    Rule("high", "wget-pipe-shell", re.compile(r"wget\s+[^|\n]+(?:-O-)?\s*\|\s*(sh|bash)\b", re.IGNORECASE), "Downloads content and pipes it directly to a shell."),
    Rule("high", "rm-rf", re.compile(r"\brm\s+-rf\b"), "Contains recursive force deletion."),
    Rule("high", "git-reset-hard", re.compile(r"git\s+reset\s+--hard"), "Rewrites the worktree aggressively with `git reset --hard`."),
    Rule("high", "credential-request", re.compile(r"(paste|share|provide|send).{0,40}(token|api[_ -]?key|password|secret|cookie)", re.IGNORECASE), "Asks the user to provide sensitive credentials."),
    Rule("medium", "require-escalated", re.compile(r"sandbox_permissions\s*[:=]\s*[\"']?require_escalated", re.IGNORECASE), "Requests escalated sandbox permissions."),
    Rule("medium", "subprocess", re.compile(r"subprocess\.(run|Popen|call|check_output)\s*\("), "Runs subprocesses; verify command construction and scope."),
    Rule("medium", "network-requests", re.compile(r"\b(requests|httpx|aiohttp)\.(get|post|put|delete)\s*\("), "Makes outbound HTTP requests."),
    Rule("medium", "urllib-open", re.compile(r"urllib\.request\.(urlopen|Request)\s*\("), "Makes outbound HTTP requests via urllib."),
    Rule("medium", "ssh-command", re.compile(r"\b(ssh|scp|rsync)\b"), "Uses remote access or file transfer commands."),
    Rule("medium", "chmod-777", re.compile(r"chmod\s+777\b"), "Sets world-writable permissions."),
    Rule("medium", "gh-auth-token", re.compile(r"gh\s+auth\s+token"), "Reads GitHub auth token from the local CLI session."),
]


def iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]

    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name != "SKILL.md":
            continue
        files.append(path)
    return files


def read_text(path: Path) -> list[str] | None:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return None


def scan(path: Path, lines: list[str]) -> list[tuple[Rule, int, str]]:
    findings: list[tuple[Rule, int, str]] = []
    for line_no, line in enumerate(lines, start=1):
        for rule in RULES:
            if rule.regex.search(line):
                findings.append((rule, line_no, line.strip()))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a skill directory for risky patterns.")
    parser.add_argument("target", help="Path to a skill directory or file")
    args = parser.parse_args()

    root = Path(args.target).resolve()
    if not root.exists():
        print(f"ERROR: target does not exist: {root}", file=sys.stderr)
        return 2

    files = iter_files(root)
    if not files:
        print("No matching text files found.")
        return 0

    total = 0
    for path in files:
        lines = read_text(path)
        if lines is None:
            continue
        findings = scan(path, lines)
        if not findings:
            continue
        print(f"## {path}")
        for rule, line_no, line in findings:
            print(f"- [{rule.severity}] {rule.rule_id} {path}:{line_no}")
            print(f"  Why: {rule.message}")
            print(f"  Line: {line}")
            total += 1
        print()

    if total == 0:
        print("No heuristic risk hits found.")
    else:
        print(f"Total findings: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
