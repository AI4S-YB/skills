#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import Any
from urllib import error, request

COMMENT_MARKER = "<!-- repo-pr-review-bot -->"

DEFAULT_PROMPT = textwrap.dedent(
    """\
    你是仓库 PR 审核 bot。
    风格冷、直、严，不寒暄，不夸奖，不为了显得苛刻而捏造问题。
    只基于给定 diff 审查安全、正确性、workflow 风险、可维护性、测试缺口和格式噪音。
    证据不足时明确写“需要人工确认”。
    """
)

REVIEW_DIMENSIONS = [
    {
        "name": "format-and-correctness",
        "focus": textwrap.dedent(
            """\
            重点查：
            - 明显的逻辑错误、错误路径、错误配置键、破坏现有行为的改动
            - 配置 / YAML / workflow / JSON / shell 的格式问题
            - 大段无意义格式化、生成文件误提交、噪音改动
            - 改动和 PR 描述明显不一致
            """
        ).strip(),
    },
    {
        "name": "security",
        "focus": textwrap.dedent(
            """\
            重点查：
            - 注入风险、命令执行、动态 eval / exec、危险 shell 用法
            - 权限放大、越权自动化、`pull_request_target` 风险、workflow token 滥用
            - 关闭 TLS / SSL 校验、硬编码密钥、机密泄露、供应链脚本风险
            - 依赖或 CI 脚本是否给攻击面开门
            """
        ).strip(),
    },
    {
        "name": "maintainability-and-tests",
        "focus": textwrap.dedent(
            """\
            重点查：
            - 可维护性下降、职责混乱、隐式行为、难以回滚的配置
            - 缺失测试、缺失文档、缺失迁移说明
            - 会让后续排障成本升高的实现
            """
        ).strip(),
    },
]

RISK_PATTERNS = [
    (re.compile(r"\bpull_request_target\b"), "检测到 `pull_request_target`，这是高权限触发器，必须确认没有执行不可信 PR 代码。"),
    (re.compile(r"curl\s+[^|\n]+\|\s*(sh|bash)\b", re.IGNORECASE), "检测到 `curl | sh/bash` 风格命令，存在供应链执行风险。"),
    (re.compile(r"\beval\s*\("), "检测到 `eval(...)`，需要确认是否引入动态执行风险。"),
    (re.compile(r"\bexec\s*\("), "检测到 `exec(...)`，需要确认是否引入动态执行风险。"),
    (re.compile(r"shell\s*=\s*True"), "检测到 `shell=True`，需要确认是否存在命令注入面。"),
    (re.compile(r"rejectUnauthorized\s*:\s*false"), "检测到关闭 TLS 校验。"),
    (re.compile(r"InsecureSkipVerify\s*:\s*true"), "检测到关闭 TLS 校验。"),
    (re.compile(r"verify\s*=\s*False"), "检测到关闭 TLS 校验。"),
    (re.compile(r"ssl\._create_unverified_context"), "检测到关闭 TLS 校验。"),
    (re.compile(r"chmod\s+777\b"), "检测到 `chmod 777`，权限过宽。"),
    (re.compile(r"\bsudo\b"), "检测到 `sudo`，需要确认是否真的必要。"),
]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def env_int(name: str, default: int) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text

    lines = text.splitlines()
    kept: list[str] = []
    used = 0

    for line in lines:
        line_cost = len(line) + 1
        if kept and used + line_cost > limit:
            break
        if not kept and line_cost > limit:
            shortened = line[: max(0, limit - 32)].rstrip()
            kept.append(f"{shortened} ...")
            used = limit
            break
        kept.append(line)
        used += line_cost

    return f"{chr(10).join(kept).rstrip()}\n... [truncated at line boundary]"


def normalize_multiline(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
        return "".join(parts)
    return str(value)


def normalize_api_base_url(base_url: str) -> str:
    value = base_url.strip().rstrip("/")
    if not value:
        return "https://api.openai.com/v1"
    if value.endswith("/v1"):
        return value
    return f"{value}/v1"


def parse_json_response(raw: str, *, url: str) -> Any:
    if not raw.strip():
        raise RuntimeError(f"LLM API returned an empty body from {url}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        snippet = raw[:400].replace("\n", "\\n")
        raise RuntimeError(f"LLM API did not return valid JSON from {url}: {snippet}") from exc


def extract_response_text(data: Any) -> str:
    if isinstance(data, dict):
        output_text = data.get("output_text")
        if isinstance(output_text, str) and output_text.strip():
            return output_text.strip()

        output = data.get("output")
        if isinstance(output, list):
            parts: list[str] = []
            for item in output:
                if not isinstance(item, dict):
                    continue
                content = item.get("content")
                if not isinstance(content, list):
                    continue
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") in {"output_text", "text"}:
                        text_value = block.get("text")
                        if isinstance(text_value, str):
                            parts.append(text_value)
                        elif isinstance(text_value, dict) and isinstance(text_value.get("value"), str):
                            parts.append(text_value["value"])
            text = "".join(parts).strip()
            if text:
                return text

        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message", {})
                text = normalize_multiline(message.get("content", "")).strip()
                if text:
                    return text

    raise RuntimeError(f"Unexpected LLM API response shape: {json.dumps(data, ensure_ascii=False)[:800]}")


def github_request(token: str, method: str, path: str, payload: Any | None = None) -> Any:
    url = f"https://api.github.com{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "repo-pr-review-bot",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")

    req = request.Request(url, method=method, headers=headers, data=data)
    try:
        with request.urlopen(req, timeout=90) as response:
            raw = response.read().decode("utf-8")
            if not raw:
                return None
            return json.loads(raw)
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"GitHub API {method} {path} failed: {exc.code} {body}") from exc


def github_paginate(token: str, path: str) -> list[Any]:
    page = 1
    results: list[Any] = []
    sep = "&" if "?" in path else "?"
    while True:
        chunk = github_request(token, "GET", f"{path}{sep}per_page=100&page={page}")
        if not chunk:
            break
        if not isinstance(chunk, list):
            raise RuntimeError(f"Expected paginated list from GitHub for {path}")
        results.extend(chunk)
        if len(chunk) < 100:
            break
        page += 1
    return results


def chat_completion(
    *,
    api_key: str,
    base_url: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> str:
    api_base = normalize_api_base_url(base_url)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    reasoning_effort = os.getenv("OPENAI_REASONING_EFFORT", "").strip()
    text_verbosity = os.getenv("OPENAI_TEXT_VERBOSITY", "").strip()

    combined_input = textwrap.dedent(
        f"""\
        [System]
        {system_prompt}

        [User]
        {user_prompt}
        """
    ).strip()

    response_payload: dict[str, Any] = {
        "model": model,
        "input": combined_input,
    }
    if reasoning_effort:
        response_payload["reasoning"] = {"effort": reasoning_effort}
    if text_verbosity:
        response_payload["text"] = {"verbosity": text_verbosity}

    response_url = f"{api_base}/responses"
    req = request.Request(
        response_url,
        method="POST",
        headers=headers,
        data=json.dumps(response_payload).encode("utf-8"),
    )
    try:
        with request.urlopen(req, timeout=180) as response:
            data = parse_json_response(response.read().decode("utf-8", "replace"), url=response_url)
        return extract_response_text(data)
    except error.HTTPError as exc:
        response_error = f"{exc.code} {exc.read().decode('utf-8', 'replace')}"
    except RuntimeError as exc:
        response_error = str(exc)

    chat_url = f"{api_base}/chat/completions"
    chat_payload = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    chat_req = request.Request(
        chat_url,
        method="POST",
        headers=headers,
        data=json.dumps(chat_payload).encode("utf-8"),
    )
    try:
        with request.urlopen(chat_req, timeout=180) as response:
            data = parse_json_response(response.read().decode("utf-8", "replace"), url=chat_url)
        return extract_response_text(data)
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise RuntimeError(
            f"LLM API request failed. responses error: {response_error}; chat error: {exc.code} {body}"
        ) from exc
    except RuntimeError as exc:
        raise RuntimeError(
            f"LLM API request failed. responses error: {response_error}; chat error: {exc}"
        ) from exc


def load_prompt(repo_root: Path) -> str:
    inline_prompt = os.getenv("PR_REVIEW_PROMPT", "").strip()
    if inline_prompt:
        return inline_prompt

    prompt_path = os.getenv("PR_REVIEW_PROMPT_PATH", "").strip() or "prompts/repo-pr-review.md"
    candidate = Path(prompt_path)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    if candidate.exists():
        return candidate.read_text(encoding="utf-8").strip()

    return DEFAULT_PROMPT.strip()


def render_pr_body(pr: dict[str, Any]) -> str:
    body = (pr.get("body") or "").strip()
    return body or "(empty)"


def build_file_summary(files: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for item in files:
        filename = item["filename"]
        status = item.get("status", "modified")
        additions = item.get("additions", 0)
        deletions = item.get("deletions", 0)
        changes = item.get("changes", additions + deletions)
        lines.append(f"- {filename} [{status}] +{additions}/-{deletions} ({changes} changed)")
    return "\n".join(lines) if lines else "- No changed files returned by GitHub."


def detect_risk_hints(files: list[dict[str, Any]]) -> list[str]:
    hints: list[str] = []
    for item in files:
        filename = item["filename"]
        patch = item.get("patch") or ""

        if filename.startswith(".github/workflows/"):
            hints.append(f"{filename}: GitHub workflow 改动，必须检查权限、触发器和是否执行了不可信输入。")
        if filename.endswith((".sh", ".bash", ".zsh", ".ps1")):
            hints.append(f"{filename}: 脚本文件改动，检查是否引入危险 shell 执行和权限问题。")
        if Path(filename).name in {
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "requirements.txt",
            "poetry.lock",
            "Cargo.toml",
            "Cargo.lock",
            "go.mod",
            "go.sum",
            "Dockerfile",
        }:
            hints.append(f"{filename}: 依赖或构建入口改动，检查供应链和安装脚本风险。")

        for pattern, message in RISK_PATTERNS:
            if pattern.search(patch):
                hints.append(f"{filename}: {message}")

        if re.search(r"(api[_-]?key|token|secret|password)\s*[:=]\s*['\"][^'\"]{8,}", patch, re.IGNORECASE):
            hints.append(f"{filename}: 可能存在硬编码凭据或敏感值。")

    deduped: list[str] = []
    seen: set[str] = set()
    for hint in hints:
        if hint not in seen:
            deduped.append(hint)
            seen.add(hint)
    return deduped


def build_patch_bundle(
    files: list[dict[str, Any]],
    *,
    max_files: int,
    max_patch_chars_per_file: int,
    max_total_patch_chars: int,
) -> tuple[str, list[str]]:
    lines: list[str] = []
    omitted: list[str] = []
    total_chars = 0

    for index, item in enumerate(files):
        filename = item["filename"]
        if index >= max_files:
            omitted.append(filename)
            continue

        patch = item.get("patch")
        status = item.get("status", "modified")
        additions = item.get("additions", 0)
        deletions = item.get("deletions", 0)
        header = f"### {filename}\nstatus: {status} | additions: {additions} | deletions: {deletions}"

        if not patch:
            lines.append(f"{header}\n_No textual patch returned by GitHub (binary, too large, or rename-only)._")
            continue

        remaining = max_total_patch_chars - total_chars
        if remaining <= 0:
            omitted.append(filename)
            continue

        snippet_limit = min(max_patch_chars_per_file, remaining)
        snippet = truncate(patch, snippet_limit)
        total_chars += len(snippet)
        lines.append(f"{header}\n```diff\n{snippet}\n```")

    return "\n\n".join(lines), omitted


def build_pr_context(
    *,
    repo_full_name: str,
    pr: dict[str, Any],
    files: list[dict[str, Any]],
    risk_hints: list[str],
    patch_bundle: str,
    omitted_files: list[str],
) -> str:
    labels = ", ".join(label["name"] for label in pr.get("labels", [])) or "(none)"
    body = render_pr_body(pr)
    hints_block = "\n".join(f"- {hint}" for hint in risk_hints) if risk_hints else "- No machine-generated risk hints."
    omitted_block = "\n".join(f"- {name}" for name in omitted_files[:30]) if omitted_files else "- None."

    return textwrap.dedent(
        f"""\
        Repository: {repo_full_name}
        PR Number: #{pr["number"]}
        Title: {pr.get("title", "")}
        State: {pr.get("state", "")}
        Author: {pr.get("user", {}).get("login", "")}
        Base: {pr.get("base", {}).get("ref", "")}
        Head: {pr.get("head", {}).get("ref", "")}
        Labels: {labels}

        PR Body:
        {body}

        Changed Files:
        {build_file_summary(files)}

        Machine Risk Hints:
        {hints_block}

        Omitted Files:
        {omitted_block}

        Patch Truncation Note:
        - Patch snippets may be truncated at line boundaries for context budgeting.
        - A truncated tail is not evidence of a syntax error by itself.

        Patch Details:
        {patch_bundle}
        """
    ).strip()


def build_review_prompt(dimension_name: str, focus: str, context: str) -> str:
    return textwrap.dedent(
        f"""\
        你现在执行 `{dimension_name}` 维度审查。

        {focus}

        审查约束：
        - 只基于下面给出的上下文和 diff。
        - 不要假装知道仓库其它未展示的代码。
        - 如果看到 `... [truncated`，只能说明上下文被截断，不能把截断尾部本身当成语法错误证据。
        - 如果没有明确问题，输出 `无新增发现。`
        - 如果有问题，每条问题使用以下字段：
          - Severity:
          - File:
          - Line:
          - Problem:
          - Why:
          - Fix:

        PR 上下文如下：
        {context}
        """
    ).strip()


def build_synthesis_prompt(
    *,
    context: str,
    review_outputs: list[tuple[str, str]],
    reviewed_file_count: int,
    omitted_files: list[str],
) -> str:
    reviews_block = "\n\n".join(
        f"### {name}\n{output}" for name, output in review_outputs
    )
    omitted_block = ", ".join(omitted_files[:20]) if omitted_files else "None"
    return textwrap.dedent(
        f"""\
        你要把多个维度的审查结果合并成最终 PR 评论。

        规则：
        - 保持冷酷、直接、没有寒暄。
        - 不要重复同一个问题。
        - 不要为了显得严格而升级严重度。
        - 如果证据来自被截断的 patch 片段，不要仅凭截断尾部残片判定语法错误或直接给 `BLOCK`。
        - 只有在可见证据完整且明确时，才能把问题升级为 `BLOCK`。
        - `BLOCK` 只用于明确的安全、正确性、权限、供应链、CI 破坏类问题。
        - `NEEDS_ATTENTION` 用于非阻塞但明显需要处理或人工确认的问题。
        - `NO_BLOCKING_FINDINGS` 只在没有明确问题时使用。
        - 如果行号不确定，写 `?`。
        - 输出纯 Markdown，不要加代码块。

        严格使用下面模板：

        ## Verdict
        `BLOCK|NEEDS_ATTENTION|NO_BLOCKING_FINDINGS`
        一句话结论。

        ## Findings
        1. [severity] file:line - title
           证据：...
           影响：...
           建议：...
        如果没有发现，写：没有发现足以阻塞合并的明确问题。

        ## Residual Risks
        - ...
        如果没有，写 `- 无。`

        ## Scope
        - Reviewed files: {reviewed_file_count}
        - Omitted files: {omitted_block}

        原始 PR 上下文：
        {context}

        各维度审查输出：
        {reviews_block}
        """
    ).strip()


def build_comment_body(report: str, model: str) -> str:
    cleaned_report = report.strip()
    return (
        f"{COMMENT_MARKER}\n"
        "## 冷酷 PR 审查\n\n"
        f"{cleaned_report}\n\n"
        f"_Generated by `scripts/review_pr.py` with model `{model}`._"
    )


def upsert_pr_comment(token: str, repo_full_name: str, pr_number: int, body: str) -> None:
    comments = github_paginate(token, f"/repos/{repo_full_name}/issues/{pr_number}/comments")
    existing = None
    for comment in reversed(comments):
        comment_body = comment.get("body") or ""
        if COMMENT_MARKER in comment_body:
            existing = comment
            break

    if existing:
        github_request(
            token,
            "PATCH",
            f"/repos/{repo_full_name}/issues/comments/{existing['id']}",
            {"body": body},
        )
        return

    github_request(
        token,
        "POST",
        f"/repos/{repo_full_name}/issues/{pr_number}/comments",
        {"body": body},
    )


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    github_token = os.getenv("GITHUB_TOKEN", "").strip()
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    model = os.getenv("OPENAI_MODEL", "").strip() or "gpt-5-mini"
    base_url = os.getenv("OPENAI_BASE_URL", "").strip() or "https://api.openai.com/v1"

    if not github_token:
        fail("GITHUB_TOKEN is required")
    if not api_key:
        fail("OPENAI_API_KEY is required")

    event_path = os.getenv("GITHUB_EVENT_PATH", "").strip()
    if not event_path:
        fail("GITHUB_EVENT_PATH is required")

    event = read_json(Path(event_path))
    pull_request = event.get("pull_request")
    repository = event.get("repository")
    if not pull_request or not repository:
        fail("This script must run on a pull_request_target event")

    repo_full_name = repository["full_name"]
    pr_number = int(pull_request["number"])
    max_files = env_int("PR_REVIEW_MAX_FILES", 40)
    max_patch_chars_per_file = env_int("PR_REVIEW_MAX_PATCH_CHARS_PER_FILE", 6000)
    max_total_patch_chars = env_int("PR_REVIEW_MAX_TOTAL_PATCH_CHARS", 45000)

    system_prompt = load_prompt(repo_root)

    pr = github_request(token=github_token, method="GET", path=f"/repos/{repo_full_name}/pulls/{pr_number}")
    files = github_paginate(github_token, f"/repos/{repo_full_name}/pulls/{pr_number}/files")

    risk_hints = detect_risk_hints(files)
    patch_bundle, omitted_files = build_patch_bundle(
        files,
        max_files=max_files,
        max_patch_chars_per_file=max_patch_chars_per_file,
        max_total_patch_chars=max_total_patch_chars,
    )

    context = build_pr_context(
        repo_full_name=repo_full_name,
        pr=pr,
        files=files,
        risk_hints=risk_hints,
        patch_bundle=patch_bundle,
        omitted_files=omitted_files,
    )

    review_outputs: list[tuple[str, str]] = []
    for dimension in REVIEW_DIMENSIONS:
        prompt = build_review_prompt(dimension["name"], dimension["focus"], context)
        output = chat_completion(
            api_key=api_key,
            base_url=base_url,
            model=model,
            system_prompt=system_prompt,
            user_prompt=prompt,
        )
        review_outputs.append((dimension["name"], output))

    synthesis_prompt = build_synthesis_prompt(
        context=context,
        review_outputs=review_outputs,
        reviewed_file_count=len(files) - len(omitted_files),
        omitted_files=omitted_files,
    )
    final_report = chat_completion(
        api_key=api_key,
        base_url=base_url,
        model=model,
        system_prompt=system_prompt,
        user_prompt=synthesis_prompt,
    )

    comment_body = build_comment_body(final_report, model)
    upsert_pr_comment(github_token, repo_full_name, pr_number, comment_body)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover
        fail(str(exc))
