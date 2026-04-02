# Repo PR Review Bot

这个仓库现在是一套最小可用的 GitHub PR 自动审核 bot。

它会在 PR 打开、更新、重新打开、从 draft 转 ready 时自动运行，用仓库内置 prompt 对 PR 做多维度审查，重点盯：

- 安全性
- 正确性
- CI / workflow 权限风险
- 配置和格式问题
- 可维护性与测试缺口

默认评论风格是“冷酷、直接、挑剔”，但不会做人身攻击。

## 结构

- `.github/workflows/pr-review.yml`：GitHub Actions 入口
- `scripts/review_pr.py`：拉取 PR 元数据、diff、调用 LLM、回贴评论
- `prompts/repo-pr-review.md`：仓库内置系统 prompt

## 工作方式

这个 bot 使用 `pull_request_target`，但只读取 GitHub API 返回的 PR 信息和 patch，不会检出 PR head，也不会执行 PR 代码。

这样做的目的是：

- 允许 bot 在 fork PR 上也能写评论
- 避免把高权限 token 暴露给不可信代码
- 把审核范围限制在 diff 级别，降低工作流本身的供应链风险

## 配置

至少需要一个仓库 secret：

- `OPENAI_API_KEY`

可选仓库 variables：

- `OPENAI_MODEL`
- `OPENAI_BASE_URL`
- `PR_REVIEW_PROMPT_PATH`
- `PR_REVIEW_MAX_FILES`
- `PR_REVIEW_MAX_PATCH_CHARS_PER_FILE`
- `PR_REVIEW_MAX_TOTAL_PATCH_CHARS`

如果不配：

- `OPENAI_MODEL` 默认是 `gpt-5-mini`
- `OPENAI_BASE_URL` 默认是 `https://api.openai.com/v1`
- `PR_REVIEW_PROMPT_PATH` 默认是 `prompts/repo-pr-review.md`

## 自定义 prompt

直接修改 `prompts/repo-pr-review.md` 就行。

脚本读取顺序是：

1. 环境变量 `PR_REVIEW_PROMPT`
2. 环境变量或仓库变量 `PR_REVIEW_PROMPT_PATH`
3. 默认文件 `prompts/repo-pr-review.md`
4. 脚本内置 fallback prompt

## 输出策略

脚本会先按三个维度分别审查，再做一次综合：

1. `format-and-correctness`
2. `security`
3. `maintainability-and-tests`

最终评论会输出：

- `BLOCK`
- `NEEDS_ATTENTION`
- `NO_BLOCKING_FINDINGS`

同时脚本会自动更新自己上一次的评论，避免每次推送都刷一条新评论。

## 限制

- 这是 diff-only 审查，不是全仓库静态分析。
- GitHub 对超大 patch、二进制文件、rename-only 变更可能不会返回完整 patch。
- 大 PR 会被截断；被截断的文件会在评论的 `Scope` 里标出来。
- 目前回贴的是 PR conversation comment，不是 inline review comment。
