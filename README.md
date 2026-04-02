# Skills

这个仓库用于存放和维护各类 skill 相关内容。

当前仓库包含：

- skill 配置与提示词
- 自动化脚本
- 仓库级 PR 审核 bot
- `review-skill-safety/`：用于审查其他 skill 是否安全的 skill

如果你要看 PR 审核 bot 的说明，去 `scripts/README.md`。

当前主要文件：

- `prompts/repo-pr-review.md`：PR 审核 bot 使用的系统 prompt
- `scripts/review_pr.py`：PR 审核脚本
- `.github/workflows/pr-review.yml`：PR 审核 workflow

这个仓库的定位不是单一应用，而是 skill 资产和相关自动化的承载仓库。
