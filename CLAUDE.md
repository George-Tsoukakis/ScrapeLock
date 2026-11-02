# ScrapeLock

## Working preferences

- Commits, pull requests and GitHub comments show only George Tsoukakis: author commits as "George Tsoukakis" with the user's own email (set `git config user.name` / `user.email` in the clone before committing, never "Claude"), never add the "Co-Authored-By: Claude" or "Claude-Session" lines to commit messages, and never add "Generated with Claude Code" or a Claude session link to PR bodies or comments.
- Never push to `main` directly. Every change goes through a pull request from its own branch, and the owner merges it on GitHub (the merge commit is then signed by GitHub and shows as Verified). Release tags point at a merge commit on `main`: run the Release workflow on `main` after the merge (with "Replace the zip" when the version already has a release).
