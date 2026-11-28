---
name: lumabridge-git-integration
description: Git worktree isolation, DCO 1.1 signing, Conventional Commits, Ruleset 28020487 CI gates, and mandatory external-review critical-PR governance for LumaBridge Display.
---

# LumaBridge Git & PR Integration Discipline

Follow [CONTRIBUTING.md](../../../CONTRIBUTING.md) and [ADR-0001](../../../docs/architecture/ADR-0001-branching-strategy.md) on every branch and PR.

## 1. Isolated Worktrees & Preserved History

- Create a dedicated `git worktree` per independent workstream (`feature/*`, `fix/*`, `docs/*`, `chore/*`) so parallel checks or pending PRs never collide.
- **Never delete** existing historical worktrees or branches (`m0-*`, `m1-*`, `docs-*`).
- **Never commit or push** directly to `dev` or `main`.
- **Never force-push** or rewrite commits already pushed to remote review branches unless fixing your own unreviewed draft before sharing (prefer additive DCO fix commits once reviewed).

## 2. Commit & PR Formatting

- **Commit Format:** `<type>(<scope>): <imperative summary>` (e.g., `feat(transport): add bounded QUIC media datagram sender`).
- **Mandatory DCO 1.1 Sign-Off:** Always pass `-s` (`git commit -s`), verifying author `name <email>` matches the `Signed-off-by:` trailer (`check_repo_hygiene.py` fails mismatches). Prefer GitHub `noreply` emails.
- **PR Body:** Follow `.github/PULL_REQUEST_TEMPLATE.md`, linking related issues, listing exact out-of-scope items, observed test commands/outcomes, risks, and honest environment blockers.

## 3. Ruleset `28020487` & Strict Branch Currency

`dev` requires:
- Reviewed PR integrated by **merge commit** (`--no-ff`; squash/rebase merges are disabled).
- `strict_required_status_checks_policy: true` (branch must be up to date with `dev` head).
- All 4 checks passing:
  - `Repository Hygiene, Licensing & Prospective DCO`
  - `Windows Unit & Tooling Tests (Non-Admin)`
  - `Windows Rust + MSVC Debug/Release FFI PoC`
  - `Linux Rust Tests + Android ARM64 & UniFFI PoC`

## 4. Critical PR Review & Stacked Branch Discipline

- **Never self-merge or bypass PR review** (`CONTRIBUTING.md`, `ADR-0001`). Changes touching cryptography, TLS, pairing, authorization/revocation, FFI/`unsafe` contracts, `windows/driver/`, privileged scripts, breaking protocol changes, architectural ADRs, or production distribution require explicit external human review before merge.
- **Protect Open Reviewed PRs from `BEHIND` Invalidation:** Because `strict_required_status_checks_policy` marks open PRs out-of-date whenever `dev` moves, avoid advancing `dev` with unrelated non-urgent merges while an audited critical PR is queued for human sign-off.
- **Stacked Development:** When new work depends on an unmerged critical PR, branch cleanly from that PR's verified commit in a new worktree, never modify the queued PR branch for unrelated work, and hold merging the stacked PR until the base PR lands on `dev`.
