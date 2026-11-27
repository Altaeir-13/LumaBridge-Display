---
name: lumabridge-session-recovery
description: Deterministic campaign checkpointing, Git/PR state verification, and work-recovery protocol across sessions or context resets.
---

# LumaBridge Session & Checkpoint Recovery

Use this skill when resuming an interrupted multi-milestone campaign, after context resets, or before transitioning between milestones.

## 1. Verify Ground Truth Before Acting

Never resume blindly from memory or stale notes. Run a single verification sweep first:

```powershell
git worktree list
git fetch origin
git status --short --branch
gh pr list --repo Altaeir-13/LumaBridge-Display --state open --json number,headRefName,headRefOid,mergeStateStatus,reviewDecision
```

Verify:
1. Exact `origin/dev` SHA and whether any open critical PRs received human reviews, requested changes, or merged.
2. Which isolated worktree owns which milestone branch.
3. Latest GitHub Actions run status on active PRs (`gh run list` / `gh pr checks`).

## 2. Reconcile Checkpoints Without Repeating Completed Work

- Read active milestone logs and qualification reports under `docs/` (and any active session checkpoint artifact).
- Confirm that every claimed `PASS` corresponds to the current `HEAD` commit SHA. If commits were added after a test run, treat prior results as stale and re-run after the final edit.
- If a PR already passes all local and remote CI gates and awaits external human review, **do not churn it** unless review feedback or new findings require changes. Advance independent or cleanly stacked non-blocked workstreams instead.

## 3. Required Checkpoint Fields

When recording a milestone or campaign checkpoint, log:
- Current milestone / sub-milestone and target next milestone.
- Exact branch names, worktree paths, base `origin/dev` SHA, and `HEAD` SHA per active PR.
- Open PRs (number, state, `mergeStateStatus`, CI summary, whether held for external review).
- Verified test/benchmark/fuzzing matrix with explicit `PASS` / `FAIL` / `BLOCKED_BY_*` / `SKIPPED` classifications.
- Confirmed remaining risks, technical debt, and exact next actions.
