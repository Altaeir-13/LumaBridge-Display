#!/usr/bin/env python3
"""Repository hygiene, licensing, workflow security, and prospective DCO checker."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError as exc:  # pragma: no cover
    yaml = None
    YAML_IMPORT_ERROR = str(exc)
else:
    YAML_IMPORT_ERROR = ""


DEFAULT_DCO_CUTOFF = "23a2804606b02a85d915a55b75663b67bd5af58b"

FORBIDDEN_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".cat",
    ".pdb",
    ".obj",
    ".lib",
    ".pfx",
    ".cer",
    ".der",
    ".p12",
    ".key",
    ".pem",
    ".etl",
    ".dmp",
    ".zip",
    ".7z",
    ".msi",
    ".cab",
    ".so",
    ".dylib",
    ".a",
    ".pyc",
    ".pyo",
}

FORBIDDEN_PATH_PREFIXES = ("windows/driver/x64/",)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key_header", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("github_classic_token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("github_fine_grained_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("github_oauth_token", re.compile(r"\bgho_[A-Za-z0-9]{20,}\b")),
    ("github_server_token", re.compile(r"\bghs_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("personal_email", re.compile(r"(?i)randerson\.sdsn@gmail\.com")),
)

WINDOWS_USER_PATH_RE = re.compile(r"""(?i)[A-Za-z]:\\+Users\\+([^\\<>\s"'`*?]+)""")
UNIX_USER_PATH_RE = re.compile(r"""(?<![A-Za-z0-9_./-])/(?:home|Users)/([^/<>$\s"'`*?]+)""")
ALLOWED_PATH_PLACEHOLDERS = {"user", "username", "your-user", "example", "public", "default", "runner"}

CONFLICT_MARKER_RE = re.compile(r"(?m)^(?:<<<<<<< |>>>>>>> )")
FENCED_CODE_RE = re.compile(r"(?ms)```.*?```|~~~.*?~~~")
INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
MD_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
WORKFLOW_SHA_PIN_RE = re.compile(r"^[^/@]+/[^/@]+(?:/[^@]+)?@[0-9a-f]{40}$")
SIGNED_OFF_BY_RE = re.compile(r"(?m)^Signed-off-by:\s+.+?\s+<[^<>\s@]+@[^<>\s@]+>\s*$")


def run_git(repo_root: Path, args: list[str], binary: bool = False) -> subprocess.CompletedProcess[Any]:
    """Execute a git command rooted at repo_root."""
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=not binary,
        encoding=None if binary else "utf-8",
        errors=None if binary else "replace",
        check=False,
    )


def get_tracked_files(repo_root: Path) -> list[str]:
    """Return all tracked POSIX-style relative paths from git index."""
    proc = run_git(repo_root, ["ls-files", "-z"], binary=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {proc.stderr.decode('utf-8', 'replace')}")
    entries = [item.decode("utf-8", "strict") for item in proc.stdout.split(b"\x00") if item]
    return sorted(entries)


def check_governance_files(repo_root: Path, errors: list[str], checked: dict[str, Any]) -> None:
    """Verify Apache-2.0 LICENSE, NOTICE, THIRD_PARTY_NOTICES.md, CONTRIBUTING.md, and nvEncodeAPI.h."""
    license_path = repo_root / "LICENSE"
    if not license_path.is_file():
        errors.append("Missing required root LICENSE file.")
    else:
        lic_text = license_path.read_text(encoding="utf-8", errors="replace")
        required_lic = [
            "Apache License",
            "Version 2.0, January 2004",
            "http://www.apache.org/licenses/",
            "END OF TERMS AND CONDITIONS",
        ]
        missing_lic = [m for m in required_lic if m not in lic_text]
        if len(lic_text) < 10000 or missing_lic:
            errors.append(f"LICENSE failed Apache-2.0 integrity check (len={len(lic_text)}, missing={missing_lic}).")

    notice_path = repo_root / "NOTICE"
    if not notice_path.is_file():
        errors.append("Missing required root NOTICE file.")
    else:
        notice_text = notice_path.read_text(encoding="utf-8", errors="replace")
        if "LumaBridge Display" not in notice_text or "THIRD_PARTY_NOTICES.md" not in notice_text:
            errors.append("NOTICE must mention 'LumaBridge Display' and 'THIRD_PARTY_NOTICES.md'.")

    tp_path = repo_root / "THIRD_PARTY_NOTICES.md"
    if not tp_path.is_file():
        errors.append("Missing required root THIRD_PARTY_NOTICES.md file.")
    else:
        tp_text = tp_path.read_text(encoding="utf-8", errors="replace")
        for token in ("windows/host/third_party/nvenc/nvEncodeAPI.h", "NVIDIA Corporation", "MIT"):
            if token not in tp_text:
                errors.append(f"THIRD_PARTY_NOTICES.md missing required attribution token '{token}'.")

    contrib_path = repo_root / "CONTRIBUTING.md"
    if not contrib_path.is_file():
        errors.append("Missing required root CONTRIBUTING.md file.")
    else:
        contrib_text = contrib_path.read_text(encoding="utf-8", errors="replace")
        for token in (
            "Developer Certificate of Origin",
            "Version 1.1",
            "Signed-off-by",
            "(a) ",
            "(b) ",
            "(c) ",
            "(d) ",
        ):
            if token not in contrib_text:
                errors.append(f"CONTRIBUTING.md missing required DCO 1.1 marker '{token}'.")

    nvenc_path = repo_root / "windows/host/third_party/nvenc/nvEncodeAPI.h"
    if not nvenc_path.is_file():
        errors.append("Missing third-party header windows/host/third_party/nvenc/nvEncodeAPI.h.")
    else:
        nv_head = nvenc_path.read_text(encoding="utf-8", errors="replace")[:2048]
        if "Copyright (c) 2010-2023 NVIDIA Corporation" not in nv_head or "Permission is hereby granted, free of charge" not in nv_head:
            errors.append("windows/host/third_party/nvenc/nvEncodeAPI.h MIT copyright notice was altered or removed.")

    checked["governance_files"] = True


def check_tracked_contents(repo_root: Path, tracked_files: list[str], errors: list[str], checked: dict[str, Any]) -> None:
    """Inspect tracked files for forbidden binaries, secrets, personal paths, conflict markers, and broken links."""
    md_count = 0
    md_link_count = 0

    for rel in tracked_files:
        full_path = repo_root / rel
        if not full_path.is_file():
            errors.append(f"Tracked file missing on disk: {rel}")
            continue

        suffix = full_path.suffix.lower()
        if suffix in FORBIDDEN_EXTENSIONS:
            errors.append(f"Forbidden binary/credential extension tracked in git: {rel}")
            continue

        for prefix in FORBIDDEN_PATH_PREFIXES:
            if rel.startswith(prefix):
                errors.append(f"Forbidden build artifact path tracked in git: {rel}")

        raw_bytes = full_path.read_bytes()
        if b"\x00" in raw_bytes:
            errors.append(f"Binary NUL bytes detected in tracked file: {rel}")
            continue

        text = raw_bytes.decode("utf-8", errors="replace")

        if CONFLICT_MARKER_RE.search(text):
            errors.append(f"Unresolved git merge conflict marker found in {rel}")

        for pat_name, pat in SECRET_PATTERNS:
            if pat.search(text):
                errors.append(f"Sensitive pattern '{pat_name}' detected in {rel}")

        for match in WINDOWS_USER_PATH_RE.finditer(text):
            user_seg = match.group(1).strip().lower()
            if user_seg not in ALLOWED_PATH_PLACEHOLDERS:
                errors.append(f"Workstation-specific Windows user path detected in {rel}: ...\\Users\\{match.group(1)}")

        for match in UNIX_USER_PATH_RE.finditer(text):
            user_seg = match.group(1).strip().lower()
            if user_seg not in ALLOWED_PATH_PLACEHOLDERS:
                errors.append(f"Workstation-specific Unix user path detected in {rel}: /{match.group(1)}")

        if suffix == ".md":
            md_count += 1
            stripped = INLINE_CODE_RE.sub("", FENCED_CODE_RE.sub("", text))
            for link_match in MD_LINK_RE.finditer(stripped):
                raw_target = link_match.group(1).strip()
                if not raw_target or raw_target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                if " " in raw_target and not raw_target.startswith("<"):
                    raw_target = raw_target.split(" ", 1)[0]
                raw_target = raw_target.strip("<>")
                target_path = raw_target.split("#", 1)[0].strip()
                if not target_path:
                    continue
                md_link_count += 1
                resolved = (full_path.parent / target_path).resolve()
                try:
                    resolved.relative_to(repo_root.resolve())
                except ValueError:
                    errors.append(f"Relative Markdown link escapes repository root in {rel}: {raw_target}")
                    continue
                if not resolved.exists():
                    errors.append(f"Broken relative Markdown link in {rel}: {raw_target}")

    checked["tracked_files_scanned"] = len(tracked_files)
    checked["markdown_files_checked"] = md_count
    checked["relative_markdown_links_checked"] = md_link_count


def check_workflows(repo_root: Path, tracked_files: list[str], errors: list[str], checked: dict[str, Any]) -> None:
    """Validate YAML structure and security hardening of .github/workflows/*.yml files."""
    if yaml is None:
        errors.append(f"PyYAML is required for workflow validation: {YAML_IMPORT_ERROR}")
        return

    workflow_files = [
        rel
        for rel in tracked_files
        if rel.startswith(".github/workflows/") and (rel.endswith(".yml") or rel.endswith(".yaml"))
    ]
    if not workflow_files:
        errors.append("No GitHub Actions workflow files found under .github/workflows/.")
        return

    for rel in workflow_files:
        full_path = repo_root / rel
        try:
            doc = yaml.safe_load(full_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"Invalid YAML in {rel}: {exc}")
            continue

        if not isinstance(doc, dict):
            errors.append(f"Workflow {rel} root must be a YAML mapping.")
            continue

        # PyYAML YAML 1.1 parses unquoted `on:` as boolean True.
        triggers = doc.get("on", doc.get(True))
        if triggers is None:
            errors.append(f"Workflow {rel} is missing 'on' triggers.")
        elif isinstance(triggers, dict) and "pull_request_target" in triggers:
            errors.append(f"Workflow {rel} must not use pull_request_target.")
        elif isinstance(triggers, list) and "pull_request_target" in triggers:
            errors.append(f"Workflow {rel} must not use pull_request_target.")
        elif triggers == "pull_request_target":
            errors.append(f"Workflow {rel} must not use pull_request_target.")

        perms = doc.get("permissions")
        if not isinstance(perms, dict) or not perms:
            errors.append(f"Workflow {rel} must define minimal top-level permissions.")
        else:
            for scope, level in perms.items():
                if level not in ("read", "none"):
                    errors.append(f"Workflow {rel} grants non-readonly permission '{scope}: {level}'.")

        concurrency = doc.get("concurrency")
        if not isinstance(concurrency, dict) or not concurrency.get("group"):
            errors.append(f"Workflow {rel} must define top-level concurrency with group.")

        jobs = doc.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            errors.append(f"Workflow {rel} must define at least one job.")
            continue

        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                errors.append(f"Workflow {rel} job '{job_id}' must be a mapping.")
                continue

            runs_on = job.get("runs-on")
            if not runs_on:
                errors.append(f"Workflow {rel} job '{job_id}' is missing runs-on.")
            else:
                runs_on_vals = runs_on if isinstance(runs_on, list) else [runs_on]
                for item in runs_on_vals:
                    if str(item).strip().lower() == "self-hosted":
                        errors.append(f"Workflow {rel} job '{job_id}' must not use self-hosted runner.")

            timeout = job.get("timeout-minutes")
            if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
                errors.append(f"Workflow {rel} job '{job_id}' must set positive integer timeout-minutes.")

            if job.get("continue-on-error") is True:
                errors.append(f"Workflow {rel} job '{job_id}' must not set continue-on-error: true.")

            steps = job.get("steps")
            if not isinstance(steps, list) or not steps:
                errors.append(f"Workflow {rel} job '{job_id}' must define steps.")
                continue

            for idx, step in enumerate(steps, start=1):
                if not isinstance(step, dict):
                    errors.append(f"Workflow {rel} job '{job_id}' step {idx} must be a mapping.")
                    continue
                if step.get("continue-on-error") is True:
                    errors.append(f"Workflow {rel} job '{job_id}' step {idx} must not set continue-on-error: true.")
                uses = step.get("uses")
                if uses is not None:
                    uses_str = str(uses).strip()
                    if not uses_str.startswith("./") and not WORKFLOW_SHA_PIN_RE.match(uses_str):
                        errors.append(
                            f"Workflow {rel} job '{job_id}' step {idx} action '{uses_str}' must be pinned to a 40-char commit SHA."
                        )

    checked["workflows_checked"] = workflow_files


def check_prospective_dco(
    repo_root: Path,
    dco_base: str | None,
    dco_head: str | None,
    dco_cutoff: str | None,
    errors: list[str],
    checked: dict[str, Any],
) -> None:
    """Validate Signed-off-by trailers on prospective non-merge commits only."""
    if not dco_base or not dco_head:
        checked["dco_checked"] = False
        return

    rev_args = ["rev-list", "--no-merges", f"{dco_base}..{dco_head}"]
    if dco_cutoff:
        cutoff_verify = run_git(repo_root, ["rev-parse", "--verify", f"{dco_cutoff}^{{commit}}"])
        if cutoff_verify.returncode == 0:
            rev_args.append(f"^{dco_cutoff}")

    rev_proc = run_git(repo_root, rev_args)
    if rev_proc.returncode != 0:
        errors.append(f"Failed to enumerate commits for prospective DCO check: {rev_proc.stderr.strip()}")
        return

    commits = [line.strip() for line in rev_proc.stdout.splitlines() if line.strip()]
    missing_dco: list[str] = []
    for sha in commits:
        msg_proc = run_git(repo_root, ["log", "-n", "1", "--format=%B", sha])
        if msg_proc.returncode != 0:
            errors.append(f"Failed to read commit message for {sha}")
            continue
        if not SIGNED_OFF_BY_RE.search(msg_proc.stdout):
            subj_proc = run_git(repo_root, ["log", "-n", "1", "--format=%s", sha])
            subj = subj_proc.stdout.strip()
            missing_dco.append(f"{sha[:12]} ({subj})")
            errors.append(f"Missing DCO Signed-off-by trailer on prospective commit {sha[:12]}: {subj}")

    checked["dco_checked"] = True
    checked["dco_prospective_commits"] = len(commits)
    checked["dco_cutoff"] = dco_cutoff
    checked["dco_missing"] = missing_dco


def run_checks(
    repo_root: Path,
    dco_base: str | None = None,
    dco_head: str | None = None,
    dco_cutoff: str | None = DEFAULT_DCO_CUTOFF,
) -> dict[str, Any]:
    """Run all repository hygiene checks and return a structured result payload."""
    errors: list[str] = []
    checked: dict[str, Any] = {}

    tracked_files = get_tracked_files(repo_root)
    check_governance_files(repo_root, errors, checked)
    check_tracked_contents(repo_root, tracked_files, errors, checked)
    check_workflows(repo_root, tracked_files, errors, checked)
    check_prospective_dco(repo_root, dco_base, dco_head, dco_cutoff, errors, checked)

    return {
        "passed": len(errors) == 0,
        "error_count": len(errors),
        "errors": errors,
        "checked": checked,
    }


def write_summary(result: dict[str, Any], summary_path: Path | None, json_path: Path | None) -> None:
    """Write structured JSON report and Markdown step summary if paths are provided."""
    if json_path is not None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    checked = result["checked"]
    lines = [
        "## Linux Repository Hygiene & Governance Summary",
        "",
        f"- Overall Result: **{'PASS' if result['passed'] else 'FAIL'}**",
        f"- Tracked Files Scanned: **{checked.get('tracked_files_scanned', 0)}**",
        f"- Markdown Files / Relative Links Verified: **{checked.get('markdown_files_checked', 0)}** / **{checked.get('relative_markdown_links_checked', 0)}**",
        f"- Workflows Validated: **{', '.join(checked.get('workflows_checked', []))}**",
    ]
    if checked.get("dco_checked"):
        lines.append(
            f"- Prospective DCO 1.1 Check: **{checked.get('dco_prospective_commits', 0)}** prospective commit(s) checked (historical cutoff `{checked.get('dco_cutoff', '')[:8]}`)"
        )
    else:
        lines.append("- Prospective DCO 1.1 Check: **SKIPPED** (no PR commit range supplied)")

    if result["errors"]:
        lines.extend(["", "### Violations"])
        for err in result["errors"]:
            lines.append(f"- {err}")

    md_text = "\n".join(lines) + "\n"
    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("a", encoding="utf-8") as fh:
            fh.write(md_text)
    print(md_text, end="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check LumaBridge Display repository hygiene and governance.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--summary-path", type=Path, default=None)
    parser.add_argument("--json-path", type=Path, default=None)
    parser.add_argument("--dco-base", type=str, default=None)
    parser.add_argument("--dco-head", type=str, default=None)
    parser.add_argument("--dco-cutoff", type=str, default=DEFAULT_DCO_CUTOFF)
    args = parser.parse_args(argv)

    result = run_checks(
        repo_root=args.repo_root.resolve(),
        dco_base=args.dco_base,
        dco_head=args.dco_head,
        dco_cutoff=args.dco_cutoff,
    )
    write_summary(result, args.summary_path, args.json_path)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
