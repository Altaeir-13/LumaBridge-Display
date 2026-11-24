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
)

WINDOWS_USER_PATH_RE = re.compile(r"""(?i)[A-Za-z]:\\+Users\\+([^\\<>\s"'`*?]+)""")
UNIX_USER_PATH_RE = re.compile(r"""(?<![A-Za-z0-9_./-])/(?:home|Users)/([^/<>$\s"'`*?]+)""")
ALLOWED_PATH_PLACEHOLDERS = {"user", "username", "your-user", "example", "public", "default", "runner"}

EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?![A-Za-z0-9._%+-])")
CONSUMER_PERSONAL_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "yahoo.com.br",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "aol.com",
    "uol.com.br",
    "bol.com.br",
    "terra.com.br",
}
ALLOWED_EMAIL_PLACEHOLDER_LOCALS = {
    "user",
    "username",
    "example",
    "placeholder",
    "your-email",
    "seu-email",
    "seu-email-ou-noreply",
    "author",
    "contributor",
    "maintainer",
    "noreply",
    "no-reply",
}

CONFLICT_MARKER_RE = re.compile(r"(?m)^(?:<<<<<<< |>>>>>>> )")
FENCED_CODE_RE = re.compile(r"(?ms)```.*?```|~~~.*?~~~")
INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
MD_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
WORKFLOW_SHA_PIN_RE = re.compile(r"^[^/@]+/[^/@]+(?:/[^@]+)?@[0-9a-f]{40}$")
SIGN_OFF_VALUE_RE = re.compile(r"^(.+?)\s+<([^<>\s@]+@[^<>\s@]+)>$")


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

        for match in EMAIL_RE.finditer(text):
            local_part = match.group(1).strip().lower()
            domain = match.group(2).strip().lower()
            if domain in CONSUMER_PERSONAL_EMAIL_DOMAINS and local_part not in ALLOWED_EMAIL_PLACEHOLDER_LOCALS:
                errors.append(
                    f"Potential personal webmail address detected in {rel} (domain '{domain}'; "
                    "use a GitHub noreply identity or synthetic example.com fixture)."
                )

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
                    if uses_str.startswith("actions/checkout@"):
                        with_cfg = step.get("with")
                        if not isinstance(with_cfg, dict) or with_cfg.get("persist-credentials") is not False:
                            errors.append(
                                f"Workflow {rel} job '{job_id}' step {idx} actions/checkout must explicitly set persist-credentials: false."
                            )

    checked["workflows_checked"] = workflow_files


def _normalize_identity_name(name: str) -> str:
    """Normalize whitespace and case for declarative author/sign-off comparison."""
    return " ".join(name.split()).casefold()


def _verify_commit_ref(repo_root: Path, ref: str, label: str, errors: list[str]) -> str | None:
    """Verify that a Git reference resolves cleanly to a commit object."""
    cleaned = ref.strip()
    if not cleaned:
        errors.append(f"Invalid empty Git commit reference for {label}.")
        return None
    proc = run_git(repo_root, ["rev-parse", "--verify", f"{cleaned}^{{commit}}"])
    if proc.returncode != 0:
        detail = proc.stderr.strip() or "unresolved commit reference"
        errors.append(f"Invalid Git commit reference for {label} ('{cleaned}'): {detail}")
        return None
    return proc.stdout.strip()


def check_prospective_dco(
    repo_root: Path,
    dco_base: str | None,
    dco_head: str | None,
    dco_cutoff: str | None,
    errors: list[str],
    checked: dict[str, Any],
) -> None:
    """Validate recognized Signed-off-by Git trailers and authorship on prospective commits."""
    base_given = dco_base is not None
    head_given = dco_head is not None

    if base_given != head_given:
        errors.append("Incomplete DCO range: both --dco-base and --dco-head must be provided together.")
        if dco_cutoff is not None:
            _verify_commit_ref(repo_root, dco_cutoff, "--dco-cutoff", errors)
        checked["dco_checked"] = False
        return

    if not base_given and not head_given:
        if dco_cutoff is not None:
            _verify_commit_ref(repo_root, dco_cutoff, "--dco-cutoff", errors)
        checked["dco_checked"] = False
        checked["dco_skip_reason"] = "no_pr_commit_range_supplied"
        return

    assert dco_base is not None and dco_head is not None
    effective_cutoff = DEFAULT_DCO_CUTOFF if dco_cutoff is None else dco_cutoff
    resolved_base = _verify_commit_ref(repo_root, dco_base, "--dco-base", errors)
    resolved_head = _verify_commit_ref(repo_root, dco_head, "--dco-head", errors)
    resolved_cutoff = _verify_commit_ref(repo_root, effective_cutoff, "--dco-cutoff", errors)
    if not resolved_base or not resolved_head or not resolved_cutoff:
        checked["dco_checked"] = False
        return

    rev_proc = run_git(
        repo_root,
        ["rev-list", "--no-merges", f"{resolved_base}..{resolved_head}", f"^{resolved_cutoff}"],
    )
    if rev_proc.returncode != 0:
        errors.append(f"Failed to enumerate commits for prospective DCO check: {rev_proc.stderr.strip()}")
        checked["dco_checked"] = False
        return

    commits = [line.strip() for line in rev_proc.stdout.splitlines() if line.strip()]
    missing_or_invalid: list[str] = []
    for sha in commits:
        meta_proc = run_git(
            repo_root,
            [
                "log",
                "-n",
                "1",
                "--format=%an%n%ae%n%s%x1e%(trailers:only=true,key=Signed-off-by,valueonly=true,separator=%x1f)",
                sha,
            ],
        )
        if meta_proc.returncode != 0:
            errors.append(f"Failed to inspect commit metadata and trailers for {sha}")
            continue

        header_part, _, trailer_part = meta_proc.stdout.partition("\x1e")
        header_lines = header_part.splitlines()
        if len(header_lines) < 3:
            errors.append(f"Unexpected commit metadata format for {sha}")
            continue
        author_name, author_email, subj = header_lines[0], header_lines[1], header_lines[2]
        trailers = [item.strip() for item in trailer_part.split("\x1f") if item.strip()]

        if not trailers:
            missing_or_invalid.append(f"{sha[:12]} ({subj})")
            errors.append(f"Missing recognized Signed-off-by Git trailer on prospective commit {sha[:12]}: {subj}")
            continue

        matched_author = False
        bad_trailer = False
        expected_name = _normalize_identity_name(author_name)
        expected_email = author_email.strip().lower()

        for trailer_val in trailers:
            match = SIGN_OFF_VALUE_RE.match(trailer_val)
            if not match:
                bad_trailer = True
                errors.append(
                    f"Malformed Signed-off-by Git trailer on prospective commit {sha[:12]}: {trailer_val}"
                )
                continue
            t_name = _normalize_identity_name(match.group(1))
            t_email = match.group(2).strip().lower()
            if t_name == expected_name and t_email == expected_email:
                matched_author = True

        if not bad_trailer and not matched_author:
            missing_or_invalid.append(f"{sha[:12]} ({subj})")
            errors.append(
                f"Signed-off-by Git trailer does not match commit authorship on prospective commit "
                f"{sha[:12]} ({subj}); CONTRIBUTING.md requires author sign-off matching "
                f"'{author_name} <{author_email}>'."
            )
        elif bad_trailer:
            missing_or_invalid.append(f"{sha[:12]} ({subj})")

    checked["dco_checked"] = True
    checked["dco_prospective_commits"] = len(commits)
    checked["dco_cutoff"] = resolved_cutoff
    checked["dco_missing"] = missing_or_invalid


def run_checks(
    repo_root: Path,
    dco_base: str | None = None,
    dco_head: str | None = None,
    dco_cutoff: str | None = None,
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
    elif checked.get("dco_skip_reason") == "no_pr_commit_range_supplied":
        lines.append(
            "- Prospective DCO 1.1 Check: **SKIPPED** (no PR commit range supplied; prospective DCO validation runs on pull_request events only)"
        )
    else:
        lines.append("- Prospective DCO 1.1 Check: **FAILED** (invalid or incomplete DCO range/cutoff parameters)")

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
    parser.add_argument("--dco-cutoff", type=str, default=None)
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
