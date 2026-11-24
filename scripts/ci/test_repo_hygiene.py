#!/usr/bin/env python3
"""Positive and negative unit tests for scripts/ci/check_repo_hygiene.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_repo_hygiene  # noqa: E402


VALID_LICENSE = (
    "Apache License\n"
    "Version 2.0, January 2004\n"
    "http://www.apache.org/licenses/\n\n"
    + ("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION.\n" * 200)
    + "END OF TERMS AND CONDITIONS\n"
)

VALID_NOTICE = (
    "LumaBridge Display\n"
    "Copyright 2026 Altaeir-13 and LumaBridge Display contributors.\n"
    "See THIRD_PARTY_NOTICES.md.\n"
)

VALID_THIRD_PARTY = (
    "# Third-Party Notices\n"
    "- windows/host/third_party/nvenc/nvEncodeAPI.h\n"
    "- Copyright (c) 2010-2023 NVIDIA Corporation\n"
    "- MIT License\n"
)

VALID_CONTRIBUTING = (
    "# Contributing\n"
    "Developer Certificate of Origin\n"
    "Version 1.1\n"
    "Signed-off-by\n"
    "(a) created by me\n"
    "(b) based upon previous work\n"
    "(c) provided directly\n"
    "(d) public record\n"
)

VALID_NVENC_HEADER = (
    "/*\n"
    " * Copyright (c) 2010-2023 NVIDIA Corporation\n"
    " * Permission is hereby granted, free of charge, to any person\n"
    " */\n"
    "#define NVENCAPI_MAJOR_VERSION 12\n"
)

VALID_WORKFLOW = (
    "name: Test CI\n"
    "on:\n"
    "  pull_request:\n"
    "    branches: [dev]\n"
    "permissions:\n"
    "  contents: read\n"
    "concurrency:\n"
    "  group: ${{ github.workflow }}-${{ github.ref }}\n"
    "  cancel-in-progress: true\n"
    "jobs:\n"
    "  check:\n"
    "    runs-on: ubuntu-24.04\n"
    "    timeout-minutes: 10\n"
    "    steps:\n"
    "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
    "      - run: echo ok\n"
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return proc.stdout.strip()


def write_repo_file(repo: Path, rel: str, content: str | bytes) -> None:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")


def create_clean_repo(repo: Path) -> tuple[str, str]:
    """Create a valid git repository with two unsigned historical commits and return (hist1, cutoff)."""
    git(repo, "init")
    git(repo, "config", "user.name", "Test Maintainer")
    git(repo, "config", "user.email", "test@users.noreply.github.com")

    write_repo_file(repo, "LICENSE", VALID_LICENSE)
    write_repo_file(repo, "NOTICE", VALID_NOTICE)
    git(repo, "add", "LICENSE", "NOTICE")
    git(repo, "commit", "-m", "chore: earliest historical commit without sign-off")
    hist1 = git(repo, "rev-parse", "HEAD")

    write_repo_file(repo, "THIRD_PARTY_NOTICES.md", VALID_THIRD_PARTY)
    write_repo_file(repo, "CONTRIBUTING.md", VALID_CONTRIBUTING)
    write_repo_file(repo, "windows/host/third_party/nvenc/nvEncodeAPI.h", VALID_NVENC_HEADER)
    write_repo_file(repo, ".github/workflows/ci-test.yml", VALID_WORKFLOW)
    write_repo_file(
        repo,
        "README.md",
        "# LumaBridge\nSee [LICENSE](LICENSE) and [CONTRIBUTING](CONTRIBUTING.md).\n",
    )
    # Legitimate synthetic Windows SIDs, placeholders, and generic OS paths MUST be allowed.
    write_repo_file(
        repo,
        "tests/fixtures.ps1",
        (
            "$sid1 = 'S-1-5-21-1000000001-1000000002-1000000003-1001'\n"
            "$lowIl = 'S-1-16-4096'\n"
            "$winPath = 'C:\\Windows\\System32\\IddCx.dll'\n"
            "$placeholder = 'C:\\Users\\<user>\\example'\n"
        ),
    )

    git(repo, "add", ".")
    git(repo, "commit", "-m", "chore: historical pre-dco baseline without sign-off")
    cutoff = git(repo, "rev-parse", "HEAD")
    return hist1, cutoff


class RepoHygieneTests(unittest.TestCase):
    def test_clean_repo_and_synthetic_sids_pass_and_historical_dco_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            hist1, cutoff = create_clean_repo(repo)
            write_repo_file(repo, "docs/note.md", "# Note\nBack to [README](../README.md).\n")
            git(repo, "add", "docs/note.md")
            git(repo, "commit", "-s", "-m", "docs: prospective signed-off commit")
            head = git(repo, "rev-parse", "HEAD")

            res = check_repo_hygiene.run_checks(
                repo, dco_base=cutoff, dco_head=head, dco_cutoff=cutoff
            )
            self.assertTrue(res["passed"], f"Expected clean repo to pass, got: {res['errors']}")

            # Checking a range that spans the historical unsigned commit `cutoff` must NOT fail retroactively.
            spanning_check = check_repo_hygiene.run_checks(
                repo, dco_base=hist1, dco_head=head, dco_cutoff=cutoff
            )
            self.assertTrue(spanning_check["passed"], f"Unexpected DCO error: {spanning_check['errors']}")
            self.assertEqual(spanning_check["checked"]["dco_prospective_commits"], 1)

    def test_negative_prospective_commit_without_dco_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _, cutoff = create_clean_repo(repo)
            write_repo_file(repo, "docs/unsigned.md", "# Unsigned\n")
            git(repo, "add", "docs/unsigned.md")
            git(repo, "commit", "-m", "docs: missing dco trailer")
            head = git(repo, "rev-parse", "HEAD")

            res = check_repo_hygiene.run_checks(
                repo, dco_base=cutoff, dco_head=head, dco_cutoff=cutoff
            )
            self.assertFalse(res["passed"])
            self.assertTrue(any("Signed-off-by" in e for e in res["errors"]))

    def test_negative_missing_license_and_altered_nvenc_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            create_clean_repo(repo)
            (repo / "LICENSE").unlink()
            write_repo_file(repo, "windows/host/third_party/nvenc/nvEncodeAPI.h", "// stripped\n")
            git(repo, "add", "-A")

            res = check_repo_hygiene.run_checks(repo)
            self.assertFalse(res["passed"])
            self.assertTrue(any("LICENSE" in e for e in res["errors"]))
            self.assertTrue(any("nvEncodeAPI.h" in e for e in res["errors"]))

    def test_negative_broken_markdown_link_and_binary_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            create_clean_repo(repo)
            write_repo_file(repo, "README.md", "# Broken\n[Missing](docs/does-not-exist.md)\n")
            write_repo_file(repo, "bin/fake.dll", b"MZ\x00\x00")
            git(repo, "add", "README.md", "bin/fake.dll")

            res = check_repo_hygiene.run_checks(repo)
            self.assertFalse(res["passed"])
            self.assertTrue(any("Broken relative Markdown link" in e for e in res["errors"]))
            self.assertTrue(any("fake.dll" in e for e in res["errors"]))

    def test_negative_secret_token_private_key_and_personal_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            create_clean_repo(repo)
            # Construct negative test payloads dynamically so this test file stays clean.
            fake_tok = "ghp_" + ("A1b2C3d4E5" * 3)
            fake_key = "-----BEGIN " + "RSA PRIVATE KEY-----"
            fake_path = "C:\\Users\\AlicePersonal\\Documents\\secret.txt"
            write_repo_file(repo, "leak.txt", f"{fake_tok}\n{fake_key}\n{fake_path}\n")
            git(repo, "add", "leak.txt")

            res = check_repo_hygiene.run_checks(repo)
            self.assertFalse(res["passed"])
            self.assertTrue(any("github_classic_token" in e for e in res["errors"]))
            self.assertTrue(any("private_key_header" in e for e in res["errors"]))
            self.assertTrue(any("AlicePersonal" in e for e in res["errors"]))

    def test_negative_insecure_workflow_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            create_clean_repo(repo)
            bad_wf = (
                "name: Bad\n"
                "on: pull_request_target\n"
                "permissions:\n"
                "  contents: write\n"
                "jobs:\n"
                "  bad:\n"
                "    runs-on: self-hosted\n"
                "    continue-on-error: true\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
            )
            write_repo_file(repo, ".github/workflows/ci-test.yml", bad_wf)
            git(repo, "add", ".github/workflows/ci-test.yml")

            res = check_repo_hygiene.run_checks(repo)
            self.assertFalse(res["passed"])
            joined = "\n".join(res["errors"])
            self.assertIn("pull_request_target", joined)
            self.assertIn("non-readonly permission", joined)
            self.assertIn("self-hosted", joined)
            self.assertIn("timeout-minutes", joined)
            self.assertIn("continue-on-error", joined)
            self.assertIn("40-char commit SHA", joined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
