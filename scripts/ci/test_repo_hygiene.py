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
    "        with:\n"
    "          persist-credentials: false\n"
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
            fake_path = "C:\\" + "Users\\AlicePersonal\\Documents\\secret.txt"
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
                "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
                "        with:\n"
                "          persist-credentials: true\n"
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
            self.assertIn("persist-credentials: false", joined)

    def test_generic_privacy_policy_allows_legitimate_emails_and_blocks_consumer_webmail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            create_clean_repo(repo)
            safe_doc = (
                "# Notices & Docs\n"
                "Author noreply: 999999+contributor@users.noreply.github.com\n"
                "Third-party attribution: legal@vendor-thirdparty.org\n"
                "Synthetic RFC 2606 fixture: alice@example.com\n"
                "Documentation placeholder: placeholder@example.org\n"
                "Generic consumer placeholder: " + "placeholder" + "@gmail.com\n"
            )
            write_repo_file(repo, "docs/contacts.md", safe_doc)
            git(repo, "add", "docs/contacts.md")

            safe_res = check_repo_hygiene.run_checks(repo)
            self.assertTrue(safe_res["passed"], f"Unexpected false positive: {safe_res['errors']}")

            leaked_local = "synth.personal.user"
            leaked_addr = leaked_local + "@gmail.com"
            write_repo_file(repo, "docs/leak-email.txt", f"Contact: {leaked_addr}\n")
            git(repo, "add", "docs/leak-email.txt")

            bad_res = check_repo_hygiene.run_checks(repo)
            self.assertFalse(bad_res["passed"])
            joined = "\n".join(bad_res["errors"])
            self.assertIn("Potential personal webmail address detected", joined)
            self.assertNotIn(leaked_local, joined)

    def test_dco_valid_single_and_multiple_signoffs_and_push_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            hist1, cutoff = create_clean_repo(repo)
            write_repo_file(repo, "docs/multi.md", "# Multi sign-off\n")
            git(repo, "add", "docs/multi.md")
            msg = (
                "docs: commit with multiple valid sign-offs\n\n"
                "Co-reviewed and committed under DCO.\n\n"
                "Signed-off-by: Test Maintainer <test@users.noreply.github.com>\n"
                "Signed-off-by: Secondary Reviewer <reviewer@example.org>\n"
            )
            git(repo, "commit", "-m", msg)
            head = git(repo, "rev-parse", "HEAD")

            res = check_repo_hygiene.run_checks(
                repo, dco_base=hist1, dco_head=head, dco_cutoff=cutoff
            )
            self.assertTrue(res["passed"], f"Expected multi sign-off to pass: {res['errors']}")
            self.assertTrue(res["checked"]["dco_checked"])
            self.assertEqual(res["checked"]["dco_prospective_commits"], 1)

            # Simulate push / workflow_dispatch without PR DCO commit range.
            skip_res = check_repo_hygiene.run_checks(repo)
            self.assertTrue(skip_res["passed"], f"Unexpected failure on skip path: {skip_res['errors']}")
            self.assertFalse(skip_res["checked"]["dco_checked"])
            self.assertEqual(skip_res["checked"].get("dco_skip_reason"), "no_pr_commit_range_supplied")

    def test_negative_dco_mismatch_body_fake_invalid_cutoff_and_incomplete_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _, cutoff = create_clean_repo(repo)

            # 1. Signed-off-by belonging to a different author identity must fail.
            write_repo_file(repo, "docs/mismatch.md", "# Mismatch\n")
            git(repo, "add", "docs/mismatch.md")
            git(
                repo,
                "commit",
                "-m",
                "docs: mismatched signoff\n\nSigned-off-by: Different Person <other@users.noreply.github.com>\n",
            )
            mismatch_head = git(repo, "rev-parse", "HEAD")
            mismatch_res = check_repo_hygiene.run_checks(
                repo, dco_base=cutoff, dco_head=mismatch_head, dco_cutoff=cutoff
            )
            self.assertFalse(mismatch_res["passed"])
            self.assertTrue(any("does not match commit authorship" in e for e in mismatch_res["errors"]))

            # 2. Signed-off-by buried in body followed by trailing prose is NOT a recognized Git trailer.
            write_repo_file(repo, "docs/body-fake.md", "# Body fake\n")
            git(repo, "add", "docs/body-fake.md")
            fake_msg = (
                "docs: fake signoff in body\n\n"
                "Signed-off-by: Test Maintainer <test@users.noreply.github.com>\n\n"
                "Paragraph after line prevents Git from treating above as a trailer.\n"
            )
            git(repo, "commit", "-m", fake_msg)
            fake_head = git(repo, "rev-parse", "HEAD")
            fake_res = check_repo_hygiene.run_checks(
                repo, dco_base=mismatch_head, dco_head=fake_head, dco_cutoff=cutoff
            )
            self.assertFalse(fake_res["passed"])
            self.assertTrue(any("Missing recognized Signed-off-by Git trailer" in e for e in fake_res["errors"]))

            # 3. Invalid cutoff must NEVER be silently ignored (with or without range).
            bad_cutoff = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            bad_cut_res = check_repo_hygiene.run_checks(
                repo, dco_base=cutoff, dco_head=fake_head, dco_cutoff=bad_cutoff
            )
            self.assertFalse(bad_cut_res["passed"])
            self.assertFalse(bad_cut_res["checked"]["dco_checked"])
            self.assertTrue(any("--dco-cutoff" in e for e in bad_cut_res["errors"]))

            bad_cut_alone = check_repo_hygiene.run_checks(repo, dco_cutoff=bad_cutoff)
            self.assertFalse(bad_cut_alone["passed"])
            self.assertTrue(any("--dco-cutoff" in e for e in bad_cut_alone["errors"]))

            # 4. Invalid base or head references must fail explicitly.
            bad_base_res = check_repo_hygiene.run_checks(
                repo, dco_base="nonexistent-ref", dco_head=fake_head, dco_cutoff=cutoff
            )
            self.assertFalse(bad_base_res["passed"])
            self.assertTrue(any("--dco-base" in e for e in bad_base_res["errors"]))

            bad_head_res = check_repo_hygiene.run_checks(
                repo, dco_base=cutoff, dco_head="nonexistent-head", dco_cutoff=cutoff
            )
            self.assertFalse(bad_head_res["passed"])
            self.assertTrue(any("--dco-head" in e for e in bad_head_res["errors"]))

            # 5. Incomplete base/head pair must fail explicitly.
            only_base = check_repo_hygiene.run_checks(repo, dco_base=cutoff, dco_cutoff=cutoff)
            self.assertFalse(only_base["passed"])
            self.assertTrue(any("Incomplete DCO range" in e for e in only_base["errors"]))

            only_head = check_repo_hygiene.run_checks(repo, dco_head=fake_head, dco_cutoff=cutoff)
            self.assertFalse(only_head["passed"])
            self.assertTrue(any("Incomplete DCO range" in e for e in only_head["errors"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
