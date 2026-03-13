"""Identity exposure scanning."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dips.core.models import ModuleResult
from dips.modules.base import ScannerModule
from dips.utils.files import safe_read_text
from dips.utils.patterns import (
    AWS_ACCESS_KEY_RE,
    EMAIL_RE,
    GITHUB_TOKEN_RE,
    JWT_RE,
    PLAINTEXT_PASSWORD_RE,
    PRIVATE_KEY_RE,
    SENSITIVE_FILENAME_RE,
)
from dips.utils.text import clip_text


class IdentityExposureScanner(ScannerModule):
    name = "identity_exposure"
    description = "Detects identity-related exposures in local files."

    def _scan_file(self, path: Path) -> list:
        findings = []
        content = safe_read_text(path)
        location = str(path)

        emails = sorted(set(EMAIL_RE.findall(content)))
        if emails:
            findings.append(
                self.build_finding(
                    severity="medium",
                    confidence="medium",
                    title="Exposed email addresses detected",
                    summary=f"Found {len(emails)} email address patterns in a local file.",
                    evidence={"matches": emails[:5], "file": location},
                    location=location,
                    recommendation="Review whether this file should contain personal or corporate email addresses in plaintext.",
                    tags=["identity", "email", "exposure"],
                )
            )

        password_matches = PLAINTEXT_PASSWORD_RE.findall(content)
        if password_matches:
            findings.append(
                self.build_finding(
                    severity="high",
                    confidence="high",
                    title="Plaintext credential material detected",
                    summary="Found plaintext password or token assignment patterns in a local file.",
                    evidence={"matches": [item[0] for item in password_matches[:5]], "file": location},
                    location=location,
                    recommendation="Remove plaintext secrets from files and move them into secure secret storage.",
                    tags=["credential", "plaintext", "exposure"],
                )
            )

        if GITHUB_TOKEN_RE.search(content):
            findings.append(
                self.build_finding(
                    severity="critical",
                    confidence="high",
                    title="GitHub token pattern detected",
                    summary="A string matching a GitHub token pattern was found in a local file.",
                    evidence={"sample": clip_text(content), "file": location},
                    location=location,
                    recommendation="Rotate the token immediately and remove it from local plaintext storage.",
                    tags=["token", "github", "secret"],
                )
            )

        if AWS_ACCESS_KEY_RE.search(content):
            findings.append(
                self.build_finding(
                    severity="critical",
                    confidence="high",
                    title="AWS access key pattern detected",
                    summary="A string matching an AWS access key identifier was found in a local file.",
                    evidence={"sample": clip_text(content), "file": location},
                    location=location,
                    recommendation="Rotate the AWS credential and store it in a managed secret store.",
                    tags=["aws", "cloud", "secret"],
                )
            )

        if JWT_RE.search(content):
            findings.append(
                self.build_finding(
                    severity="high",
                    confidence="medium",
                    title="JWT-like token detected",
                    summary="A JWT-like token string was found in a local file.",
                    evidence={"sample": clip_text(content), "file": location},
                    location=location,
                    recommendation="Avoid storing long-lived access tokens in plaintext files.",
                    tags=["jwt", "token", "session"],
                )
            )

        if PRIVATE_KEY_RE.search(content):
            findings.append(
                self.build_finding(
                    severity="critical",
                    confidence="high",
                    title="Private key material detected",
                    summary="A private key header was found in a file included in the scan scope.",
                    evidence={"header": "private key header detected", "file": location},
                    location=location,
                    recommendation="Restrict access to the key, verify permissions, and move it out of broad-access locations.",
                    tags=["private-key", "crypto", "secret"],
                )
            )

        if SENSITIVE_FILENAME_RE.match(path.name):
            findings.append(
                self.build_finding(
                    severity="medium",
                    confidence="medium",
                    title="Sensitive file naming pattern detected",
                    summary="The filename suggests it may store credentials, secrets, or identity exports.",
                    evidence={"file_name": path.name},
                    location=location,
                    recommendation="Review whether this file should exist in plaintext and restrict or remove it if unnecessary.",
                    tags=["filename", "privacy", "identity"],
                )
            )

        return findings

    def run(self, context) -> ModuleResult:
        candidate_files = context.candidate_files
        findings = []
        workers = max(1, context.config.scan.max_workers)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for file_findings in executor.map(self._scan_file, candidate_files):
                findings.extend(file_findings)

        return ModuleResult(
            module=self.name,
            description=self.description,
            status="completed",
            findings=findings,
            metadata={"scanned_files": len(candidate_files), "target_paths": [str(path) for path in context.target_paths]},
        )
