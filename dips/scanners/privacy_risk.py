"""Local privacy risk scanning."""

from __future__ import annotations

import stat

from dips.core.models import ModuleResult
from dips.modules.base import ScannerModule


class PrivacyRiskScanner(ScannerModule):
    name = "privacy_risk"
    description = "Scans the local user profile for privacy and storage misconfigurations."

    def run(self, context) -> ModuleResult:
        findings = []
        profile = context.user_profile
        platform_name = context.platform_name

        known_sensitive_files = [
            profile / ".bash_history",
            profile / ".zsh_history",
            profile / ".git-credentials",
            profile / ".npmrc",
            profile / ".pypirc",
            profile / ".aws" / "credentials",
            profile / ".ssh" / "id_rsa",
            profile / ".ssh" / "id_ed25519",
        ]

        for candidate in known_sensitive_files:
            if not candidate.exists():
                continue

            if candidate.name in {".bash_history", ".zsh_history"}:
                findings.append(
                    self.build_finding(
                        severity="low",
                        confidence="high",
                        title="Shell history file present",
                        summary="Shell history can retain copied secrets, tokens, or investigation commands.",
                        evidence={"file": str(candidate)},
                        location=str(candidate),
                        recommendation="Review shell history, clear sensitive entries, and avoid pasting secrets into terminals.",
                        tags=["privacy", "shell-history"],
                    )
                )
                continue

            if candidate.name in {"id_rsa", "id_ed25519"}:
                findings.append(
                    self.build_finding(
                        severity="high",
                        confidence="high",
                        title="Private SSH key stored in profile",
                        summary="A private SSH key exists in the user profile and should be tightly permissioned.",
                        evidence={"file": str(candidate)},
                        location=str(candidate),
                        recommendation="Ensure the key is required, protected by a passphrase, and restricted to the owning user.",
                        tags=["ssh", "private-key", "privacy"],
                    )
                )
            else:
                findings.append(
                    self.build_finding(
                        severity="medium",
                        confidence="high",
                        title="Sensitive credential store detected",
                        summary="A local file known to contain authentication material was found in the profile.",
                        evidence={"file": str(candidate)},
                        location=str(candidate),
                        recommendation="Review whether the file is needed and reduce plaintext credential storage where possible.",
                        tags=["credential-store", "privacy"],
                    )
                )

            if platform_name != "windows":
                try:
                    mode = stat.S_IMODE(candidate.stat().st_mode)
                except OSError:
                    continue
                if mode & (stat.S_IRWXG | stat.S_IRWXO):
                    findings.append(
                        self.build_finding(
                            severity="high",
                            confidence="high",
                            title="Sensitive file has broad permissions",
                            summary="A credential or private-key file is readable or writable by group or other users.",
                            evidence={"file": str(candidate), "mode": oct(mode)},
                            location=str(candidate),
                            recommendation="Restrict the file to owner-only access, typically chmod 600 for private artifacts.",
                            tags=["permissions", "local-hardening"],
                        )
                    )

        for directory_name in ("Documents", "Desktop", "Downloads"):
            candidate_dir = profile / directory_name
            if not candidate_dir.exists():
                continue
            for file_path in candidate_dir.glob("*"):
                if not file_path.is_file():
                    continue
                name = file_path.name.lower()
                if name.endswith(".csv") and ("password" in name or "credential" in name or "browser" in name):
                    findings.append(
                        self.build_finding(
                            severity="high",
                            confidence="medium",
                            title="Possible browser or credential export detected",
                            summary="A CSV export in a common user directory may contain credentials or identity data.",
                            evidence={"file": str(file_path)},
                            location=str(file_path),
                            recommendation="Delete stale exports and move required files into encrypted or access-restricted storage.",
                            tags=["export", "browser", "privacy"],
                        )
                    )

        return ModuleResult(
            module=self.name,
            description=self.description,
            status="completed",
            findings=findings,
            metadata={"profile": str(profile), "platform": platform_name},
        )
