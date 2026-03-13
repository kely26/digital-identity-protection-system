"""Credential hygiene analysis."""

from __future__ import annotations

from collections import Counter

from dips.core.models import ModuleResult
from dips.modules.base import ScannerModule
from dips.utils.patterns import COMMON_PASSWORDS


class CredentialHygieneScanner(ScannerModule):
    name = "credential_hygiene"
    description = "Analyzes password quality and reuse patterns."

    @staticmethod
    def _character_classes(password: str) -> int:
        return sum(
            [
                any(char.islower() for char in password),
                any(char.isupper() for char in password),
                any(char.isdigit() for char in password),
                any(not char.isalnum() for char in password),
            ]
        )

    def run(self, context) -> ModuleResult:
        passwords = context.password_inputs
        if not passwords:
            return self.skipped("No password candidates were provided; supply --password-file or credential.passwords.")

        findings = []
        counts = Counter(passwords)
        for password, count in counts.items():
            password_lower = password.lower()
            evidence = {"length": len(password), "count": count}

            if count > 1:
                findings.append(
                    self.build_finding(
                        severity="high",
                        confidence="high",
                        title="Password reuse detected",
                        summary="The same password was provided multiple times, which suggests reuse across accounts or services.",
                        evidence=evidence,
                        location="credential_inputs",
                        recommendation="Use unique passwords for each account and store them in a password manager.",
                        tags=["password", "reuse"],
                    )
                )

            if len(password) < 12:
                findings.append(
                    self.build_finding(
                        severity="medium",
                        confidence="high",
                        title="Short password detected",
                        summary="A password candidate is shorter than the recommended 12-character baseline.",
                        evidence=evidence,
                        location="credential_inputs",
                        recommendation="Use passphrases or long random passwords with at least 12-16 characters.",
                        tags=["password", "length"],
                    )
                )

            if self._character_classes(password) < 3:
                findings.append(
                    self.build_finding(
                        severity="medium",
                        confidence="medium",
                        title="Low password complexity detected",
                        summary="A password candidate lacks enough character variety.",
                        evidence=evidence,
                        location="credential_inputs",
                        recommendation="Mix upper-case, lower-case, digits, and symbols or use longer passphrases.",
                        tags=["password", "complexity"],
                    )
                )

            if password_lower in COMMON_PASSWORDS:
                findings.append(
                    self.build_finding(
                        severity="high",
                        confidence="high",
                        title="Common password detected",
                        summary="A password candidate matches a widely known common password.",
                        evidence=evidence,
                        location="credential_inputs",
                        recommendation="Replace common passwords with unique, manager-generated secrets.",
                        tags=["password", "common"],
                    )
                )

            for identifier in context.user_identifiers:
                if identifier and identifier.lower() in password_lower:
                    findings.append(
                        self.build_finding(
                            severity="medium",
                            confidence="medium",
                            title="Password contains personal identifier",
                            summary="A password candidate contains the current username or email local-part.",
                            evidence={**evidence, "identifier": identifier},
                            location="credential_inputs",
                            recommendation="Do not include names, usernames, or email identifiers in passwords.",
                            tags=["password", "identifier"],
                        )
                    )
                    break

        return ModuleResult(
            module=self.name,
            description=self.description,
            status="completed",
            findings=findings,
            metadata={"password_count": len(passwords), "unique_passwords": len(counts)},
        )
