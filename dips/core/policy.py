"""Policy evaluation for scan automation workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from dips.core.models import SEVERITY_ORDER, ScanReport


SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


@dataclass(slots=True)
class PolicyViolation:
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def evaluate_scan_policy(
    report: ScanReport,
    *,
    fail_on_severity: str | None = None,
    fail_on_score: int | None = None,
) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []

    if fail_on_score is not None and report.summary.overall_score >= fail_on_score:
        violations.append(
            PolicyViolation(
                code="risk_score_threshold",
                message=(
                    f"Overall risk score {report.summary.overall_score} met or exceeded the configured "
                    f"failure threshold of {fail_on_score}."
                ),
                details={"overall_score": report.summary.overall_score, "threshold": fail_on_score},
            )
        )

    if fail_on_severity is not None:
        threshold_rank = SEVERITY_RANK[fail_on_severity]
        matching = [
            finding
            for module in report.modules
            for finding in module.findings
            if SEVERITY_RANK.get(finding.severity, -1) >= threshold_rank
        ]
        if matching:
            highest = max(matching, key=lambda finding: SEVERITY_RANK.get(finding.severity, -1)).severity
            violations.append(
                PolicyViolation(
                    code="finding_severity_threshold",
                    message=(
                        f"Detected {len(matching)} finding(s) at or above the configured severity threshold "
                        f"of {fail_on_severity}. Highest observed severity: {highest}."
                    ),
                    details={
                        "threshold": fail_on_severity,
                        "match_count": len(matching),
                        "highest_severity": highest,
                    },
                )
            )

    return violations
