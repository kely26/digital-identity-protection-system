"""Scanner module contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from time import perf_counter

from dips.core.models import Finding, ModuleResult, ScanContext, stable_finding_id


class ScannerModule(ABC):
    name = "base"
    description = "Base module"

    def supports(self, context: ScanContext) -> bool:
        return True

    @abstractmethod
    def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError

    def run_with_results(self, context: ScanContext, prior_results: list[ModuleResult]) -> ModuleResult:
        del prior_results
        return self.run(context)

    def skipped(self, reason: str) -> ModuleResult:
        return ModuleResult(
            module=self.name,
            description=self.description,
            status="skipped",
            warnings=[reason],
        )

    def timed_run(self, context: ScanContext, prior_results: list[ModuleResult] | None = None) -> ModuleResult:
        started = perf_counter()
        result = self.run_with_results(context, prior_results or [])
        result.duration_ms = int((perf_counter() - started) * 1000)
        return result

    def build_finding(
        self,
        *,
        severity: str,
        confidence: str,
        title: str,
        summary: str,
        evidence: dict,
        location: str,
        recommendation: str,
        tags: list[str] | None = None,
    ) -> Finding:
        finding_id = stable_finding_id(self.name, title, location, summary)
        return Finding(
            id=finding_id,
            module=self.name,
            severity=severity,
            confidence=confidence,
            title=title,
            summary=summary,
            evidence=evidence,
            location=location,
            recommendation=recommendation,
            tags=tags or [],
        )
