"""AI-powered analysis of existing scan findings."""

from __future__ import annotations

import json
import os
from html import unescape
from typing import Any
from urllib import error, request

from dips.core.models import ModuleResult
from dips.modules.ai_security_analysis.finding_summarizer import (
    build_finding_digest,
    build_security_summary,
    collect_ranked_findings,
    findings_reviewed,
    module_names,
    severity_counts,
)
from dips.modules.ai_security_analysis.risk_explainer import (
    detect_suspicious_patterns,
    explain_risk,
    synthesize_recommendations,
)
from dips.modules.base import ScannerModule
from dips.utils.text import clip_text, normalize_whitespace


class AiSecurityAnalysisScanner(ScannerModule):
    name = "ai_security_analysis"
    description = "Summarizes findings, explains risk in plain language, and highlights compound identity threats."

    def run(self, context) -> ModuleResult:
        del context
        return self.skipped("AI security analysis requires prior module results from the same scan.")

    def run_with_results(self, context, prior_results: list[ModuleResult]) -> ModuleResult:
        settings = context.config.ai_security_analysis
        warnings: list[str] = []
        findings = collect_ranked_findings(prior_results, limit=settings.max_findings)
        reviewed = findings_reviewed(prior_results)
        provider = settings.provider
        analysis_mode = "local"

        analysis = self._build_local_analysis(findings, settings.max_recommendations, reviewed)
        if settings.allow_online and settings.provider != "local_heuristic":
            try:
                analysis = self._run_online_analysis(context, findings, reviewed)
                analysis_mode = "online-redacted"
            except RuntimeError as exc:
                warnings.append(f"Online AI analysis fallback: {exc}")
                analysis_mode = "local-fallback"
                provider = "local_heuristic"

        module_findings = [
            self.build_finding(
                severity="info",
                confidence="medium" if analysis_mode.startswith("local") else "high",
                title="AI security summary",
                summary=analysis["summary"],
                evidence={
                    "provider": provider,
                    "analysis_mode": analysis_mode,
                    "findings_reviewed": reviewed,
                    "suspicious_pattern_count": len(analysis["suspicious_patterns"]),
                },
                location="report_summary",
                recommendation=analysis["recommended_actions"][0]
                if analysis["recommended_actions"]
                else "Keep periodic scans enabled and review the latest report.",
                tags=["ai-analysis", "summary"],
            )
        ]

        for pattern in analysis["suspicious_patterns"]:
            tags = [str(item) for item in pattern.get("tags", []) if str(item).strip()]
            if "ai-analysis" not in tags:
                tags.append("ai-analysis")
            module_findings.append(
                self.build_finding(
                    severity=str(pattern.get("severity", "medium")),
                    confidence="medium",
                    title=str(pattern.get("title", "AI-detected suspicious pattern")),
                    summary=str(pattern.get("summary", "Cross-module security pattern detected.")),
                    evidence={
                        "provider": provider,
                        "related_findings": pattern.get("related_findings", []),
                    },
                    location="cross-module-analysis",
                    recommendation=str(
                        pattern.get("recommendation", "Review correlated findings and remediate the highest-risk source.")
                    ),
                    tags=tags,
                )
            )

        return ModuleResult(
            module=self.name,
            description=self.description,
            status="completed",
            findings=module_findings,
            warnings=warnings,
            metadata={
                "provider": provider,
                "analysis_mode": analysis_mode,
                "summary": analysis["summary"],
                "risk_explanation": analysis["risk_explanation"],
                "recommended_actions": analysis["recommended_actions"],
                "suspicious_patterns": analysis["suspicious_patterns"],
                "findings_reviewed": reviewed,
                "source_modules": module_names(findings),
                "severity_counts": severity_counts(findings),
                "finding_digest": build_finding_digest(findings, max_items=min(6, len(findings))),
            },
        )

    def _build_local_analysis(
        self,
        findings,
        max_recommendations: int,
        reviewed: int,
    ) -> dict[str, Any]:
        patterns = detect_suspicious_patterns(findings)
        return {
            "summary": normalize_whitespace(build_security_summary(findings)),
            "risk_explanation": normalize_whitespace(explain_risk(findings)),
            "recommended_actions": synthesize_recommendations(
                findings,
                patterns,
                max_recommendations=max_recommendations,
            ),
            "suspicious_patterns": patterns,
            "findings_reviewed": reviewed,
        }

    def _run_online_analysis(self, context, findings, reviewed: int) -> dict[str, Any]:
        settings = context.config.ai_security_analysis
        api_key = os.environ.get(settings.api_key_env, "").strip() if settings.api_key_env else ""
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        payload = {
            "model": settings.model,
            "scan": {
                "platform": context.platform_name,
                "hostname": context.hostname,
                "report_scope": "redacted-summary",
                "findings_reviewed": reviewed,
            },
            "findings": [
                {
                    "module": item.module,
                    "severity": item.finding.severity,
                    "title": item.finding.title,
                    "summary": clip_text(normalize_whitespace(item.finding.summary), 180),
                    "tags": item.finding.tags,
                }
                for item in findings
            ],
        }

        body = json.dumps(payload).encode("utf-8")
        req = request.Request(settings.endpoint, data=body, headers=headers, method="POST")
        try:
            with request.urlopen(req, timeout=settings.timeout_seconds) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except error.URLError as exc:
            raise RuntimeError(f"provider request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise RuntimeError("provider request timed out") from exc

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("provider returned invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise RuntimeError("provider returned an invalid response object")

        patterns = self._normalize_patterns(parsed.get("suspicious_patterns", []))
        recommendations = self._normalize_string_list(parsed.get("recommended_actions", []))
        if not recommendations:
            recommendations = self._build_local_analysis(findings, settings.max_recommendations, reviewed)[
                "recommended_actions"
            ]

        summary = normalize_whitespace(str(parsed.get("summary", "") or "")).strip()
        explanation = normalize_whitespace(str(parsed.get("risk_explanation", "") or "")).strip()
        if not summary or not explanation:
            fallback = self._build_local_analysis(findings, settings.max_recommendations, reviewed)
            summary = summary or fallback["summary"]
            explanation = explanation or fallback["risk_explanation"]
            if not patterns:
                patterns = fallback["suspicious_patterns"]

        return {
            "summary": unescape(summary),
            "risk_explanation": unescape(explanation),
            "recommended_actions": recommendations[: settings.max_recommendations],
            "suspicious_patterns": patterns,
            "findings_reviewed": reviewed,
        }

    @staticmethod
    def _normalize_string_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        result: list[str] = []
        for item in value:
            text = normalize_whitespace(str(item)).strip()
            if text:
                result.append(text)
        return result

    def _normalize_patterns(self, value: Any) -> list[dict[str, object]]:
        if not isinstance(value, list):
            return []
        patterns: list[dict[str, object]] = []
        for item in value:
            if not isinstance(item, dict):
                continue
            title = normalize_whitespace(str(item.get("title", ""))).strip()
            summary = normalize_whitespace(str(item.get("summary", ""))).strip()
            if not title or not summary:
                continue
            patterns.append(
                {
                    "title": title,
                    "summary": summary,
                    "severity": str(item.get("severity", "medium")).lower(),
                    "recommendation": normalize_whitespace(str(item.get("recommendation", ""))).strip(),
                    "tags": self._normalize_string_list(item.get("tags", [])),
                    "related_findings": self._normalize_string_list(item.get("related_findings", [])),
                }
            )
        return patterns
