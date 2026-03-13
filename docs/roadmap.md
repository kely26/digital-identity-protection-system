# Development Roadmap

This roadmap outlines the next realistic stages for DIPS as a local-first identity security platform. It is intentionally structured around defensive value, operator usability, and maintainable engineering scope.

## Roadmap Principles

- Keep the core product useful without mandatory cloud dependencies.
- Expand intelligence and analytics without weakening privacy guarantees.
- Prioritize features that improve analyst decision-making, not just surface area.
- Grow the plugin and integration story in a controlled, documented way.

## Phase 1: Intelligence and Detection Depth

Primary goals:

- Add additional threat intelligence sources with per-provider trust metadata and better source attribution.
- Improve phishing analysis with attachment heuristics, sender impersonation detection, and richer message-authentication interpretation.
- Expand offline dataset tooling for breach and IOC curation so operators can maintain higher-quality local intelligence packs.

Why it matters:

- Better enrichment increases the value of local findings.
- Stronger phishing analysis improves the practical usefulness of the alerting pipeline.
- Better offline datasets keep the project aligned with its local-first model.

## Phase 2: Analytics and Operator Workflow

Primary goals:

- Enhance dashboard analytics with stronger trend views, scan-to-scan comparisons, and investigation shortcuts.
- Improve alert correlation workflows so related phishing, token, breach, and browser findings are easier to triage as one incident.
- Add richer reporting comparisons and posture drift summaries for recurring scans and watch mode.

Why it matters:

- Operators need to understand change over time, not just a single report snapshot.
- Better correlation reduces alert fatigue and makes the dashboard feel closer to a real analyst tool.

## Phase 3: Enterprise-Oriented Operations

Primary goals:

- Introduce an enterprise deployment mode with controlled multi-endpoint rollout patterns and team-safe configuration bundles.
- Add explicit opt-in cloud monitoring integrations for approved defensive systems such as SIEM, SOAR, and alert-routing platforms.
- Improve packaging and artifact delivery for larger rollouts, including signed builds and cleaner deployment guidance.

Why it matters:

- Some users will want to move from single-host visibility to repeatable team operations.
- Integrations should exist, but remain optional and privacy-conscious.

## Phase 4: Ecosystem and Extensibility

Primary goals:

- Expand the plugin ecosystem with stronger templates, plugin packaging guidance, and compatibility/version metadata.
- Publish more example plugins for external security tools, enrichment providers, and custom reporting extensions.
- Improve contributor ergonomics around module development, testing, and release compatibility.

Why it matters:

- A healthier plugin ecosystem increases the value of the core platform without bloating the main codebase.
- Good contributor workflows make the project easier to adopt and extend.

## Candidate Future Improvements

- Additional reputation and threat-feed providers
- Improved phishing body-language and lure analysis
- Enterprise deployment profiles and rollout tooling
- Cloud monitoring and alert-routing integrations
- Enhanced dashboard trend analytics and investigation panels
- More mature plugin validation, discovery, and packaging support

## What Not to Compromise

Even as the project grows, the roadmap assumes these constraints stay intact:

- local-first by default
- defensive-only in scope
- safe handling of sensitive data
- transparent reports and explainable scoring
- Windows and Linux support as first-class targets

For the public project overview, see [../README.md](../README.md). For the architecture that this roadmap builds on, see [architecture.md](architecture.md).
