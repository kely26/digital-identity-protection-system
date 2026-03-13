# FAQ

## Is DIPS an offensive tool?

No. DIPS is defensive-only. It is designed for identity-risk visibility, privacy protection, configuration review, and analyst workflows.

## Does DIPS send my data to the cloud?

Not by default. Core scanning is local-first. Some modules support optional provider integrations, but those are opt-in.

## Does DIPS decrypt stored browser passwords?

No. DIPS audits browser posture and artifact presence. It does not decrypt protected browser vaults.

## What operating systems are supported?

Windows and Linux.

## Does DIPS require administrator or root privileges?

Not for standard operation. It scans the current user context by default and is intended to work safely without invasive host changes.

## What kind of risks does DIPS detect?

- identity exposure in local files
- weak password hygiene
- breach exposure
- risky local privacy artifacts
- browser security issues
- phishing indicators
- malicious reputation hits from threat intelligence
- correlated risk patterns across modules

## What is the Digital Identity Risk Score?

It is a configurable weighted score derived from findings across modules such as breach exposure, credential hygiene, browser posture, phishing indicators, token exposure, and privacy risk.

## Can I extend DIPS with my own scanner?

Yes. Use the plugin system for external modules and the scanner contract for core-style modules. Start with [plugins.md](plugins.md) and [module-development.md](module-development.md).

## Can I use DIPS without the desktop dashboard?

Yes. The CLI is a first-class interface. You can run scans, watch mode, config inspection, and report export without the GUI.

## How do I generate GitHub-quality screenshots?

Run a fixture-backed scan, then load the generated JSON report in the dashboard and save screenshots with:

```bash
dips dashboard --load-report reports/<scan-id>.json --page overview --screenshot screenshots/dashboard-overview.png
```

## Why are report values redacted?

Because DIPS defaults to privacy-respecting evidence handling. Redaction is intended to reduce accidental exposure in exports, screenshots, and shared artifacts.
