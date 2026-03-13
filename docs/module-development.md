# Module Development

## Scanner Contract

Every built-in scanner subclasses `dips.modules.base.ScannerModule` and should:

- expose a stable `name`
- provide a concise `description`
- implement `supports(context) -> bool` when host applicability is conditional
- implement `run(context) -> ModuleResult`

Use `build_finding(...)` from the base class to keep finding identifiers and field shape consistent.

## Scan Context Expectations

Scanners receive an immutable `ScanContext` that already contains:

- merged and validated application config
- normalized target paths
- pre-discovered candidate files
- discovered browser profiles
- optional password and email inputs
- basic host metadata and operator identifiers

Do not mutate the context in-place.

## Performance Guidance

- Reuse `context.candidate_files` instead of walking the filesystem again.
- Short-circuit early when the module does not apply.
- Bound concurrency carefully and avoid unbounded thread pools.
- Treat missing files, unreadable artifacts, and malformed inputs as recoverable conditions.

## Findings and Evidence

Every finding should include:

- a severity with operational meaning
- a confidence level
- clear location metadata
- a concrete remediation recommendation
- evidence that is useful but safe to redact

Report renderers redact evidence by default. Avoid placing raw credential material or entire file contents into findings.

## Testing Expectations

New modules should include:

- unit tests for core detection logic
- fixture-based tests for representative host artifacts
- at least one CLI or engine-path test if the module changes runtime behavior

Cross-platform behavior should be explicit. If a module is platform-specific, encode that in `supports(context)` and test both the supported and unsupported paths.
