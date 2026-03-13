# Release Title

`vX.Y.Z`

## Summary

- Short description of the release scope.
- Primary operator or developer-facing value.

## Highlights

- Major feature or capability
- Important quality/security/performance improvement
- Dashboard, reporting, or packaging improvement

## Included Changes

- CLI:
- Dashboard:
- Scanners and modules:
- Reporting:
- Documentation:

## Upgrade Notes

- Configuration changes:
- New dependencies or packaging changes:
- Migration or compatibility notes:

## Verification

- `pytest`
- `ruff check .`
- `python -m compileall dips tests`
- `python -m build`
- `twine check dist/*`
- `dips scan --config config/example.config.json`
- `dips dashboard --demo`

## Assets

- Source tarball
- Source zip
- Wheel
- Any optional desktop screenshots or demo artifacts
