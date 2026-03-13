# Plugin Development Guide

## Purpose

DIPS plugins let external security modules extend the platform without modifying core source files.

Plugins can:

- add new scanner modules
- enrich existing findings after scans
- extend JSON and HTML reports
- integrate local or external defensive tools

## Directory Layout

```text
plugins/
  custom_scanner/
    plugin.py
    config.json
```

## Configuration

Use the `plugin_system` section in your main config:

```json
{
  "plugin_system": {
    "search_paths": ["plugins"],
    "enabled_plugins": ["custom_scanner"],
    "plugin_configs": {
      "custom_scanner": {
        "severity": "high",
        "external_tool_command": "local-yara --scan"
      }
    }
  }
}
```

If a plugin exposes scanner modules, add their module names to `modules.enabled` in execution order.

## Plugin Interface

Plugins implement `SecurityPlugin` from `dips.core.plugin_system.plugin_interface`.

Required properties:

- `plugin_name`
- `version`
- `description`

Optional hooks:

- `validate()`
- `create_modules()`
- `enrich_results(context, results)`
- `extend_report(context, report)`

## Entry Point Options

`plugin.py` must expose one of:

- `PLUGIN_CLASS`
- `get_plugin(...)`
- `plugin`

## Minimal Example

```python
from dips.core.plugin_system.plugin_interface import SecurityPlugin


class ExamplePlugin(SecurityPlugin):
    plugin_name = "example_plugin"
    version = "0.1.0"
    description = "Example DIPS plugin"

    def validate(self) -> None:
        super().validate()

    def create_modules(self):
        return []
```

## Validation Expectations

Plugin validation should confirm:

- required plugin metadata is present
- config is sane
- external tool dependencies are optional or fail gracefully

Plugins should not assume:

- root or administrator access
- network access
- platform-specific directories without checking first

## Best Practices

- keep plugins defensive-only
- use clear finding titles and concrete recommendations
- return structured report extensions instead of raw text blobs
- redact or avoid secret material in plugin-generated evidence
- degrade safely when local tools or optional inputs are missing
- document Linux and Windows behavior explicitly

## Report Extensions

Plugins can contribute structured report data under `extensions.plugins.<plugin_name>`.

Recommended shape:

```json
{
  "version": "1.0.0",
  "description": "Example custom scanner plugin",
  "modules": ["custom_sensitive_file_scanner"],
  "report": {
    "title": "Custom Scanner Insights",
    "summary": "Detected 1 custom artifact and enriched 2 findings."
  }
}
```

## Testing Plugins

Suggested checks:

- plugin loads successfully
- plugin validation rejects bad config
- added modules execute
- report extension appears in JSON and HTML output
- plugin behavior is safe on both Windows and Linux where relevant

Start from the bundled example at [../plugins/custom_scanner](../plugins/custom_scanner).
