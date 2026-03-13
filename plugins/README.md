# Plugins

This folder is the local plugin root used by DIPS during development and example scans.

Included plugin:

- `custom_scanner/`: example external scanner that adds a module, enriches findings, and extends reports

Enable it through `plugin_system.search_paths` and `plugin_system.enabled_plugins` in your config.
