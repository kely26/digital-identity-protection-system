"""Plugin system for external DIPS integrations."""

from dips.core.plugin_system.plugin_interface import LoadedPlugin, SecurityPlugin
from dips.core.plugin_system.plugin_registry import PluginRegistry, load_plugin_registry

__all__ = ["LoadedPlugin", "PluginRegistry", "SecurityPlugin", "load_plugin_registry"]
