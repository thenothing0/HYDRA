"""
╔══════════════════════════════════════════════════════════════╗
║  Modular Plugin System — Hot-loadable Extensions           ║
║  Python plugins, MCP plugins, external API connectors      ║
╚══════════════════════════════════════════════════════════════╝
"""

import importlib
import importlib.util
import logging
import os
from typing import Any, Dict, List, Optional, Type
from dataclasses import dataclass, field
from pathlib import Path
from abc import ABC, abstractmethod

logger = logging.getLogger("hydra.plugins")


@dataclass
class PluginInfo:
    """Plugin metadata."""
    name: str
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    plugin_type: str = "tool"  # tool, agent, integration
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)


class HydraPlugin(ABC):
    """Base class for all HYDRA plugins."""

    NAME: str = "base_plugin"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = ""
    PLUGIN_TYPE: str = "tool"

    @abstractmethod
    async def initialize(self, config: Dict[str, Any]):
        """Initialize the plugin with configuration."""
        pass

    @abstractmethod
    async def execute(self, action: str,
                      params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a plugin action."""
        pass

    async def shutdown(self):
        """Clean up plugin resources."""
        pass

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name=self.NAME, version=self.VERSION,
            description=self.DESCRIPTION,
            plugin_type=self.PLUGIN_TYPE,
        )

    def get_actions(self) -> List[str]:
        """Return list of supported actions."""
        return []


class ToolPlugin(HydraPlugin):
    """Plugin that provides security tools."""
    PLUGIN_TYPE = "tool"

    @abstractmethod
    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return tool definitions for MCP registration."""
        pass


class AgentPlugin(HydraPlugin):
    """Plugin that provides custom agents."""
    PLUGIN_TYPE = "agent"

    @abstractmethod
    def get_agent_class(self) -> Type:
        """Return the agent class to register."""
        pass


class IntegrationPlugin(HydraPlugin):
    """Plugin for external API integrations."""
    PLUGIN_TYPE = "integration"


class PluginRegistry:
    """Registry of loaded plugins."""

    def __init__(self):
        self._plugins: Dict[str, HydraPlugin] = {}
        self._info: Dict[str, PluginInfo] = {}

    def register(self, plugin: HydraPlugin):
        name = plugin.NAME
        self._plugins[name] = plugin
        self._info[name] = plugin.get_info()
        logger.info(f"🔌 Plugin registered: {name} v{plugin.VERSION}")

    def unregister(self, name: str):
        self._plugins.pop(name, None)
        self._info.pop(name, None)

    def get(self, name: str) -> Optional[HydraPlugin]:
        return self._plugins.get(name)

    def get_all(self) -> Dict[str, HydraPlugin]:
        return dict(self._plugins)

    def get_by_type(self, plugin_type: str) -> List[HydraPlugin]:
        return [
            p for p in self._plugins.values()
            if p.PLUGIN_TYPE == plugin_type
        ]

    def list_plugins(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": info.name, "version": info.version,
                "description": info.description,
                "type": info.plugin_type,
                "enabled": info.enabled,
            }
            for info in self._info.values()
        ]


class PluginLoader:
    """
    Dynamic plugin loader.
    
    Supports:
      - Python module plugins
      - Directory-based plugin discovery
      - Hot-reload (re-import)
      - Configuration injection
    """

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        self.plugin_dirs = [
            Path(d) for d in (plugin_dirs or ["plugins"])
        ]
        self.registry = PluginRegistry()

    async def discover_and_load(self):
        """Discover and load plugins from plugin directories."""
        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                plugin_dir.mkdir(parents=True, exist_ok=True)
                continue

            for item in plugin_dir.iterdir():
                if item.suffix == ".py" and not item.name.startswith("_"):
                    await self._load_plugin_file(item)
                elif item.is_dir() and (item / "__init__.py").exists():
                    await self._load_plugin_package(item)

    async def _load_plugin_file(self, path: Path):
        """Load a single Python plugin file."""
        try:
            spec = importlib.util.spec_from_file_location(
                f"hydra_plugin_{path.stem}", str(path)
            )
            if not spec or not spec.loader:
                return

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find HydraPlugin subclasses
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type)
                        and issubclass(attr, HydraPlugin)
                        and attr is not HydraPlugin
                        and attr not in (ToolPlugin, AgentPlugin, IntegrationPlugin)):
                    plugin = attr()
                    await plugin.initialize({})
                    self.registry.register(plugin)

        except Exception as e:
            logger.error(f"Failed to load plugin {path}: {e}")

    async def _load_plugin_package(self, path: Path):
        """Load a plugin from a package directory."""
        init_file = path / "__init__.py"
        await self._load_plugin_file(init_file)

    async def load_plugin(self, name: str,
                          plugin_class: Type[HydraPlugin],
                          config: Optional[Dict] = None):
        """Manually load and register a plugin."""
        plugin = plugin_class()
        await plugin.initialize(config or {})
        self.registry.register(plugin)

    async def unload_plugin(self, name: str):
        """Unload a plugin."""
        plugin = self.registry.get(name)
        if plugin:
            await plugin.shutdown()
            self.registry.unregister(name)
            logger.info(f"🔌 Plugin unloaded: {name}")

    async def reload_plugin(self, name: str):
        """Hot-reload a plugin."""
        await self.unload_plugin(name)
        await self.discover_and_load()
