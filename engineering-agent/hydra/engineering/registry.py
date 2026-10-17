"""Session-local capability registry with explicit tool ownership."""

from dataclasses import dataclass
from copy import deepcopy
from typing import Awaitable, Callable


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    schema: dict
    handler: Callable[[str, dict], Awaitable[dict]]
    capability: str


class ToolRegistry:
    def __init__(self):
        self._tools = {}

    def register(self, name, schema, handler, *, capability):
        if not isinstance(name, str) or not name or name in self._tools:
            raise ValueError(f"Duplicate or empty tool registration: {name}")
        if not isinstance(schema, dict) or not callable(handler) or not capability:
            raise ValueError("A tool requires a schema, handler and owning capability")
        self._tools[name] = ToolDefinition(name, deepcopy(schema), handler, capability)

    @property
    def schemas(self):
        return {name: deepcopy(tool.schema) for name, tool in self._tools.items()}

    async def execute(self, name, arguments):
        if not isinstance(arguments, dict):
            raise ValueError("arguments must be an object")
        if not isinstance(name, str) or name not in self._tools:
            raise ValueError(f"Unknown tool: {name}")
        tool = self._tools[name]
        return await tool.handler(name, arguments)
