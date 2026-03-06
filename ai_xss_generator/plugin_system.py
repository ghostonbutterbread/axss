from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any


class PluginRegistry:
    def __init__(self) -> None:
        self.parsers: list[Any] = []
        self.mutators: list[Any] = []

    def load_from(self, root: Path) -> None:
        for plugin_dir_name, bucket in (
            ("plugins/parsers", self.parsers),
            ("plugins/mutators", self.mutators),
        ):
            plugin_dir = root / plugin_dir_name
            if not plugin_dir.exists():
                continue
            for path in sorted(plugin_dir.glob("*.py")):
                if path.name.startswith("_"):
                    continue
                plugin = self._load_module(path)
                if hasattr(plugin, "PLUGIN"):
                    bucket.append(plugin.PLUGIN)

    def _load_module(self, path: Path) -> Any:
        module_name = f"ai_xss_generator_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Could not load plugin: {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
