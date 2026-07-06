"""Hatch build hook: convert relative README links to absolute GitHub URLs for PyPI."""

import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class ReadmeLinksHook(BuildHookInterface):
    """Run the link-fix script before building the wheel."""

    def initialize(self, version, build_data):
        script = Path(__file__).parent.parent / "scripts" / "fix-pypi-readme-links.sh"
        if script.is_file():
            subprocess.run(["bash", str(script)], check=True)
