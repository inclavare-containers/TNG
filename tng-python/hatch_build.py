"""Hatch build hook: convert relative README links to absolute GitHub URLs for PyPI.

Copies README files to the build output directory and converts relative links
to absolute GitHub URLs in the copies. The originals in the source tree are
never modified, so local ``hatch build`` is safe for developers.
"""

import re
import shutil
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

REPO = "https://github.com/inclavare-containers/TNG"
BRANCH = "master"
BASE = "tng-python"


class ReadmeLinksHook(BuildHookInterface):
    """Convert relative README links to absolute GitHub URLs during build."""

    def initialize(self, version, build_data):
        for readme_name in ("README.md", "README_zh.md"):
            src = Path(__file__).parent / readme_name
            dst = Path(__file__).parent / "build" / readme_name
            if not src.is_file():
                continue
            dst.parent.mkdir(exist_ok=True)
            shutil.copy2(src, dst)
            content = dst.read_text()
            # Replace relative doc links with absolute GitHub blob URLs
            content = re.sub(
                r"]\(docs/([^)#)]+)\)",
                f"]({REPO}/blob/{BRANCH}/{BASE}/docs/\\1)",
                content,
            )
            content = re.sub(
                r"]\(README_([^)#)]+)\)",
                f"]({REPO}/blob/{BRANCH}/{BASE}/README_\\1)",
                content,
            )
            dst.write_text(content)

        # Point hatch at the converted README for wheel metadata
        converted = Path(__file__).parent / "build" / "README.md"
        if converted.is_file():
            build_data.readme = {
                "content-type": "text/markdown",
                "path": str(converted),
            }
