"""Hatch build hook: pin the wheel platform tag from TNG_WHEEL_TAG.

The wheel bundles a pre-built, platform-specific `tng` binary, so it cannot
use hatchling's default pure-python tag `py3-none-any`. With the default tag,
every platform's wheel would share a single filename (`tng_sdk-<ver>-py3-none-any.whl`)
and overwrite each other when the release job collects them into one dist/ —
leaving PyPI with only one wheel instead of five.

CI sets TNG_WHEEL_TAG per matrix target, e.g. `py3-none-manylinux_2_17_x86_64`.
This hook writes it into build_data["tag"], which hatchling uses for both the
wheel filename and the `Tag` line in the WHEEL file.

When TNG_WHEEL_TAG is unset (local `hatch build`), the hook is a no-op and
hatchling falls back to its default tag — convenient for development, since a
local wheel only needs to run on the host.
"""

import os

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class WheelTagHook(BuildHookInterface):
    """Pin the wheel tag from the TNG_WHEEL_TAG environment variable."""

    PLUGIN_NAME = "wheel-tag"

    def initialize(self, version, build_data):
        tag = os.environ.get("TNG_WHEEL_TAG")
        if tag:
            build_data["tag"] = tag
            build_data["infer_tag"] = False
