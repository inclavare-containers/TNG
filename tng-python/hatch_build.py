"""Hatch build hook: pin the wheel platform tag.

The wheel bundles a pre-built, platform-specific `tng` binary, so it cannot
use hatchling's default pure-python tag `py3-none-any`. With the default tag,
every platform's wheel would share a single filename
(`tng_sdk-<ver>-py3-none-any.whl`) and overwrite each other when the release
job collects them into one dist/ — leaving PyPI with only one wheel instead of
five.

Tag selection:
  * CI cross-compile builds set TNG_WHEEL_TAG explicitly per matrix target
    (e.g. `py3-none-manylinux_2_17_x86_64`), because the binary's target
    platform differs from the runner's host platform.
  * Local builds (e.g. `make python-wheel`, which builds for the host) leave
    TNG_WHEEL_TAG unset, so we infer a host platform tag from
    `packaging.tags.sys_tags()`. This yields an honest tag for the host
    (manylinux_<glibc>_<arch> / macosx_<ver>_<arch> / win_<arch>) and still
    differs from py3-none-any so local wheels no longer masquerade as
    platform-agnostic.

build_data["tag"] drives both the wheel filename and the `Tag` line in the
WHEEL file.
"""

import os

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def _infer_host_platform_tag() -> str:
    """Return a `py3-none-<platform>` tag for the current host."""
    from packaging.tags import sys_tags

    for tag in sys_tags():
        if tag.platform and tag.platform != "any":
            return f"py3-none-{tag.platform}"
    return "py3-none-any"


class WheelTagHook(BuildHookInterface):
    """Pin the wheel tag from TNG_WHEEL_TAG, else infer it for the host."""

    PLUGIN_NAME = "wheel-tag"

    def initialize(self, version, build_data):
        tag = os.environ.get("TNG_WHEEL_TAG") or _infer_host_platform_tag()
        build_data["tag"] = tag
        build_data["infer_tag"] = False
