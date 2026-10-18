"""HoneyLens plugin ABI — public types.

Plugins should depend on this package and import the Plugin and
HoneyLensCore Protocols from here.
"""

from honeylens_plugin_api.types import (
    CURRENT_API_VERSION,
    HoneyLensCore,
    Plugin,
)

__all__ = ["CURRENT_API_VERSION", "HoneyLensCore", "Plugin"]
__version__ = CURRENT_API_VERSION
