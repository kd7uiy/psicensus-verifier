"""Compatibility name: this module now lives in the package as precog_verifier.tokenjoin.

`import tokenjoin` (with tools/ on sys.path) gives the very same module object, so existing callers and
tests that patch its attributes keep working."""
import sys
from pathlib import Path

try:
    import precog_verifier  # noqa: F401
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from precog_verifier import tokenjoin as _module

sys.modules[__name__] = _module
