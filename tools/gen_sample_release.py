"""Write the deterministic synthetic sample release to tests/data/sample_release/.

Usage: python tools/gen_sample_release.py
The sample uses mock authorities and a mock beacon; it demonstrates the format and the CLI only.
"""
import shutil
from pathlib import Path

from precog_verifier.release import write_release
from precog_verifier.testing import build_sample_release

OUT = Path(__file__).resolve().parent.parent / "tests" / "data" / "sample_release"


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    write_release(build_sample_release(), OUT)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
