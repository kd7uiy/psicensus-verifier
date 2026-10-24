"""The package version is stated twice; both must name specification version 1."""
import pathlib
import tomllib

import precog_verifier

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_package_and_module_versions_agree():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == precog_verifier.__version__


def test_version_is_1_for_specification_version_1():
    assert precog_verifier.__version__.split(".")[0] == "1"
