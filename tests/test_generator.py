import pytest
from pathlib import Path
from pysbomkit import SBOMGenerator

def test_requirements_scan(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("fastapi==0.95.0\npyserial>=3.5\n")

    generator = SBOMGenerator()
    components = generator.scan_directory(tmp_path)
    assert len(components) == 2
    names = [c.name for c in components]
    assert "fastapi" in names
    assert "pyserial" in names

def test_cyclonedx_export(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("colorlog==6.7.0\n")

    generator = SBOMGenerator()
    components = generator.scan_directory(tmp_path)
    bom = generator.export_cyclonedx_json(components)
    assert bom["bomFormat"] == "CycloneDX"
    assert len(bom["components"]) == 1


# --- components file ---------------------------------------------------------------------------

import json
import subprocess
import sys

FIXTURE = Path(__file__).parent / "fixtures" / "components.yaml"


def test_components_file_adds_declared_parts_and_a_product(tmp_path):
    generator = SBOMGenerator()
    bom = generator.export_cyclonedx_json([], FIXTURE, product_version="2.0.1")
    product = bom["metadata"]["component"]
    assert product["name"] == "Acme Smart Meter" and product["type"] == "device"
    assert product["version"] == "2.0.1"
    by_name = {c["name"]: c for c in bom["components"]}
    modem = by_name["Example Cellular Modem Firmware"]
    assert modem["type"] == "firmware" and "version" not in modem          # "unknown" is not guessed
    assert {"name": "sbomkit:gaps", "value": "version, CVE check"} in modem["properties"]
    assert by_name["Vendor MCU SDK"]["licenses"] == [{"expression": "Zlib"}]
    assert by_name["Example Toolchain"]["type"] == "application"
    deps = next(d for d in bom["dependencies"] if d["ref"] == "product")["dependsOn"]
    assert len(deps) == len(bom["components"]) == 11


def test_components_file_merges_with_scanned_components(tmp_path):
    (tmp_path / "requirements.txt").write_text("colorlog==6.7.0\n")
    generator = SBOMGenerator()
    bom = generator.export_cyclonedx_json(generator.scan_directory(tmp_path), FIXTURE)
    assert "colorlog" in {c["name"] for c in bom["components"]} and len(bom["components"]) == 12


def test_markdown_lists_declared_components():
    text = SBOMGenerator().export_markdown([], FIXTURE)
    assert "## Declared components" in text and "`ExampleCrypto`" in text and "version, CVE check" in text


def test_bad_components_file_is_an_error(tmp_path):
    from pysbomkit.components_file import ComponentsFileError, load_components_file
    bad = tmp_path / "bad.yaml"
    bad.write_text("modem:\n  - name: X\n    type: spaceship\n")
    with pytest.raises(ComponentsFileError, match="spaceship"):
        load_components_file(bad)


def test_cli_components_flag(tmp_path):
    out = tmp_path / "sbom.json"
    result = subprocess.run([sys.executable, "-m", "pysbomkit.cli", str(tmp_path), "--components", str(FIXTURE),
                             "--product-version", "1.0", "-o", str(out)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(out.read_text())["metadata"]["component"]["version"] == "1.0"
    missing = subprocess.run([sys.executable, "-m", "pysbomkit.cli", str(tmp_path), "--components",
                              str(tmp_path / "nope.yaml")], capture_output=True, text=True)
    assert missing.returncode == 2 and "cannot read" in missing.stderr
