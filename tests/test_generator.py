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
