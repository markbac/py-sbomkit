# `py-sbomkit` — Universal Software Bill of Materials (SBOM) Generator Toolkit

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![SBOM](https://img.shields.io/badge/CycloneDX-1.4-blue.svg)

`py-sbomkit` is a generic, Python-based CLI developer toolkit for scanning multi-ecosystem code repositories (`requirements.txt`, `package.json`, `pyproject.toml`) and generating standardized **CycloneDX 1.4 JSON** and **Markdown** Software Bill of Materials (SBOM) manifests.

---

## 🎯 What It Does

Software supply chain security requires maintaining accurate Software Bill of Materials (SBOM) manifests. `py-sbomkit` provides:

1. **Multi-Ecosystem Discovery**: Automatically parses Python (`requirements.txt`, `pyproject.toml`) and Node.js (`package.json`) dependency manifests.
2. **CycloneDX Standard Export**: Generates compliant CycloneDX 1.4 JSON specifications (`pkg:pypi/`, `pkg:npm/`) for security auditing tools (e.g. Dependency-Track, Grype, Trivy).
3. **Markdown Matrix Export**: Generates human-readable Markdown tables for technical documentation pages.
4. **Py-LogKit Logging**: Color-coded terminal progress logging (`pylogkit`).

---

## 🏗️ Tool Architecture

The package contains dedicated manifest parsers and format exporters:

```
py-sbomkit/
├── pysbomkit/
│   ├── __init__.py         # Package exports
│   ├── generator.py        # Core SBOMGenerator & Component model
│   ├── components_file.py  # Hand-kept components.yaml reader
│   ├── cli.py              # CLI Argument Parser & Exporter
│   └── pylogkit/           # Py-LogKit logging framework
├── tests/
│   └── test_generator.py   # Unit test suite
├── setup.py                # Package metadata & entry points
└── README.md               # Comprehensive documentation
```

### Data Pipeline

```
[Project Root Directory]
           │
           ├──► [requirements.txt] ──► [PyPI Parser] ────┐
           │                                             │
           └──► [package.json]      ──► [npm Parser]  ────┼──► [Component Store]
                                                         │
                                                         ▼
                                                [SBOMGenerator]
                                                         │
                                   ┌─────────────────────┴─────────────────────┐
                                   ▼                                           ▼
                       [CycloneDX JSON Exporter]                   [Markdown Table Exporter]
                                   │                                           │
                                   ▼                                           ▼
                         (sbom.json / stdout)                        (SBOM.md / stdout)
```

---

## 💻 Installation

```bash
# Clone repository
git clone https://github.com/markbac/py-sbomkit.git
cd py-sbomkit

# Install in editable mode
pip install -e .
```

---

## 🛠️ How To Use

### 1. Command-Line Interface (CLI)

```bash
# Generate CycloneDX JSON SBOM to stdout for current directory
py-sbomkit .

# Export CycloneDX JSON SBOM to file
py-sbomkit . -f cyclonedx-json -o sbom.json

# Export Markdown table SBOM to documentation file
py-sbomkit docs/project -f markdown -o SBOM.md
```

#### CLI Options Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `target` | | `.` | Target project root directory containing manifests |
| `--format` | `-f` | `cyclonedx-json` | Output format (`cyclonedx-json`, `markdown`) |
| `--output` | `-o` | `stdout` | Output file path (prints to terminal stdout if omitted) |
| `--components` | `-c` | none | Hand-kept `components.yaml` to include (see below) |
| `--product-version` | | none | Version for the product when the components file leaves it unknown |

#### Components file

A manifest scan cannot see a bootloader in protected flash, modem firmware delivered as a binary, a second
processor, or the toolchain. List them in a YAML file and pass it with `--components`:

```yaml
metadata:
  supplier: "Example Ltd"
product:
  name: "Example Meter"
  type: device
application_firmware:
  third_party:
    - { name: "Gecko SDK", version: "4.4.1", type: framework, license: "Zlib", spdx_expression: "Zlib" }
modem_firmware:
  - { name: "Modem firmware", version: "unknown", type: firmware, supplier: "Quectel", license: "Proprietary" }
```

Any top-level list of components is read, and a section may itself hold lists (`first_party`, `third_party`). A
`product` section becomes the described component. An empty value or `unknown` is left out of the SBOM and listed
in the `sbomkit:gaps` property of that component and in `sbomkit:components-file-gaps`, so missing versions,
licences and CVE checks are visible rather than guessed. Supported keys per component: `name`, `version`, `type`,
`supplier`, `supplier_url`, `supplier_contact`, `license`, `spdx_expression`, `license_notes`, `purl`, `cpe`,
`location`, `description`, `notes`, `copyright`, `cve_checked` and `compliance_actions`.

```bash
py-sbomkit . --components components.yaml --product-version 2.0.1 -o sbom.json
```

---

### 2. Python API

```python
from pathlib import Path
from pysbomkit import SBOMGenerator

# Initialize generator
generator = SBOMGenerator()

# Scan project directory for components
components = generator.scan_directory(Path("."))

# Generate CycloneDX JSON
cyclonedx_bom = generator.export_cyclonedx_json(components)
print(f"BOM Format: {cyclonedx_bom['bomFormat']}, Components: {len(cyclonedx_bom['components'])}")

# Generate Markdown table string
markdown_table = generator.export_markdown(components)
print(markdown_table)
```

---

## 🧪 Running Tests

```bash
python -m pytest
```

---

## 📄 License

Licensed under the [MIT License](LICENSE).
