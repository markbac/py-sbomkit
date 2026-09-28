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
