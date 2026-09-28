# `py-sbomkit` — Universal Software Bill of Materials (SBOM) Generator Toolkit

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)

A generic, Python-based CLI and developer toolkit for scanning multi-language repositories (`requirements.txt`, `package.json`) and exporting standardized **CycloneDX JSON** and **Markdown** Software Bill of Materials (SBOM) reports.

---

## 🚀 Features

- **Multi-Ecosystem Discovery**: Auto-detects dependencies across Python (`requirements.txt`) and Node.js (`package.json`).
- **CycloneDX Standard Export**: Outputs valid CycloneDX 1.4 JSON specs for enterprise security auditing.
- **Markdown Matrix Export**: Generates clean Markdown tables for documentation pages.
- **Py-LogKit Integration**: Color-coded log reporting.

---

## 🛠️ Installation

```bash
pip install -e .
```

---

## 💻 CLI Usage

```bash
# Export CycloneDX JSON SBOM to stdout
py-sbomkit .

# Export Markdown SBOM table to file
py-sbomkit . -f markdown -o SBOM.md
```
