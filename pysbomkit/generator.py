import os
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from .pylogkit import setup_logging

logger = setup_logging(name="SBOMKit", to_console=True, to_file=False)

class Component:
    def __init__(self, name: str, version: str, ecosystem: str, license_name: str = "UNKNOWN"):
        self.name = name
        self.version = version
        self.ecosystem = ecosystem
        self.license_name = license_name

    def to_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "license": self.license_name
        }

    def __repr__(self):
        return f"<Component {self.name}@{self.version} ({self.ecosystem})>"

class SBOMGenerator:
    """
    Software Bill of Materials (SBOM) Generator for Python, Node, Go, and C/C++ projects.
    """

    def scan_directory(self, root_dir: Path) -> List[Component]:
        root_dir = Path(root_dir).resolve()
        components: List[Component] = []

        if not root_dir.exists():
            logger.error(f"Directory not found: {root_dir}")
            return components

        # 1. Python requirements.txt
        req_file = root_dir / "requirements.txt"
        if req_file.exists():
            components.extend(self._parse_requirements(req_file))

        # 2. Node package.json
        pkg_file = root_dir / "package.json"
        if pkg_file.exists():
            components.extend(self._parse_package_json(pkg_file))

        logger.info(f"Scanned {root_dir.name}: {len(components)} component(s) discovered.")
        return components

    def _parse_requirements(self, req_path: Path) -> List[Component]:
        components = []
        try:
            for line in req_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|~=|>|<)?\s*([0-9a-zA-Z\.\-]+)?", line)
                if match:
                    name = match.group(1)
                    ver = match.group(2) or "latest"
                    components.append(Component(name=name, version=ver, ecosystem="PyPI"))
        except Exception as e:
            logger.error(f"Error parsing {req_path}: {e}")
        return components

    def _parse_package_json(self, pkg_path: Path) -> List[Component]:
        components = []
        try:
            data = json.loads(pkg_path.read_text(encoding="utf-8"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name, ver in deps.items():
                ver_clean = ver.replace("^", "").replace("~", "")
                components.append(Component(name=name, version=ver_clean, ecosystem="npm"))
        except Exception as e:
            logger.error(f"Error parsing {pkg_path}: {e}")
        return components

    def export_cyclonedx_json(self, components: List[Component]) -> Dict[str, Any]:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": c.name,
                    "version": c.version,
                    "purl": f"pkg:{c.ecosystem.lower()}/{c.name}@{c.version}",
                    "licenses": [{"license": {"name": c.license_name}}]
                }
                for c in components
            ]
        }

    def export_markdown(self, components: List[Component]) -> str:
        lines = [
            "# Software Bill of Materials (SBOM)",
            "",
            "| Component Name | Version | Ecosystem | License |",
            "|---|---|---|---|"
        ]
        for c in sorted(components, key=lambda x: x.name.lower()):
            lines.append(f"| `{c.name}` | `{c.version}` | {c.ecosystem} | {c.license_name} |")
        lines.append("")
        return "\n".join(lines)
