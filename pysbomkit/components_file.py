"""
Read a hand-kept components file (for example a product's ``components.yaml``) and turn it into
CycloneDX components.

The file records what a manifest scan cannot see: a bootloader in protected flash, modem firmware
delivered as a binary, a metrology processor, the toolchain. Sections are ``metadata``,
``product``, and any other top-level list of components. A section may also be a mapping of lists
(``application_firmware`` has ``first_party`` and ``third_party``). An empty value or "unknown" is
left out of the SBOM and reported as a gap. Nothing is guessed.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

UNKNOWN = {"", "unknown", "tbc", "tbd", "n/a", "none"}

# Types used in components files, mapped to CycloneDX 1.4 component types
TYPES = {
    "device": "device", "firmware": "firmware", "operating-system": "operating-system", "library": "library",
    "framework": "framework", "application": "application", "toolchain": "application", "platform": "library",
    "container": "container", "data": "data", "file": "file", "device-driver": "library",
}
SPDX_KNOWN = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "Zlib", "Unlicense", "GPL-2.0-only",
    "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only",
    "LGPL-3.0-or-later", "CC0-1.0", "BSL-1.0", "EPL-2.0", "0BSD",
}


class ComponentsFileError(ValueError):
    pass


def known(value: Any) -> Optional[str]:
    """A scalar as text, or None when it is empty or a placeholder such as "unknown"."""
    if value is None:
        return None
    text = " ".join(str(value).split())
    return None if text.lower() in UNKNOWN else text


@dataclass
class Declared:
    section: str
    name: str
    version: Optional[str]
    type: str
    supplier: Optional[str] = None
    supplier_url: Optional[str] = None
    contact: Optional[str] = None
    license: Optional[str] = None
    spdx: Optional[str] = None
    license_notes: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    copyright: Optional[str] = None
    cve_checked: Optional[str] = None
    compliance_actions: List[str] = field(default_factory=list)

    def gaps(self) -> List[str]:
        out = []
        if self.version is None:
            out.append("version")
        if self.license is None and self.spdx is None:
            out.append("licence")
        if self.cve_checked is None:
            out.append("CVE check")
        return out


@dataclass
class ComponentsFile:
    path: Path
    metadata: Dict[str, Any]
    product: Optional[Declared]
    components: List[Declared]

    def gaps(self) -> Dict[str, List[str]]:
        found = {c.name: c.gaps() for c in self.components}
        if self.product and self.product.version is None:
            found[self.product.name] = ["version"]
        return {k: v for k, v in found.items() if v}


def _declared(section: str, raw: Dict[str, Any]) -> Declared:
    name = known(raw.get("name"))
    if not name:
        raise ComponentsFileError(f"a component in '{section}' has no name")
    kind = str(raw.get("type") or "library").strip().lower()
    if kind not in TYPES:
        raise ComponentsFileError(f"component '{name}' has type '{kind}', expected one of {sorted(TYPES)}")
    actions = raw.get("compliance_actions") or []
    if isinstance(actions, str):
        actions = [actions]
    return Declared(
        section=section, name=name, version=known(raw.get("version")), type=TYPES[kind],
        supplier=known(raw.get("supplier")), supplier_url=known(raw.get("supplier_url")),
        contact=known(raw.get("supplier_contact")), license=known(raw.get("license")),
        spdx=known(raw.get("spdx_expression")), license_notes=known(raw.get("license_notes")),
        purl=known(raw.get("purl")), cpe=known(raw.get("cpe")), location=known(raw.get("location")),
        description=known(raw.get("description")), notes=known(raw.get("notes")), copyright=known(raw.get("copyright")),
        cve_checked=known(raw.get("cve_checked")), compliance_actions=[a for a in map(known, actions) if a])


def _entries(section: str, value: Any) -> List[Declared]:
    if isinstance(value, list):
        return [_declared(section, v) for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        if "name" in value:
            return [_declared(section, value)]
        out: List[Declared] = []
        for sub, items in value.items():
            out += _entries(f"{section}.{sub}", items)
        return out
    return []


def load_components_file(path: Path) -> ComponentsFile:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ComponentsFileError(f"cannot read components file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ComponentsFileError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ComponentsFileError(f"{path} must be a YAML mapping of sections")
    product = _declared("product", raw["product"]) if isinstance(raw.get("product"), dict) else None
    components: List[Declared] = []
    for section, value in raw.items():
        if section not in ("metadata", "product"):
            components += _entries(section, value)
    return ComponentsFile(path, raw.get("metadata") or {}, product, components)


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-").lower() or "component"


def refs_for(components: List[Declared]) -> List[str]:
    seen: Dict[str, int] = {}
    out = []
    for c in components:
        base = f"declared-{_slug(c.name)}"
        seen[base] = seen.get(base, 0) + 1
        out.append(base if seen[base] == 1 else f"{base}-{seen[base]}")
    return out


def _licenses(d: Declared) -> List[Dict[str, Any]]:
    if d.spdx:
        return [{"expression": d.spdx}]
    if not d.license:
        return []
    entry: Dict[str, Any] = {"license": {"id": d.license} if d.license in SPDX_KNOWN else {"name": d.license}}
    if d.license_notes:
        entry["license"]["text"] = {"contentType": "text/plain", "content": d.license_notes}
    return [entry]


def to_component(d: Declared, ref: str, version: Optional[str] = None) -> Dict[str, Any]:
    """One declared component as a CycloneDX component. Only what the file states is written."""
    out: Dict[str, Any] = {"type": d.type, "bom-ref": ref, "name": d.name}
    if d.version or version:
        out["version"] = d.version or version
    supplier: Dict[str, Any] = {}
    if d.supplier:
        supplier["name"] = d.supplier
    if d.supplier_url:
        supplier["url"] = [d.supplier_url]
    if d.contact and "@" in d.contact:
        supplier["contact"] = [{"email": d.contact}]
    if supplier:
        out["supplier"] = supplier
    for key, value in (("description", d.description), ("copyright", d.copyright), ("purl", d.purl), ("cpe", d.cpe)):
        if value:
            out[key] = value
    licenses = _licenses(d)
    if licenses:
        out["licenses"] = licenses
    props = [{"name": "sbomkit:evidence", "value": "components file"}, {"name": "sbomkit:section", "value": d.section}]
    for name, value in (("location", d.location), ("notes", d.notes), ("cve-checked", d.cve_checked)):
        if value:
            props.append({"name": f"sbomkit:{name}", "value": value})
    props += [{"name": "sbomkit:compliance-action", "value": a} for a in d.compliance_actions]
    gaps = d.gaps()
    if gaps:
        props.append({"name": "sbomkit:gaps", "value": ", ".join(gaps)})
    out["properties"] = props
    return out


def apply_to_bom(bom: Dict[str, Any], cf: ComponentsFile, product_version: Optional[str] = None) -> Dict[str, Any]:
    """Add the file's components to a CycloneDX document. A ``product`` section becomes metadata.component."""
    refs = refs_for(cf.components)
    bom.setdefault("components", []).extend(to_component(c, r) for c, r in zip(cf.components, refs))
    meta = bom.setdefault("metadata", {})
    supplier = {}
    if known(cf.metadata.get("supplier")):
        supplier["name"] = known(cf.metadata["supplier"])
    if known(cf.metadata.get("supplier_url")):
        supplier["url"] = [known(cf.metadata["supplier_url"])]
    if supplier:
        meta["supplier"] = supplier
    if known(cf.metadata.get("sbom_author")):
        meta["authors"] = [{"name": known(cf.metadata["sbom_author"])}]
    props = meta.setdefault("properties", [])
    props.append({"name": "sbomkit:components-file", "value": cf.path.name})
    if known(cf.metadata.get("last_reviewed")):
        props.append({"name": "sbomkit:last-reviewed", "value": known(cf.metadata["last_reviewed"])})
    gaps = cf.gaps()
    if gaps:
        props.append({"name": "sbomkit:components-file-gaps",
                      "value": "; ".join(f"{n}: {', '.join(items)}" for n, items in gaps.items())})
    depends = list(refs)
    if cf.product is not None:
        product = to_component(cf.product, "product", product_version)
        if product["type"] == "library":
            product["type"] = "device"
        meta["component"] = product
        bom.setdefault("dependencies", []).append({"ref": "product", "dependsOn": sorted(depends)})
    return bom
