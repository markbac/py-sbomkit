import argparse
import json
import sys
from pathlib import Path
from .generator import SBOMGenerator

def main():
    parser = argparse.ArgumentParser(
        prog="py-sbomkit",
        description="Universal Software Bill of Materials (SBOM) Generator Toolkit"
    )
    parser.add_argument("target", type=str, nargs="?", default=".", help="Target project root directory")
    parser.add_argument("-f", "--format", choices=["cyclonedx-json", "markdown"], default="cyclonedx-json", help="Output format")
    parser.add_argument("-o", "--output", type=str, help="Output file path (prints to stdout if omitted)")

    args = parser.parse_args()

    generator = SBOMGenerator()
    target_path = Path(args.target).resolve()
    components = generator.scan_directory(target_path)

    if args.format == "cyclonedx-json":
        bom_data = generator.export_cyclonedx_json(components)
        output_str = json.dumps(bom_data, indent=2)
    else:
        output_str = generator.export_markdown(components)

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_str, encoding="utf-8")
        print(f"SBOM written to {out_path} ({len(components)} components)")
    else:
        print(output_str)

if __name__ == "__main__":
    main()
