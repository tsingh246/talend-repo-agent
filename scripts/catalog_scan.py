import argparse
import csv
import sys
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from catalog_scanner import run_catalog_scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan Talend jobs for data catalog field evidence.")
    parser.add_argument("--input", default="data/repos", help="Talend repo root to catalog.")
    parser.add_argument("--output", default="exports/talend_data_catalog.csv", help="CSV output path.")
    args = parser.parse_args()

    result = run_catalog_scan(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = [asdict(finding) for finding in result.findings]
    fieldnames = list(rows[0].keys()) if rows else []
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        if fieldnames:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    print(f"Input type: {result.input_type}")
    print(f"Findings: {len(result.findings)}")
    print(f"CSV written: {output_path}")


if __name__ == "__main__":
    main()
