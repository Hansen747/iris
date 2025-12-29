#!/usr/bin/env python3
import csv
import argparse
from pathlib import Path

def read_project_slugs(csv_path, key):
    slugs = set()
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        if key not in reader.fieldnames:
            raise ValueError(f"CSV {csv_path} does not contain column '{key}'")
        for row in reader:
            val = row.get(key, "").strip()
            if val:
                slugs.add(val)
    return slugs

def main():
    parser = argparse.ArgumentParser(
        description="Find project_slug present in project_info.csv but missing in build_info.csv"
    )
    parser.add_argument("--project-info", default="/home/agent/iris/data/cwe-bench-java/data/project_info.csv",
                        help="Path to project_info.csv")
    parser.add_argument("--build-info", default="/home/agent/iris/data/cwe-bench-java/data/build_info.csv",
                        help="Path to build_info.csv")
    parser.add_argument("--output", default="missing_in_build_info.csv",
                        help="Output CSV file (default: missing_in_build_info.csv)")
    args = parser.parse_args()

    project_info_path = Path(args.project_info)
    build_info_path = Path(args.build_info)

    project_slugs = read_project_slugs(project_info_path, "project_slug")
    build_slugs = read_project_slugs(build_info_path, "project_slug")

    missing = sorted(project_slugs - build_slugs)

    print(f"Project info total: {len(project_slugs)}")
    print(f"Build info total:   {len(build_slugs)}")
    print(f"Missing in build_info: {len(missing)}")

    with open(args.output, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["project_slug"])
        for slug in missing:
            writer.writerow([slug])

    print(f"\nSaved missing project slugs to: {args.output}")

if __name__ == "__main__":
    main()
