#!/usr/bin/env python3
import os
import csv

PROJECT_INFO_CSV = "/home/agent/iris/data/cwe-bench-java/data/project_info.csv"
CODEQL_DB_ROOT = "/data/codeql_db"


def collect_project_slugs(csv_path):
    """从 project_info.csv 中读取所有 project_slug"""
    project_slugs = set()
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            slug = row.get("project_slug")
            if slug:
                project_slugs.add(slug.strip())
    return project_slugs


def collect_codeql_dirnames(root_dir):
    """递归收集 codeql_db 下所有目录名（只要目录）"""
    dirnames = set()
    for root, dirs, _ in os.walk(root_dir):
        for d in dirs:
            dirnames.add(d)
    return dirnames


def main():
    print("[*] Loading project_slug from CSV...")
    project_slugs = collect_project_slugs(PROJECT_INFO_CSV)
    print(f"    Total project_slug in CSV: {len(project_slugs)}")

    print("[*] Scanning codeql_db directories...")
    codeql_dirs = collect_codeql_dirnames(CODEQL_DB_ROOT)
    print(f"    Total directory names in codeql_db: {len(codeql_dirs)}")

    print("[*] Matching valid projects (directory name match)...")
    valid_projects = project_slugs & codeql_dirs

    print("\n========== RESULT ==========")
    print(f"Valid project count: {len(valid_projects)}")
    print("============================")

    # 如需查看具体项目名，取消注释
    # for p in sorted(valid_projects):
    #     print(p)


if __name__ == "__main__":
    main()
