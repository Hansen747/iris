#!/usr/bin/env python3

import argparse
import subprocess
import os
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(
        description="Run CWE-Bench Java setup for one project and save build log"
    )
    parser.add_argument(
        "project",
        help="Project slug, e.g. spring-projects__spring-framework_CVE-2022-22965_5.2.19.RELEASE"
    )
    args = parser.parse_args()

    project = args.project
    log_file = Path(f"./logs_setup/{project}_build_log.txt")

    setup_script = os.path.expanduser(
        "~/iris/data/cwe-bench-java/scripts/setup.py"
    )

    cmd = [
        "python3",
        setup_script,
        "--filter",
        project
    ]

    print(f"[INFO] Running setup for project: {project}")
    print(f"[INFO] Log file: {log_file.resolve()}")
    print(f"[CMD ] {' '.join(cmd)} > {log_file} 2>&1")

    with log_file.open("w") as f:
        subprocess.run(
            cmd,
            stdout=f,
            stderr=subprocess.STDOUT,
            check=False
        )

    print("[DONE] Setup finished (check log for details).")

if __name__ == "__main__":
    main()
