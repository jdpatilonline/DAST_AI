import subprocess
import os

REPORT_DIR = "reports/semgrep"
os.makedirs(REPORT_DIR, exist_ok=True)


def run():

    print("Running Semgrep...")

    subprocess.run([
        "docker", "run", "--rm",
        "-u", "0",
        "-v", f"{os.getcwd()}:/src",
        "semgrep/semgrep",
        "semgrep", "scan",
        "--json",
        "--output", "/src/reports/semgrep/semgrep.json"
    ])
