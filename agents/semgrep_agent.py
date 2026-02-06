import subprocess
import os
import json

REPORT_DIR = "reports/semgrep"
REPORT_FILE = f"{REPORT_DIR}/semgrep.json"

os.makedirs(REPORT_DIR, exist_ok=True)


def print_semgrep_report():

    print("\n===== SEMGREP REPORT CONTENT =====")

    if not os.path.exists(REPORT_FILE):
        print("❌ Semgrep report not found")
        return

    try:
        with open(REPORT_FILE, "r") as f:
            data = json.load(f)

        results = data.get("results", [])

        if not results:
            print("✅ No Semgrep findings")
            return

        print(f"⚠ Total Findings: {len(results)}\n")

        for finding in results:
            print("Rule:", finding.get("check_id"))
            print("File:", finding.get("path"))
            print("Severity:", finding.get("extra", {}).get("severity"))
            print("Message:", finding.get("extra", {}).get("message"))
            print("-" * 50)

    except json.JSONDecodeError:
        print("❌ Invalid JSON format in Semgrep report")

    except Exception as e:
        print("❌ Error reading Semgrep report:", e)

    print("===== END SEMGREP REPORT =====\n")


def run():
    workspace = os.getcwd()

    print("\n===== SEMGREP ENTERPRISE SCAN =====")
    print("Workspace Path:", workspace)

    try:
        print("Workspace Files:", os.listdir(workspace))
    except Exception as e:
        print("Error listing workspace files:", e)

    print("\nRunning Semgrep Docker scan...")

    semgrep_cmd = [
        "docker", "run", "--rm",
        "-u", "0",
        "-v", f"{workspace}:/src",
        "semgrep/semgrep",
        "semgrep", "scan",
        "--json",
        "--output", "/src/reports/semgrep/semgrep.json"
    ]

    try:
        result = subprocess.run(
            semgrep_cmd,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print("⚠ Semgrep exited with non-zero code:", result.returncode)
            print("Stdout:", result.stdout)
            print("Stderr:", result.stderr)
        else:
            print("✅ Semgrep scan completed successfully")

    except Exception as e:
        print("❌ Error running Semgrep:", e)

    # Print Semgrep JSON Results
    print_semgrep_report()

    print("===== SEMGREP SCAN COMPLETED =====\n")
