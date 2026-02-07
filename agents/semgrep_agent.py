import subprocess
import os

REPORT_DIR = "reports/semgrep"
REPORT_FILE = f"{REPORT_DIR}/semgrep.json"

os.makedirs(REPORT_DIR, exist_ok=True)


def preview_report():

    print("\n===== SEMGREP REPORT PREVIEW (cat first 5 lines) =====")

    if not os.path.exists(REPORT_FILE):
        print("❌ Report file not found")
        return

    try:
        subprocess.run(
            f"cat {REPORT_FILE}"
        )
    except Exception as e:
        print("❌ Error previewing report:", e)

    print("===== END REPORT PREVIEW =====\n")


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

    # ✅ Preview using cat
    preview_report()

    print("===== SEMGREP SCAN COMPLETED =====\n")
    
# Only Run If Executed Directly
# -------------------------------------------------
if __name__ == "__main__":
    run()
