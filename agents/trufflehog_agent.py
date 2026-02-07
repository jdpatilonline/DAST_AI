import subprocess
import os

REPORT_DIR = "reports/trufflehog"
REPORT_FILE = f"{REPORT_DIR}/trufflehog.json"


# -------------------------------------------------
# Enterprise Preview Engine
# -------------------------------------------------
def preview_report():

    print("\n===== TRUFFLEHOG REPORT PREVIEW =====")

    if not os.path.exists(REPORT_FILE):
        print("❌ Report file not found:", REPORT_FILE)
        return

    try:
        subprocess.run("cat reports/trufflehog/trufflehog.json ", shell=True)

    except Exception as e:
        print("❌ Preview error:", e)

    print("===== END REPORT PREVIEW =====\n")


# -------------------------------------------------
# Enterprise Trufflehog Scan
# -------------------------------------------------
def run():

    workspace = os.getcwd()

    os.makedirs(REPORT_DIR, exist_ok=True)

    print("\n===== TRUFFLEHOG ENTERPRISE SCAN =====")
    print("Workspace:", workspace)

    try:
        with open(REPORT_FILE, "w") as outfile:

            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{workspace}:/repo",
                    "gesellix/trufflehog",
                    "--json", "/repo"
                ],
                stdout=outfile,
                stderr=subprocess.PIPE,
                text=True
            )

        if result.returncode != 0:
            print("⚠ Trufflehog exited with non-zero code:", result.returncode)
            print("Stderr:", result.stderr)
        else:
            print("✅ Trufflehog scan completed successfully")

    except Exception as e:
        print("❌ Error running Trufflehog:", e)

    preview_report()

    print("===== TRUFFLEHOG SCAN COMPLETED =====\n")


# -------------------------------------------------
# Only Run If Executed Directly
# -------------------------------------------------
if __name__ == "__main__":
    run()
