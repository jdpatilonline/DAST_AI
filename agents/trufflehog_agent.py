import subprocess
import os

REPORT_DIR = "reports/trufflehog"
REPORT_FILE = f"{REPORT_DIR}/trufflehog.json"

os.makedirs(REPORT_DIR, exist_ok=True)


def preview_report():

    print("\n===== TRUFFLEHOG REPORT PREVIEW (cat first 5 lines) =====")

    if not os.path.exists(REPORT_FILE):
        print("❌ Report file not found")
        return

    try:
        subprocess.run(
            f"cat {REPORT_FILE} | head -n 20"
        )
    except Exception as e:
        print("❌ Error previewing report:", e)

    print("===== END REPORT PREVIEW =====\n")


def run():

    workspace = os.getcwd()

    print("\n===== TRUFFLEHOG ENTERPRISE SCAN =====")
    print("Running Trufflehog...")

    try:
        with open(REPORT_FILE, "w") as outfile:
            result = subprocess.run([
                "docker", "run", "--rm",
                "-v", f"{workspace}:/repo",
                "gesellix/trufflehog",
                "--json", "/repo"
            ], stdout=outfile, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            print("⚠ Trufflehog exited with non-zero code:", result.returncode)
            print("Stderr:", result.stderr)
        else:
            print("✅ Trufflehog scan completed successfully")

    except Exception as e:
        print("❌ Error running Trufflehog:", e)

    # ✅ Preview using cat
    preview_report()

    print("===== TRUFFLEHOG SCAN COMPLETED =====\n")
