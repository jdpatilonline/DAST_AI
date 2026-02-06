import subprocess
import os

REPORT_DIR = "reports/trufflehog"
os.makedirs(REPORT_DIR, exist_ok=True)


def run():

    workspace = os.getcwd()

    # ✅ Debug prints
    print("\n===== WORKSPACE DEBUG =====")
    print("Workspace Path:", workspace)

    try:
        print("Workspace Files:", os.listdir(workspace))
    except Exception as e:
        print("Error listing files:", e)

    print("===========================\n")

    print("Running Trufflehog...")

    with open(f"{REPORT_DIR}/trufflehog.json", "w") as outfile:
        subprocess.run([
            "docker", "run", "--rm",
            "-v", f"{workspace}:/repo",
            "gesellix/trufflehog",
            "--json", "/repo"
        ], stdout=outfile)
