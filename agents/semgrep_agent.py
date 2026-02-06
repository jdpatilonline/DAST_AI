import subprocess
import os

REPORT_DIR = "reports/semgrep"
os.makedirs(REPORT_DIR, exist_ok=True)


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

    # Validate that Docker mount worked
    print("\nValidating Docker mount for Semgrep...")
    try:
        mount_test = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{workspace}:/src", "alpine", "ls", "/src"],
            capture_output=True,
            text=True
        )
        print("Files inside container /src:")
        print(mount_test.stdout)
    except Exception as e:
        print("❌ Docker mount validation failed:", e)

    print("===== SEMGREP SCAN COMPLETED =====\n")
