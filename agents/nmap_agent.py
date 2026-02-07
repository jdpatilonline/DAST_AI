import subprocess
import os

HOST = os.getenv("HOST")

REPORT_DIR = "reports/nmap"
REPORT_FILE = f"{REPORT_DIR}/nmap.xml"

os.makedirs(REPORT_DIR, exist_ok=True)


# -------------------------------------------------
# Preview Report Using CAT (Enterprise Safe)
# -------------------------------------------------
def preview_report():

    print("\n===== NMAP REPORT PREVIEW=====")

    if not os.path.exists(REPORT_FILE):
        print("❌ Report file not found")
        return

    try:
      subprocess.run("cat reports/nmap/nmap.xml ", shell=True)

    except Exception as e:
        print("❌ Error previewing report:", e)

    print("===== END REPORT PREVIEW =====\n")


# -------------------------------------------------
# Main Scan
# -------------------------------------------------
def run():

    workspace = os.getcwd()

    print("\n===== NMAP ENTERPRISE SCAN =====")
    print("Workspace Path:", workspace)
    print("Target Host:", HOST)

    try:
        print("Workspace Files:", os.listdir(workspace))
    except Exception as e:
        print("Error listing workspace files:", e)

    if not HOST:
        print("❌ HOST environment variable not set, skipping Nmap scan")
        return

    print("\nRunning Nmap Docker scan...")

    nmap_cmd = [
        "docker", "run", "--rm",
        "-v", f"{workspace}/reports/nmap:/data",
        "uzyexe/nmap",
        "-Pn", "-p", "80,443",
        "-sV", "-A",
        "-oX", "/data/nmap.xml",
        HOST
    ]

    try:
        result = subprocess.run(
            nmap_cmd,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print("⚠ Nmap exited with non-zero code:", result.returncode)
            print("Stdout:", result.stdout)
            print("Stderr:", result.stderr)
            return
        else:
            print("✅ Nmap scan completed successfully")

    except Exception as e:
        print("❌ Error running Nmap:", e)
        return

    # Small delay ensures Docker flushes file
    import time
    time.sleep(2)

    preview_report()

    print("===== NMAP SCAN COMPLETED =====\n")
    
# Only Run If Executed Directly
# -------------------------------------------------
if __name__ == "__main__":
    run()
