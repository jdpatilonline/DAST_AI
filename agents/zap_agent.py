import os
import time
import json
import subprocess
import requests
from zapv2 import ZAPv2

TARGET = os.getenv("TARGET_URL")
MODEL = os.getenv("OLLAMA_MODEL", "mistral")
DEBUG = os.getenv("ENTERPRISE_DEBUG", "false").lower() == "true"

REPORT_DIR = "reports/zap"
os.makedirs(REPORT_DIR, exist_ok=True)

ZAP_CONTAINER = "enterprise-zap"
ZAP_PROXY = "http://127.0.0.1:8080"

zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})


# -------------------------------------------------
# Debug Logger
# -------------------------------------------------
def debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")


# -------------------------------------------------
# Start ZAP Container
# -------------------------------------------------
def start_zap_container():

    print("\nStarting ZAP container...")

    # Check if container already running
    result = subprocess.run(
        ["docker", "ps", "--filter", f"name={ZAP_CONTAINER}", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )

    if ZAP_CONTAINER in result.stdout:
        print("✅ ZAP container already running")
        return

    try:
        subprocess.run([
            "docker", "run", "-d",
            "--name", ZAP_CONTAINER,
            "-p", "8080:8080",
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap.sh",
            "-daemon",
            "-port", "8080",
            "-host", "0.0.0.0",
            "-config", "api.disablekey=true",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true"
        ], check=True)

        print("✅ ZAP container started")

    except Exception as e:
        print("❌ Failed to start ZAP container:", e)


# -------------------------------------------------
# Wait For ZAP Ready
# -------------------------------------------------
def wait_for_zap(timeout=300):

    print("\nWaiting for ZAP to become ready...")

    start = time.time()

    while time.time() - start < timeout:
        try:
            zap.core.version()
            print("✅ ZAP is ready")
            return True
        except Exception:
            print("ZAP still starting...")
            time.sleep(5)

    print("❌ ZAP failed to start")
    return False


# -------------------------------------------------
# Ollama AI Helper
# -------------------------------------------------
def ask_ai(prompt):

    try:
        r = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=120
        )

        return r.json().get("response", "No AI response")

    except Exception as e:
        print("❌ AI request failed:", e)
        return "AI request failed"


# -------------------------------------------------
# Run Scan
# -------------------------------------------------
def run():

    workspace = os.getcwd()

    print("\n===== ZAP ENTERPRISE SCAN =====")
    print("Workspace:", workspace)
    print("Target:", TARGET)

    if not TARGET:
        print("❌ TARGET_URL not set")
        return

    # Start ZAP Tool
    start_zap_container()

    if not wait_for_zap():
        return

    # ---------------- Spider--------
    try:
        print("\nRunning ZAP Spider...")

        zap.urlopen(TARGET)
        time.sleep(5)

        spider_id = zap.spider.scan(TARGET)

        while int(zap.spider.status(spider_id)) < 100:
            print(f"Spider progress: {zap.spider.status(spider_id)}%")
            time.sleep(3)

        print("✅ Spider completed")

    except Exception as e:
        print("❌ Spider failed:", e)
        return

    # ---------------- Active Scan
    try:
        print("\nRunning ZAP Active Scan...")

        scan_id = zap.ascan.scan(TARGET)

        while int(zap.ascan.status(scan_id)) < 100:
            print(f"Active scan progress: {zap.ascan.status(scan_id)}%")
            time.sleep(5)

        print("✅ Active scan completed")

    except Exception as e:
        print("❌ Active scan failed:", e)
        return

    # ---------------- Alerts + AI
    try:
        alerts = zap.core.alerts()
        enriched = []

        print(f"\nProcessing {len(alerts)} alerts with AI...")

        for alert in alerts:

            remediation = ask_ai(
                f"Explain vulnerability and remediation:\n{json.dumps(alert, indent=2)}"
            )

            enriched.append({
                **alert,
                "ai_remediation": remediation
            })

        report_file = f"{REPORT_DIR}/zap_ai.json"

        with open(report_file, "w") as f:
            json.dump(enriched, f, indent=2)

        print(f"✅ Report saved: {report_file}")

    except Exception as e:
        print("❌ Alert processing failed:", e)

    print("===== ZAP SCAN COMPLETED =====\n")
    
# Only Run If Executed Directly
# -------------------------------------------------
if __name__ == "__main__":
    run()

