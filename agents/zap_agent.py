import os
import time
import json
import socket
import subprocess
import requests
from zapv2 import ZAPv2

# -------------------------------------------------
# CONFIG
# -------------------------------------------------
TARGET = os.getenv("TARGET_URL")
MODEL = os.getenv("OLLAMA_MODEL", "mistral")
DEBUG = os.getenv("ENTERPRISE_DEBUG", "false").lower() == "true"

ZAP_CONTAINER = "enterprise-zap"
ZAP_PORT = 8080
ZAP_PROXY = f"http://127.0.0.1:{ZAP_PORT}"
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

REPORT_DIR = "reports/zap"
AI_REPORT_DIR = "reports/ai"
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(AI_REPORT_DIR, exist_ok=True)

MAX_SCAN_TIME = 600  # seconds
SPIDER_MAX_CHILDREN = 50

# -------------------------------------------------
# DEBUG LOGGER
# -------------------------------------------------
def debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")

# -------------------------------------------------
# PORT CHECK
# -------------------------------------------------
def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0

# -------------------------------------------------
# CONTAINER CHECK
# -------------------------------------------------
def container_running():
    result = subprocess.run(
        ["docker", "ps", "--filter", f"name={ZAP_CONTAINER}", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    return ZAP_CONTAINER in result.stdout

# -------------------------------------------------
# START ZAP CONTAINER
# -------------------------------------------------
def start_container():
    print("\n🚀 Starting ZAP container...")

    if container_running():
        print("✅ ZAP container already running")
        return True

    if is_port_open(ZAP_PORT):
        print("⚠ Port already in use. Assuming ZAP running externally")
        return True

    try:
        subprocess.run([
            "docker", "run", "-d",
            "--name", ZAP_CONTAINER,
            "-p", f"{ZAP_PORT}:{ZAP_PORT}",
            ZAP_IMAGE,
            "zap.sh",
            "-daemon",
            "-port", str(ZAP_PORT),
            "-host", "0.0.0.0",
            "-config", "api.disablekey=true",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true"
        ], check=True)
        print("✅ ZAP container started")
        return True
    except Exception as e:
        print("❌ Failed to start ZAP container:", e)
        return False

# -------------------------------------------------
# WAIT FOR ZAP READY
# -------------------------------------------------
def wait_for_api(timeout=600):
    print("\n⏳ Waiting for ZAP API readiness...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{ZAP_PROXY}/JSON/core/view/version/", timeout=10)
            if r.status_code == 200:
                print("✅ ZAP API is ready:", r.json().get("version"))
                return True
        except Exception as e:
            debug(f"ZAP not ready: {e}")
        time.sleep(5)
    print("❌ ZAP API did not become ready in time")
    dump_debug()
    return False

# -------------------------------------------------
# DEBUG TELEMETRY
# -------------------------------------------------
def dump_debug():
    subprocess.run(["docker", "ps", "-a"])
    subprocess.run(["docker", "logs", ZAP_CONTAINER])

# -------------------------------------------------
# BUILD ZAP CLIENT
# -------------------------------------------------
def build_client():
    zap = ZAPv2(apikey="", proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})
    zap._ZAPv2__base = ZAP_PROXY  # fix proxy bug
    return zap

# -------------------------------------------------
# AI HELPER
# -------------------------------------------------
def ask_ai(prompt):
    try:
        r = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=600
        )
        return r.json().get("response", "No AI response")
    except Exception as e:
        print("❌ AI request failed:", e)
        return "AI request failed"

# -------------------------------------------------
# LOAD ALL JSON REPORTS
# -------------------------------------------------
def load_reports():
    findings = []
    if not os.path.exists("reports"):
        return findings
    for root, _, files in os.walk("reports"):
        for f in files:
            if f.endswith(".json"):
                try:
                    with open(os.path.join(root, f)) as file:
                        findings.append(file.read()[:3000])
                except Exception:
                    pass
    return findings

# -------------------------------------------------
# EXECUTIVE AI SUMMARY
# -------------------------------------------------
def generate_executive_summary():
    findings = load_reports()
    if not findings:
        print("⚠ No reports found for AI summary")
        return
    prompt = "Create executive vulnerability summary from findings:\n" + "\n".join(findings)
    summary = ask_ai(prompt)
    with open(f"{AI_REPORT_DIR}/executive_summary.txt", "w") as f:
        f.write(summary)
    print("✅ Executive AI summary generated")

# -------------------------------------------------
# RUN ZAP SCAN + AI ENRICHMENT
# -------------------------------------------------
def run():
    print("\n===== ENTERPRISE ZAP + AI SCAN =====")
    print("Target:", TARGET)

    if not TARGET:
        print("❌ TARGET_URL not set")
        return

    if not start_container():
        return

    if not wait_for_api():
        return

    zap = build_client()

    # ---------------- Spider --------------------------
    print("\nRunning ZAP Spider...")
    zap.urlopen(TARGET)
    time.sleep(2)
    spider_id = zap.spider.scan(TARGET, maxchildren=SPIDER_MAX_CHILDREN)
    start_time = time.time()
    while int(zap.spider.status(spider_id)) < 100:
        if time.time() - start_time > 300:  # 5 min timeout
            print("❌ Spider timeout, aborting")
            break
        print("Spider progress:", zap.spider.status(spider_id), "%")
        time.sleep(5)

    # ---------------- Active Scan --------------------
    print("\nRunning ZAP Active Scan...")
    zap.ascan.set_policy_attack_strength(policy_name="Default Policy",attack_strength="LOW")
    zap.ascan.set_policy_alert_threshold(policy_name="Default Policy",alert_threshold="MEDIUM")
    scan_id = zap.ascan.scan(TARGET)
    start_time = time.time()
    while int(zap.ascan.status(scan_id)) < 50:
        if time.time() - start_time > MAX_SCAN_TIME:
            print("❌ Active scan timeout, aborting")
            zap.ascan.stop(scan_id)
            break
        print("Active progress:", zap.ascan.status(scan_id), "%")
        time.sleep(10)

    # ---------------- Collect Alerts + AI ----------------
    alerts = zap.core.alerts(baseurl=TARGET)
    enriched = []
    print(f"\nProcessing {len(alerts)} alerts with AI...")
    for alert in alerts:
        remediation = ask_ai(f"Explain vulnerability and remediation:\n{json.dumps(alert, indent=2)}")
        enriched.append({**alert, "ai_remediation": remediation})

    zap_report = f"{REPORT_DIR}/zap_ai.json"
    with open(zap_report, "w") as f:
        json.dump(enriched, f, indent=2)
    print("✅ ZAP AI report saved")

    # ---------------- Executive Summary ----------------
    generate_executive_summary()
    print("===== ENTERPRISE SCAN COMPLETED =====\n")

# -------------------------------------------------
# SAFE ENTRY POINT
# -------------------------------------------------
if __name__ == "__main__":
    run()
