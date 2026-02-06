import os
import time
import json
import requests
from zapv2 import ZAPv2

TARGET = os.getenv("TARGET_URL")
MODEL = os.getenv("OLLAMA_MODEL", "mistral")

REPORT_DIR = "reports/zap"
os.makedirs(REPORT_DIR, exist_ok=True)

zap = ZAPv2(proxies={
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
})


def ask_ai(prompt):
    """
    Ask Ollama AI for remediation, explanation, or validation.
    """
    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=120
        )
        return r.json().get("response", "No response from AI")
    except Exception as e:
        print("❌ AI request failed:", e)
        return "AI request failed"


def run():
    workspace = os.getcwd()

    # ----------------------------
    # Enterprise debug info
    # ----------------------------
    print("\n===== ZAP ENTERPRISE SCAN =====")
    print("Workspace Path:", workspace)
    print("Target URL:", TARGET)

    try:
        print("Workspace Files:", os.listdir(workspace))
    except Exception as e:
        print("Error listing workspace files:", e)

    if not TARGET:
        print("❌ TARGET_URL not set. Skipping ZAP scan.")
        return

    # ----------------------------
    # ZAP Health Check
    # ----------------------------
    try:
        resp = requests.get("http://127.0.0.1:8080")
        if resp.status_code == 200:
            print("✅ ZAP proxy is running")
    except Exception as e:
        print("❌ ZAP proxy not reachable:", e)
        return

    # ----------------------------
    # Start Scan
    # ----------------------------
    try:
        print("Running ZAP spider...")
        zap.urlopen(TARGET)
        time.sleep(5)
        spider = zap.spider.scan(TARGET)
        while int(zap.spider.status(spider)) < 100:
            print(f"Spider progress: {zap.spider.status(spider)}%")
            time.sleep(2)

        print("Running ZAP active scan...")
        active = zap.ascan.scan(TARGET)
        while int(zap.ascan.status(active)) < 100:
            print(f"Active scan progress: {zap.ascan.status(active)}%")
            time.sleep(5)

    except Exception as e:
        print("❌ ZAP scanning failed:", e)
        return

    # ----------------------------
    # Collect alerts and ask AI
    # ----------------------------
    try:
        alerts = zap.core.alerts()
        enriched = []

        print(f"Found {len(alerts)} alerts. Asking AI for remediation...")

        for alert in alerts:
            remediation = ask_ai(f"Provide remediation and explanation for this alert:\n{alert}")
            enriched.append({
                **alert,
                "remediation": remediation
            })

        report_path = os.path.join(REPORT_DIR, "zap_ai.json")
        with open(report_path, "w") as f:
            json.dump(enriched, f, indent=2)

        print(f"✅ ZAP scan report written to {report_path}")

    except Exception as e:
        print("❌ Failed to process ZAP alerts:", e)

    print("===== ZAP SCAN COMPLETED =====\n")
