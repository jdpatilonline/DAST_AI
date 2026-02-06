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

    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=120
    )
    return r.json()["response"]


def run():

    if not TARGET:
        return

    print("Running ZAP scan...")

    zap.urlopen(TARGET)
    time.sleep(5)

    spider = zap.spider.scan(TARGET)
    while int(zap.spider.status(spider)) < 100:
        time.sleep(2)

    active = zap.ascan.scan(TARGET)
    while int(zap.ascan.status(active)) < 100:
        time.sleep(5)

    alerts = zap.core.alerts()

    enriched = []

    for alert in alerts:

        remediation = ask_ai(f"Provide remediation:\n{alert}")

        enriched.append({
            **alert,
            "remediation": remediation
        })

    with open(f"{REPORT_DIR}/zap_ai.json", "w") as f:
        json.dump(enriched, f, indent=2)
