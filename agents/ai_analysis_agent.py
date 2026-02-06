import os
import json
import requests

MODEL = os.getenv("OLLAMA_MODEL", "mistral")

REPORT_DIR = "reports/ai"
os.makedirs(REPORT_DIR, exist_ok=True)


def ask_ai(prompt):

    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False}
    )

    return r.json()["response"]


def load_reports():

    findings = []

    for root, _, files in os.walk("reports"):
        for f in files:
            if f.endswith(".json"):
                with open(os.path.join(root, f)) as file:
                    findings.append(file.read()[:3000])

    return findings


def run():

    findings = load_reports()

    summary = ask_ai(
        "Create executive vulnerability summary:\n" +
        "\n".join(findings)
    )

    with open(f"{REPORT_DIR}/executive_summary.txt", "w") as f:
        f.write(summary)
