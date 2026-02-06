import os
import json
import sys
import requests

MODEL = os.getenv("OLLAMA_MODEL", "mistral")


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
                    findings.append(file.read())

    return findings


def run():

    findings = load_reports()

    decision = ask_ai(f"""
Should pipeline fail only if critical vulnerability confirmed?

Return JSON:
{{ "fail": true/false }}

Findings:
{findings[:5000]}
""")

    try:
        result = json.loads(decision)
        if result.get("fail"):
            sys.exit(1)
    except:
        pass
