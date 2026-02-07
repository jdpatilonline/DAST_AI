import os
import subprocess
import time
import requests
import json
import socket

OLLAMA_PORT = 11434
OLLAMA_URL = "http://127.0.0.1:11434"
MODEL = os.getenv("OLLAMA_MODEL", "mistral")

REPORT_DIR = "reports/ollama_test"
os.makedirs(REPORT_DIR, exist_ok=True)


# -------------------------------------------------
# Check Port Usage
# -------------------------------------------------
def is_port_open(port):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


# -------------------------------------------------
# Install Ollama
# -------------------------------------------------
def install_ollama():

    print("\nInstalling Ollama...")

    try:
        subprocess.run(
            "curl -fsSL https://ollama.com/install.sh | sh",
            shell=True,
            check=True
        )

        print("✅ Ollama installation complete")

    except Exception as e:
        print("❌ Ollama install failed:", e)


# -------------------------------------------------
# Start Ollama Service
# -------------------------------------------------
def start_ollama():

    print("\nChecking Ollama service...")

    if is_port_open(OLLAMA_PORT):
        print("✅ Ollama already running")
        return

    print("Starting Ollama service...")

    subprocess.Popen(
        "ollama serve",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(20)

    if is_port_open(OLLAMA_PORT):
        print("✅ Ollama started successfully")
    else:
        print("❌ Ollama failed to start")


# -------------------------------------------------
# Pull AI Model
# -------------------------------------------------
def pull_model():

    print(f"\nPulling AI model: {MODEL}")

    try:
        subprocess.run(
            ["ollama", "pull", MODEL],
            check=True
        )

        print("✅ Model ready")

    except Exception as e:
        print("❌ Model pull failed:", e)


# -------------------------------------------------
# Test AI
# -------------------------------------------------
def test_ai():

    print("\nTesting Ollama AI response...")

    payload = {
        "model": MODEL,
        "prompt": "what are Top 10 OWASP Web vulnerabilities",
        "stream": False
    }

    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            timeout=120
        )

        response = r.json().get("response", "")

        print("\n===== AI RESPONSE =====")
        print(response)
        print("=======================\n")

        with open(f"{REPORT_DIR}/ollama_test.json", "w") as f:
            json.dump(r.json(), f, indent=2)

        print("✅ AI test report saved")

    except Exception as e:
        print("❌ AI test failed:", e)


# -------------------------------------------------
# MAIN RUN
# -------------------------------------------------
def run():

    print("\n===== ENTERPRISE OLLAMA AGENT =====")

    install_ollama()
    start_ollama()
    pull_model()
    test_ai()

    print("===== OLLAMA AGENT COMPLETED =====\n")

if __name__ == "__main__":
    run()
