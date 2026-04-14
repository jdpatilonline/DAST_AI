import os
import time
import json
import subprocess
import requests
from zapv2 import ZAPv2

# ==========================================
# CONFIGURATION
# ==========================================
OLLAMA_API_URL = "http://127.0.0.1:11434"
MODEL = os.getenv("OLLAMA_MODEL", "qwen")
REPORT_DIR = "reports/ollama_test"
os.makedirs(REPORT_DIR, exist_ok=True)

ZAP_PORT = 8080
ZAP_PROXY = f"http://127.0.0.1:{ZAP_PORT}"

# -------------------------------------------------
# START ZAP (FIXED - REUSE CONTAINER)
# -------------------------------------------------
def start_zap():
    print("🚀 Starting ZAP (reuse mode)...")

    container_name = "enterprise-zap"
    image_name = "ghcr.io/zaproxy/zaproxy:stable"

    # Check if container already exists
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
        capture_output=True,
        text=True
    )
    container_exists = container_name in result.stdout.strip()

    if container_exists:
        print("🔁 Container already exists")

        # Check if running
        running_check = subprocess.run(
            ["docker", "ps", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True
        )
        is_running = container_name in running_check.stdout.strip()

        if not is_running:
            print("▶ Starting existing container...")
            subprocess.run(["docker", "start", container_name], check=True)
        else:
            print("✅ Container already running")

    else:
        print("📦 Creating new ZAP container (first time only)...")
        subprocess.run(
            [
                "docker", "run", "-d",
                "--name", container_name,
                "-p", f"{ZAP_PORT}:8080",
                image_name,
                "zap.sh",
                "-daemon",
                "-host", "0.0.0.0",
                "-port", "8080",
                "-config", "api.disablekey=true",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
                "-config", "scanner.attackStrength=MEDIUM",
                "-config", "scanner.alertThreshold=MEDIUM"
            ],
            check=True
        )

    print("✅ ZAP container ready")

# -------------------------------------------------
# WAIT FOR API
# -------------------------------------------------
def wait_for_api(timeout=120):
    print("⏳ Waiting for ZAP API...")
    start = time.time()
    while True:
        if time.time() - start > timeout:
            raise TimeoutError("ZAP API timeout")

        try:
            r = requests.get(f"{ZAP_PROXY}/JSON/core/view/version/")
            if r.status_code == 200:
                print("✅ ZAP Ready")
                return
        except:
            pass
        time.sleep(3)

# -------------------------------------------------
# BUILD CLIENT
# -------------------------------------------------
def build_client():
    zap = ZAPv2(apikey="", proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})
    zap._ZAPv2__base = ZAP_PROXY
    return zap

# -------------------------------------------------
# INSTALL OLLAMA LOCALLY
# -------------------------------------------------
def install_and_start_ollama():
    print("🚀 Installing Ollama locally...")

    try:
        # Install Ollama using the official script
        subprocess.run(
            "curl -fsSL https://ollama.com/install.sh | sh",
            shell=True,
            check=True
        )
        print("✅ Ollama installed successfully")
    except Exception as e:
        print("[✗] Ollama installation failed:", e)

# -------------------------------------------------
# START OLLAMA LOCALLY
# -------------------------------------------------
def start_ollama():
    print("🚀 Starting Ollama locally...")

    # First check if API is already reachable
    if check_ollama():
        print("✅ Ollama already running")
        return True

    try:
        # Start Ollama daemon in background
        subprocess.Popen(["ollama", "ls"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for API to come up
        start = time.time()
        timeout = 300
        while time.time() - start < timeout:
            if check_ollama():
                print("✅ Ollama daemon started and reachable")
                return True
            time.sleep(3)

        print("[✗] Ollama did not start within timeout")
        return False
    except Exception as e:
        print("[✗] Failed to start Ollama:", e)
        return False

# ==========================================
# CHECK OLLAMA HEALTH
# ==========================================
def check_ollama():
    try:
        r = requests.get(f"{OLLAMA_API_URL}/api/tags", timeout=100)
        if r.status_code == 200:
            print("[✓] Ollama API reachable")
            return True
        return False
    except Exception as e:
        print("[✗] API connection failed:", e)
        return False

# ==========================================
# CHECK IF MODEL EXISTS
# ==========================================
def is_model_installed():
    try:
        r = requests.get(f"{OLLAMA_API_URL}/api/tags", timeout=100)
        models = r.json().get("models", [])
        return any(MODEL in m.get("name", "") for m in models)
    except:
        return False

# ==========================================
# ENSURE MODEL
# ==========================================
def ensure_model():
    if is_model_installed():
        print(f"[✓] Model '{MODEL}' already installed on server")
        return True

    print(f"[+] Model '{MODEL}' not found. Attempting to pull...")
    try:
        subprocess.run(["ollama", "pull", MODEL], check=True)
        print("[✓] Model pulled successfully")
        return True
    except Exception as e:
        print("[✗] Model pull failed. Pull manually on server:", e)
        return False

# ==========================================
# TEST AI GENERATION
# ==========================================
def test_ai():
    print("\n[+] Testing AI response...")
    payload = {
        "model": MODEL,
        "prompt": "List Top 10 OWASP Web Vulnerabilities with short explanation.",
        "stream": False
    }
    try:
        r = requests.post(f"{OLLAMA_API_URL}/api/generate", json=payload, timeout=300)
        r.raise_for_status()
        result = r.json()

        print("\n========== AI RESPONSE ==========\n")
        print(result.get("response", "No response"))
        print("\n=================================\n")

        with open(f"{REPORT_DIR}/ollama_test.json", "w") as f:
            json.dump(result, f, indent=2)
        print("[✓] Report saved successfully")
    except Exception as e:
        print("[✗] AI test failed:", e)

# ==========================================
# MAIN EXECUTION
# ==========================================
def run():
    print("\n===== ENTERPRISE OLLAMA + ZAP AGENT =====")

    # Start ZAP
    start_zap()
    wait_for_api()
    zap_client = build_client()

    # Install and start Ollama locally
    install_and_start_ollama()

    # start Ollama locally
    start_ollama()
    
    # Ollama checks
    if not check_ollama():
        print("[✗] Ollama API not reachable")
        return
    if not ensure_model():
        return

    # Test AI
    test_ai()

    print("===== AGENT COMPLETED =====\n")

if __name__ == "__main__":
    run()
