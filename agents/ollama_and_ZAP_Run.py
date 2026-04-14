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
    print("🚀 Starting ZAP")

    container_name = "enterprise-zap"
    image_name = "ghcr.io/zaproxy/zaproxy:stable"

    # 1. Clean up existing container to apply new resource limits
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)

    # 2. Start ZAP with hardware and scan engine constraints
    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--cpus", "2.0",                 # Limit to 2 CPU Cores
        "--memory", "6g",                # Limit to 4GB RAM
        "-e", "JAVA_OPTS=-Xmx4g",        # Limit Java Heap to 2GB
        "-p", f"{ZAP_PORT}:8080",
        image_name,
        "zap.sh", "-daemon", 
        "-host", "0.0.0.0", 
        "-port", "8080",
        "-config", "api.addrs.addr.name=.*",        # FIX: Allow Docker IP to access outside container
        "-config", "api.addrs.addr.regex=true",     # FIX: Allow Docker IP to access outside container
        "-config", "api.disablekey=true",
        "-config", "ascan.threadPerHost=1",         # Force sequential scanning
        "-config", "ascan.delayInMs=200",           # 200ms delay = 5 RPS
        "-config", "spider.thread=1",               # Low-intensity spidering
        "-config", "scanner.attackStrength=LOW"     # Fewer requests per plugin
    ]
    try:
        subprocess.run(cmd, check=True)
        print(f"[✓] ZAP started on port {ZAP_PORT}")
        print("✅ ZAP container ready")
    except subprocess.CalledProcessError as e:
        print(f"[✗] Failed to start ZAP: {e}")

# -------------------------------------------------
# WAIT FOR API
# -------------------------------------------------
def wait_for_api(timeout=300): 
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
# INSTALL AND START OLLAMA LOCALLY
# -------------------------------------------------
def install_and_start_ollama():
    print("🚀 Installing and starting Ollama locally...")

    # Step 1: Check if Ollama is already installed
    try:
        subprocess.run(["ollama", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ Ollama already installed")
    except FileNotFoundError:
        print("[+] Ollama not found. Installing...")
        try:
            subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, check=True)
            print("✅ Ollama installed successfully")
        except Exception as e:
            print("[✗] Ollama installation failed:", e)
            return False

    # Step 2: Check if Ollama API is already reachable
    if check_ollama():
        print("✅ Ollama already running")
        return True

    # Step 3: Start Ollama daemon in background
    try:
        subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("▶ Starting Ollama daemon...")

        # Wait until API responds
        start = time.time()
        timeout = 180
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

