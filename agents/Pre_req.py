import subprocess
import sys
import os

def run_command(command):
    print(f"Running: {command}")
    subprocess.run(command, shell=True, check=True)

def main():
    # Step 1: Create virtual environment
    run_command("python3 -m venv zapenv")

    # Step 2: Define paths inside venv
    venv_python = os.path.join("zapenv", "bin", "python")
    venv_pip = os.path.join("zapenv", "bin", "pip")

    # Step 3: Upgrade pip
    run_command(f"{venv_pip} install --upgrade pip")

    # Step 4: Install required packages
    packages = [
        "aiohttp",
        "python-owasp-zap-v2.4",
        "pandas",
        "matplotlib",
        "playwright",
        "docx",
        "python-docx",
        "python-owasp-zap-v2.4"
    ]
    for pkg in packages:
        run_command(f"{venv_pip} install {pkg}")

    # Step 5: Install Playwright browser
    run_command(f"{venv_python} -m playwright install chromium")

    print("\n✅ Environment setup complete.")
    print("To activate manually in your shell, run:\n  source zapenv/bin/activate")

if __name__ == "__main__":
    main()
