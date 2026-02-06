import subprocess
import os

HOST = os.getenv("HOST")

REPORT_DIR = "reports/nmap"
os.makedirs(REPORT_DIR, exist_ok=True)


def run():

    if not HOST:
        return

    print("Running Nmap...")

    subprocess.run([
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}/reports/nmap:/data",
        "uzyexe/nmap",
        "-Pn", "-p", "80,443",
        "-sV", "-A",
        "-oX", "/data/nmap.xml",
        HOST
    ])
