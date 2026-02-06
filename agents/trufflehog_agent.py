import subprocess
import os

REPORT_DIR = "reports/trufflehog"
os.makedirs(REPORT_DIR, exist_ok=True)


def run():

    print("Running Trufflehog...")

    subprocess.run(
        f'docker run --rm gesellix/trufflehog --json . > {REPORT_DIR}/trufflehog.json || true',
        shell=True
    )
