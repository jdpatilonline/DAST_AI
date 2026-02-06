import os
import subprocess
import sys
import platform


def safe_run(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return str(e)


def print_header(title):
    print("\n" + "=" * 60)
    print(f"🔍 {title}")
    print("=" * 60)


def run_enterprise_debug():

    # ===============================
    # Workspace Debug
    # ===============================
    print_header("WORKSPACE INFORMATION")

    workspace = os.getcwd()
    print("Workspace Path:", workspace)

    try:
        print("\nWorkspace Files:")
        for f in os.listdir(workspace):
            print(" -", f)
    except Exception as e:
        print("Error reading workspace:", e)

    # ===============================
    # Git Debug
    # ===============================
    print_header("GIT INFORMATION")

    print("Branch:", safe_run(["git", "rev-parse", "--abbrev-ref", "HEAD"]))
    print("Commit SHA:", safe_run(["git", "rev-parse", "HEAD"]))
    print("Repo Remote:", safe_run(["git", "config", "--get", "remote.origin.url"]))

    # ===============================
    # GitHub Runner Debug
    # ===============================
    print_header("GITHUB RUNNER ENVIRONMENT")

    github_vars = [
        "GITHUB_WORKSPACE",
        "GITHUB_REPOSITORY",
        "GITHUB_SHA",
        "GITHUB_REF",
        "RUNNER_OS",
        "RUNNER_NAME"
    ]

    for var in github_vars:
        print(f"{var}: {os.getenv(var)}")

    # ===============================
    # Python Environment
    # ===============================
    print_header("PYTHON RUNTIME")

    print("Python Version:", sys.version)
    print("Platform:", platform.platform())

    # ===============================
    # Docker Debug
    # ===============================
    print_header("DOCKER STATUS")

    print(safe_run(["docker", "version"]))
    print("\nRunning Containers:")
    print(safe_run(["docker", "ps"]))

    # ===============================
    # Volume Mount Validation
    # ===============================
    print_header("DOCKER VOLUME TEST")

    test_cmd = [
        "docker", "run", "--rm",
        "-v", f"{workspace}:/repo",
        "alpine",
        "ls", "/repo"
    ]

    print(safe_run(test_cmd))

    # ===============================
    # Security Tools Availability
    # ===============================
    print_header("SECURITY TOOL CHECK")

    tools = ["docker", "git", "python"]

    for tool in tools:
        print(f"{tool}:", safe_run([tool, "--version"]))

    # ===============================
    # Environment Variables Safety
    # ===============================
    print_header("ENV VARIABLE SAFETY CHECK")

    sensitive_vars = [
        "OPENAI_API_KEY",
        "TARGET_URL",
        "HOST"
    ]

    for var in sensitive_vars:
        val = os.getenv(var)
        print(f"{var} Present:", bool(val))

    # ===============================
    # Directory Tree Preview
    # ===============================
    print_header("DIRECTORY TREE PREVIEW")

    print(safe_run(["ls", "-R", "|", "head", "-n", "50"]))
