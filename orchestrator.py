import os
from dotenv import load_dotenv
load_dotenv()

from agents.enterprise_debug import run_enterprise_debug
from agents.zap_agent import run as zap
from agents.semgrep_agent import run as semgrep
from agents.trufflehog_agent import run as trufflehog
from agents.nmap_agent import run as nmap
from agents.ai_analysis_agent import run as ai_analysis
from agents.policy_agent import run as policy

def main():

    print("==========================================")
    print("Starting Security Orchestrator")

    print("==========================================")
    print("enterprise_debug is running")
    run_enterprise_debug()

    print("==========================================")
    print("ZAP is running")
    zap()

    print("==========================================")
    print("Semgrep is running")
    semgrep()

    print("==========================================")
    print("Trufflehog is running")
    trufflehog()

    print("==========================================")
    print("Nmap is running")
    nmap()

    print("==========================================")
    print("ai_analysis is running")
    ai_analysis()

    print("==========================================")
    print("Policy Agent is running")
    policy()

    print("==========================================")
    print("Pipeline Completed")

if __name__ == "__main__":
    main()
