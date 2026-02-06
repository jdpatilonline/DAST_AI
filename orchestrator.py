from dotenv import load_dotenv
load_dotenv()
from enterprise_debug import run_enterprise_debug
from agents.zap_agent import run as zap
from agents.semgrep_agent import run as semgrep
from agents.trufflehog_agent import run as trufflehog
from agents.nmap_agent import run as nmap
from agents.ai_analysis_agent import run as ai_analysis
from agents.policy_agent import run as policy


def main():

    print("Starting Security Orchestrator")

    if os.getenv("ENTERPRISE_DEBUG") == "true":
        print("enterprise_debug is running")
        run_enterprise_debug()
    
    print("ZAP is running")
    zap()
    
    print("Semgrep is running")
    semgrep()
    
    print("Trufflehog is running")
    trufflehog()
    
    print("Nmap is running")
    nmap()
    
    print("ai_analysis is running")
    ai_analysis()
    
    print("Policy Agent is running")
    policy()

    print("Pipeline Completed")


if __name__ == "__main__":
    main()
