from dotenv import load_dotenv
load_dotenv()

from agents.zap_agent import run as zap
from agents.semgrep_agent import run as semgrep
from agents.trufflehog_agent import run as trufflehog
from agents.nmap_agent import run as nmap
from agents.ai_analysis_agent import run as ai_analysis
from agents.policy_agent import run as policy


def main():

    print("Starting Security Orchestrator")

    zap()
    semgrep()
    trufflehog()
    nmap()
    ai_analysis()
    policy()

    print("Pipeline Completed")


if __name__ == "__main__":
    main()
