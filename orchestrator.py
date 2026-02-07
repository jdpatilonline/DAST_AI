import os
from dotenv import load_dotenv
load_dotenv()

from agents.enterprise_debug import run_enterprise_debug
#from agents.semgrep_agent import run as semgrep
#from agents.trufflehog_agent import run as trufflehog
#from agents.nmap_agent import run as nmap
#from agents.zap_agent import run as zap
from agents.ai_analysis_agent import run as ai_analysis
from agents.policy_agent import run as policy

def main():

    print("==========================================")
    print("Starting Security Orchestrator Funtion")

    print("==========================================")
    print("enterprise_debug Funtion is running")
    #run_enterprise_debug()

    print("==========================================")
    #print("Semgrep Funtion is running")
    #semgrep()

    print("==========================================")
    #print("Trufflehog Funtion is running")
    #trufflehog()

    print("==========================================")
    #print("Nmap Funtion is running")
    #nmap()

    print("==========================================")
   # print("ZAP Funtion is running")
   # zap()

    print("==========================================")
    print("ai_analysis Funtion is running")
    ai_analysis()

    print("==========================================")
    print("Policy Agent Funtion is running")
    policy()

    print("==========================================")
    print("Pipeline Funtion Completed")

if __name__ == "__main__":
    main()
