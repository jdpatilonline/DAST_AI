import os
from dotenv import load_dotenv

from agents.scanner_agent import ScannerAgent
from agents.payload_agent import PayloadAgent
from agents.validation_agent import ValidationAgent
from agents.intelligence_agent import IntelligenceAgent
from agents.remediation_agent import RemediationAgent
from agents.reporting_agent import ReportingAgent

load_dotenv()

TARGET = os.getenv("TARGET_URL")

scanner = ScannerAgent()
payload_agent = PayloadAgent()
validation_agent = ValidationAgent()
intel_agent = IntelligenceAgent()
remediation_agent = RemediationAgent()
report_agent = ReportingAgent()


def run():

    alerts = scanner.scan(TARGET)

    results = []

    for vuln in alerts[:5]:

        payloads = payload_agent.generate(vuln)

        evidence = validation_agent.validate(
            vuln["url"],
            payloads
        )

        intelligence = intel_agent.analyze(vuln, evidence)

        remediation = remediation_agent.recommend(vuln)

        results.append({
            "vulnerability": vuln["name"],
            "url": vuln["url"],
            "analysis": intelligence,
            "remediation": remediation
        })

    report_agent.generate(results)


if __name__ == "__main__":
    run()
