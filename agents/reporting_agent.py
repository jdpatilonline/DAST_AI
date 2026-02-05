import json

class ReportingAgent:

    def generate(self, results):

        with open("security-report.json", "w") as f:
            json.dump(results, f, indent=2)
