import requests
import time
from core.zap_client import ZapClient

class ValidationAgent:

    def __init__(self):

        self.session = requests.Session()

        self.session.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080"
        }

        self.client = ZapClient()

    def validate(self, url, payloads):

        evidence = []

        for payload in payloads:

            try:
                test_url = f"{url}?ai_test={payload}"

                self.session.get(test_url, timeout=8)

                time.sleep(2)

                alerts = self.client.alerts(test_url)

                evidence.append({
                    "payload": payload,
                    "alerts": alerts
                })

            except Exception as ex:
                evidence.append({"error": str(ex)})

        return evidence
