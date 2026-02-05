import time
from core.zap_client import ZapClient

class ScannerAgent:

    def __init__(self):
        self.client = ZapClient()

    def scan(self, target):

        spider_id = self.client.spider(target)

        while int(self.client.spider_status(spider_id)) < 100:
            time.sleep(2)

        scan_id = self.client.active_scan(target)

        while int(self.client.active_status(scan_id)) < 100:
            time.sleep(5)

        return self.client.alerts()
