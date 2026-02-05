from zapv2 import ZAPv2

class ZapClient:

    def __init__(self):

        self.zap = ZAPv2(proxies={
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080"
        })

    def spider(self, target):
        return self.zap.spider.scan(target)

    def spider_status(self, scan_id):
        return self.zap.spider.status(scan_id)

    def active_scan(self, target):
        return self.zap.ascan.scan(target)

    def active_status(self, scan_id):
        return self.zap.ascan.status(scan_id)

    def alerts(self, baseurl=None):
        return self.zap.core.alerts(baseurl=baseurl)
