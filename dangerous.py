from mitmproxy import http
from mitmproxy import ctx

# Path to your mitmproxy CA certificate (for reference in instructions, not used directly here)
CA_CERT_PATH = "/home/ntb/Stažené/mitmproxy-ca-cert.pem"

# The JS overlay to inject
OVERLAY_JS = """
((here js to inject))
"""

INJECT_SNIPPET = f"<script>{OVERLAY_JS}</script>"

class OverlayInjector:
    def __init__(self):
        self.monitored_urls = []

    def response(self, flow: http.HTTPFlow):
        # Only inject into HTML documents
        if "text/html" in flow.response.headers.get("content-type", ""):
            ctx.log.info(f"Injecting overlay into {flow.request.pretty_url}")
            content = flow.response.text
            # Try injecting before closing </body>, fallback to end of document
            if "</body>" in content:
                content = content.replace("</body>", f"{INJECT_SNIPPET}</body>")
            else:
                content += INJECT_SNIPPET
            flow.response.text = content
            self.monitored_urls.append(flow.request.pretty_url)
            ctx.log.info(f"Monitored URLs: {self.monitored_urls}")

addons = [OverlayInjector()]
