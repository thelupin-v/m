from mitmproxy import http
from mitmproxy import ctx

# Path to your mitmproxy CA certificate (for reference in instructions, not used directly here)
CA_CERT_PATH = "/home/ntb/Stažené/mitmproxy-ca-cert.pem"

# The JS overlay to inject
OVERLAY_JS = """
(function() {
    let overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.top = 0;
    overlay.style.left = 0;
    overlay.style.width = "100%";
    overlay.style.height = "100%";
    overlay.style.backgroundColor = "rgba(255,0,0,0.9)";
    overlay.style.zIndex = 999999;
    overlay.style.color = "#fff";
    overlay.style.display = "flex";
    overlay.style.flexDirection = "column";
    overlay.style.justifyContent = "center";
    overlay.style.alignItems = "center";
    overlay.innerHTML = `
        <h1 style="font-size: 32px; margin: 0;">⚠️ NEBEZPEČNÁ STRÁNKA</h1>
        <p style="font-size: 20px;">Tato stránka byla označena jako potenciálně škodlivá.</p>
        <button onclick="location.href='https://www.google.com'" style="margin-top:20px;padding:10px 20px;font-size:16px;">Opustit stránku</button>
    `;
    document.body.appendChild(overlay);
})();
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
