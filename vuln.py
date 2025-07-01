from mitmproxy import http
from mitmproxy import ctx

# Path to your mitmproxy CA certificate (for reference in instructions, not used directly here)
CA_CERT_PATH = "/home/ntb/Stažené/mitmproxy-ca-cert.pem"

# The JS overlay to inject
OVERLAY_JS = """
(function() {
    // Create overlay background
    var overlay = document.createElement('div');
    overlay.id = 'vtx-xss-overlay';
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.width = '100vw';
    overlay.style.height = '100vh';
    overlay.style.background = 'rgba(0,0,0,0.75)';
    overlay.style.zIndex = '2147483647';
    overlay.style.display = 'flex';
    overlay.style.flexDirection = 'column';
    overlay.style.justifyContent = 'center';
    overlay.style.alignItems = 'center';

    // Prevent scrolling
    document.body.style.overflow = 'hidden';

    // Overlay content
    var box = document.createElement('div');
    box.style.background = '#fff';
    box.style.padding = '32px 28px 28px 28px';
    box.style.borderRadius = '12px';
    box.style.boxShadow = '0 8px 32px rgba(0,0,0,0.15)';
    box.style.display = 'flex';
    box.style.flexDirection = 'column';
    box.style.alignItems = 'center';
    box.style.minWidth = '320px';

    // Heading
    var h1 = document.createElement('h2');
    h1.textContent = 'Detected a XSS Vulnerability!';
    h1.style.color = '#d32f2f';
    h1.style.margin = '0 0 10px 0';
    box.appendChild(h1);

    // Subheading
    var sub = document.createElement('div');
    sub.textContent = 'VTX - By Alfi Keita - Detected a Vulnerability!';
    sub.style.color = '#444';
    sub.style.marginBottom = '18px';
    sub.style.fontWeight = 'bold';
    box.appendChild(sub);

    // Question
    var q = document.createElement('div');
    q.textContent = 'Do you want to proceed?';
    q.style.marginBottom = '22px';
    q.style.fontSize = '16px';
    q.style.color = '#222';
    box.appendChild(q);

    // Button container
    var btns = document.createElement('div');
    btns.style.display = 'flex';
    btns.style.gap = '16px';

    // Access button
    var access = document.createElement('button');
    access.textContent = 'Access';
    access.style.background = '#388e3c';
    access.style.color = '#fff';
    access.style.border = 'none';
    access.style.padding = '10px 24px';
    access.style.fontSize = '15px';
    access.style.borderRadius = '5px';
    access.style.cursor = 'pointer';
    access.onclick = function() {
        document.body.style.overflow = '';
        overlay.remove();
    };
    btns.appendChild(access);

    // Go back button
    var back = document.createElement('button');
    back.textContent = 'Go back';
    back.style.background = '#d32f2f';
    back.style.color = '#fff';
    back.style.border = 'none';
    back.style.padding = '10px 24px';
    back.style.fontSize = '15px';
    back.style.borderRadius = '5px';
    back.style.cursor = 'pointer';
    back.onclick = function() {
        window.history.back();
    };
    btns.appendChild(back);

    box.appendChild(btns);
    overlay.appendChild(box);
    document.body.appendChild(overlay);

    // Trap tab navigation inside overlay (basic version)
    overlay.tabIndex = 0;
    overlay.focus();
    overlay.onkeydown = function(e) {
        if (e.key === 'Tab') {
            e.preventDefault();
        }
    };
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
