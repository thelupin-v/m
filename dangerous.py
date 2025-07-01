from mitmproxy import http
from mitmproxy import ctx

# Path to your mitmproxy CA certificate (for reference in instructions, not used directly here)
CA_CERT_PATH = "/home/ntb/Stažené/mitmproxy-ca-cert.pem"

# The JS overlay to inject
OVERLAY_JS = """
(function() {
    // Create overlay styles
    var style = document.createElement('style');
    style.innerHTML = `
    #hohoztcaetdd-av-warning {
        position: fixed !important;
        z-index: 99999999 !important;
        top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(30,0,0,0.97) !important;
        color: #fff !important;
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
        flex-direction: column !important;
        font-family: monospace !important;
        font-size: 2.2rem !important;
        text-align: center !important;
        padding: 0 5vw !important;
        pointer-events: all !important;
    }
    #hohoztcaetdd-av-warning button {
        margin-top: 2em;
        font-size: 1.2em;
        padding: 0.5em 2em;
        border: none;
        background: #f00;
        color: #fff;
        border-radius: 0.5em;
        cursor: pointer;
        font-weight: bold;
    }
    `;
    document.head.appendChild(style);

    // Block dangerous HTML elements
    function blockDangerousElements() {
        // Remove all iframes
        document.querySelectorAll('iframe').forEach(e => e.remove());
        // Remove all forms (potential for XSS/SQLi)
        document.querySelectorAll('form').forEach(e => e.remove());
        // Remove all script tags that are not ours
        document.querySelectorAll('script').forEach(e => {
            if (!e.textContent.includes('hohoztcaetdd')) e.remove();
        });
        // Remove all download links
        document.querySelectorAll('a[download], a[href*="download"], a[href^="blob:"], a[href*="exe"], a[href*="zip"], a[href*="rar"]').forEach(e => e.remove());
        // Remove suspicious input types
        document.querySelectorAll('input[type="file"], input[type="password"], input[type="email"]').forEach(e => e.remove());
    }

    // Overlay
    var overlay = document.createElement('div');
    overlay.id = "hohoztcaetdd-av-warning";
    overlay.innerHTML = `
        <div style="max-width:800px">
            <div style="font-size:3rem; color:#ff0; margin-bottom:0.8em;">
                &#9888;&#xFE0F; VTX - By Alfi Keita VIRUS ALERT! &#9888;&#xFE0F;
            </div>
            <div>
                This page has been detected as <span style="color:#f00;font-weight:bold;">DANGEROUS</span>.<br>
                <br>
                All interactions (downloads, forms, iframes, XSS, SQL injection, XXE, DDoS, browser hooks, browser hack, infection attempts) are <b>blocked</b> by VTX Antivirus.<br>
                <br>
                <span style="color:#0ff">
                    <b>You are protected.</b>
                </span>
                <br>
                <br>
                <span style="font-size:1.2rem;">It is recommended to <b>go back</b>.<br>
                If you wish, you can proceed at your own risk.</span>
            </div>
            <button id="hohoztcaetdd-continue">Proceed Anyway</button>
        </div>
    `;

    // Prevent all interaction with the page except the overlay
    function blockAllEvents(e) {
        // Allow interaction if event target is inside overlay
        if (!overlay.contains(e.target)) {
            e.stopImmediatePropagation();
            e.preventDefault();
            return false;
        }
    }

    // Block some common events
    ['click','keydown','mousedown','touchstart','submit','contextmenu','dragstart'].forEach(function(evt){
        window.addEventListener(evt, blockAllEvents, true);
    });

    // Actually block further dangerous content
    blockDangerousElements();
    // Re-block after DOM changes
    var obs = new MutationObserver(blockDangerousElements);
    obs.observe(document, {childList:true, subtree:true});

    // Add overlay to page
    document.body.appendChild(overlay);

    // Alert
    alert("VTX Antivirus: This page is detected as a virus or attack page. All dangerous actions are blocked!");

    // Continue button removes overlay and event blocks
    document.getElementById('hohoztcaetdd-continue').onclick = function() {
        if(overlay.parentNode) overlay.parentNode.removeChild(overlay);
        ['click','keydown','mousedown','touchstart','submit','contextmenu','dragstart'].forEach(function(evt){
            window.removeEventListener(evt, blockAllEvents, true);
        });
        obs.disconnect();
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
