import sys
import asyncio
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from mitmproxy import http

if len(sys.argv) != 3:
    print("Usage: python3 0.py <url to inject the js file> <js file to inject>")
    sys.exit(1)

TARGET_URL = sys.argv[1]
JS_FILE_PATH = sys.argv[2]

try:
    with open(JS_FILE_PATH, "r", encoding="utf-8") as f:
        OVERLAY_JS = f.read()
except Exception as e:
    print(f"Failed to read JS file '{JS_FILE_PATH}': {e}")
    sys.exit(1)

INJECT_SNIPPET = f"<script>{OVERLAY_JS}</script>"

class OverlayInjector:
    def response(self, flow: http.HTTPFlow):
        if (
            flow.request.pretty_url == TARGET_URL and
            "text/html" in flow.response.headers.get("content-type", "")
        ):
            print(f"Injecting overlay into {flow.request.pretty_url}")
            content = flow.response.text
            if "</body>" in content:
                content = content.replace("</body>", f"{INJECT_SNIPPET}</body>")
            else:
                content += INJECT_SNIPPET
            flow.response.text = content

async def amain():
    opts = Options(listen_host='127.0.0.1', listen_port=8080, ssl_insecure=True)
    m = DumpMaster(opts, with_termlog=False, with_dumper=False)
    m.addons.add(OverlayInjector())
    try:
        print("Starting proxy on 127.0.0.1:8080")
        await m.run()
    except KeyboardInterrupt:
        print("Shutting down...")
        await m.shutdown()

if __name__ == "__main__":
    asyncio.run(amain())
