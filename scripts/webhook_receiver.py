"""Tiny webhook receiver for local demos: prints alerts and checks signatures.

    python scripts/webhook_receiver.py [--port 9000] [--secret s3cret]

Then run the SIEM with WEBHOOK_URLS=http://host.docker.internal:9000 (from
Docker) or http://localhost:9000 (local), and the same WEBHOOK_SECRET.
"""

import argparse
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

HEADER = "X-MiniSIEM-Signature"


def make_handler(secret: str | None):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if secret:
                expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, self.headers.get(HEADER, "")):
                    print("!! rejected request with invalid signature")
                    self.send_response(401)
                    self.end_headers()
                    return
            alert = json.loads(body).get("alert", {})
            verified = "signature OK" if secret else "unsigned"
            print(
                f"[{alert.get('severity', '?').upper()}] risk {alert.get('risk_score')}  "
                f"{alert.get('title')}  ({alert.get('rule_id')}, {verified})"
            )
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--secret")
    args = parser.parse_args()
    print(f"listening on :{args.port}")
    HTTPServer(("0.0.0.0", args.port), make_handler(args.secret)).serve_forever()
