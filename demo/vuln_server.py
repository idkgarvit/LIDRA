#!/usr/bin/env python3
"""Tiny vulnerable webserver for LIDRA demo.

Endows the demo with a real HTTP target that responds to requests.
Three endpoints:
  GET /            -> "LIDRA demo server"
  GET /search?q=.. -> echoes the query (so SQLi shows up in payload)
  GET /login       -> fake login form

The server is INTENTIONALLY trivial. It is not a real vuln app —
its job is to make attack traffic appear in the pcap/SPAN feed
so LIDRA can detect it. We never run user input as SQL.

Run:
  python3 demo/vuln_server.py [PORT]
  defaults to port 8080
"""
import http.server
import socketserver
import sys
import urllib.parse
from datetime import datetime

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


class DemoHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[vuln_server] {self.address_string()} - {fmt % args}\n")

    def _send(self, body, code=200, ctype="text/html"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/":
            self._send(
                "<h1>LIDRA demo server</h1>"
                "<p>Try <a href='/search?q=hello'>/search?q=hello</a></p>"
                "<p>Or <a href='/login'>/login</a></p>"
                f"<p><small>Time: {datetime.now().isoformat()}</small></p>"
            )
            return

        if parsed.path == "/search":
            q = qs.get("q", [""])[0]
            # Just echo — never exec the query
            self._send(
                f"<h1>Search results for: {q!r}</h1>"
                f"<p>(Demo: query echoed, not executed)</p>"
            )
            return

        if parsed.path == "/login":
            self._send(
                "<h1>Login</h1>"
                "<form method='POST'>"
                "<input name='user'><input name='pass' type='password'>"
                "<button>Login</button>"
                "</form>"
            )
            return

        if parsed.path == "/healthz":
            self._send("ok", ctype="text/plain")
            return

        self._send("not found", code=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/login":
            self._send(
                f"<h1>Login failed for: {body!r}</h1>"
                f"<p>(Demo: never actually authenticated)</p>"
            )
            return
        self._send("not found", code=404)


class ReusingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    print(f"[vuln_server] Listening on 0.0.0.0:{PORT}", flush=True)
    try:
        with ReusingTCPServer(("0.0.0.0", PORT), DemoHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[vuln_server] Shutting down", flush=True)
