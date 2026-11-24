#!/usr/bin/env python3
"""Fleet Muse M1 — cover page server.

Listens on 127.0.0.1:$COVER_PORT (default 18080) and returns HTTP 200 with a
generic static landing page for ANY request. Xray's inbound `fallbacks`
forwards non-VLESS traffic (e.g. GET /) here so the node looks like an
ordinary web service.

Stdlib only. No logging of request headers, paths, or environment.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COVER_PORT = int(os.environ.get("COVER_PORT", "18080"))
COVER_HOST = os.environ.get("COVER_HOST", "127.0.0.1")

PAGE = b"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Welcome</title></head>
<body><h1>Welcome</h1><p>This is a static web service.</p></body>
</html>
"""


class CoverHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self):
        body = PAGE
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self._respond()

    def do_HEAD(self):
        self._respond()

    def do_POST(self):
        # Drain any body so the connection stays clean, then answer 200.
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._respond()

    def log_message(self, fmt, *args):
        # Silent by design: never log request lines, headers or paths.
        pass


def main():
    server = ThreadingHTTPServer((COVER_HOST, COVER_PORT), CoverHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
