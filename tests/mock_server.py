#!/usr/bin/env python3
"""A minimal stand-in for the three Vaultwarden endpoints the backup script uses.

    python tests/mock_server.py <fixture folder> [port]

Only for the automated tests. It listens on 127.0.0.1 and serves the test data
written by make_fixture.py.
"""
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

FIXTURE = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
CLIENT_ID = "user.test-client"
CLIENT_SECRET = "test-secret-123"
TOKEN = "test-access-token"


def load(name):
    with open(os.path.join(FIXTURE, name), "rb") as fh:
        return fh.read()


EXPECTED = json.loads(load("expected.json").decode("utf-8"))


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, content_type="application/json", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        return self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8")

    def _route(self):
        # "/big/..." serves the same account with twice as many items
        if self.path.startswith("/big/"):
            self.path = self.path[4:]
            return True
        return False

    def do_GET(self):
        big = self._route()
        if self.path.startswith("/api/sync"):
            if self.headers.get("Authorization") != "Bearer " + TOKEN:
                return self._send(401, '{"message":"Unauthorized"}')
            if big:
                sync = json.loads(load(os.path.join("server", "sync.json")).decode("utf-8"))
                sync["ciphers"] = sync["ciphers"] * 2
                return self._send(200, json.dumps(sync))
            return self._send(200, load(os.path.join("server", "sync.json")))
        if self.path == "/alive":
            return self._send(200, "{}")
        self._send(404, '{"message":"Not found"}')

    def do_POST(self):
        self._route()
        body = self._body()
        if self.path == "/identity/connect/token":
            form = urllib.parse.parse_qs(body)
            ok = (form.get("grant_type") == ["client_credentials"]
                  and form.get("client_id") == [CLIENT_ID]
                  and form.get("client_secret") == [CLIENT_SECRET])
            if not ok:
                return self._send(400, '{"error":"invalid_client","error_description":"bad credentials"}')
            return self._send(200, json.dumps({"access_token": TOKEN, "expires_in": 7200, "token_type": "Bearer"}))
        if self.path == "/identity/accounts/prelogin":
            email = (json.loads(body) or {}).get("email")
            if email != EXPECTED["email"]:
                # Like the real server: unknown addresses get default values, not an error
                return self._send(200, '{"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null}')
            return self._send(200, load(os.path.join("server", "prelogin.json")))
        if self.path == "/redirect/identity/connect/token":
            return self._send(307, "", headers={"Location": "http://127.0.0.1:%d/identity/connect/token" % PORT})
        self._send(404, '{"message":"Not found"}')

    def log_message(self, fmt, *args):
        sys.stderr.write("mock: " + (fmt % args) + "\n")


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
