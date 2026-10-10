"""A tiny Prometheus HTTP API for tests: deterministic CPU and memory series per pod."""

import json
import math
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def cpu(pod, t):
    return 0.05 + 0.04 * (1 + math.sin(t / 600 + len(pod)))


def memory(pod, t):
    return (180 + 20 * math.sin(t / 900 + len(pod))) * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    pods = ()
    queries = []

    def do_GET(self):
        url = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        Handler.queries.append(q["query"])
        fn = cpu if "cpu" in q["query"] else memory
        match = re.search(r'pod="([^"]+)"', q["query"])
        if url.path == "/api/v1/query_range":
            pod = match.group(1)
            start, end, step = float(q["start"]), float(q["end"]), int(q["step"])
            values = [[t, str(fn(pod, t))] for t in range(int(start), int(end), step)]
            result = [{"metric": {}, "values": values}] if pod in self.pods else []
        else:
            result = [{"metric": {"pod": p}, "value": [0, str(fn(p, 0))]} for p in self.pods]
        raw = json.dumps({"status": "success", "data": {"resultType": "matrix", "result": result}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


def start(pods):
    handler = type("BoundProm", (Handler,), {"pods": tuple(pods), "queries": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}", handler
