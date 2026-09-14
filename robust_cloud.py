"""FedZTA Cloud Aggregator with Byzantine-robust aggregation.

Coordinate-wise median tolerates f malicious clients only when K >= 2f+1, so the
aggregator reports how many distinct peers it is aggregating over and refuses to
claim robustness below that threshold.

Change over the previous revision: updates are keyed by client_id and only the
most recent upload per peer is retained. The previous version kept a sliding
window of the last 10 uploads regardless of origin, which computes a median over
*time* rather than over *peers* -- a persistently malicious node simply occupies
half of every window.
"""
import json
import os
import statistics
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import fedzta_features as F

MODEL_PATH = os.environ.get("FEDZTA_MODEL", "fed_model.json")
AGGREGATION = os.environ.get("FEDZTA_AGG", "median")   # median | trimmed | mean
TRIM = int(os.environ.get("FEDZTA_TRIM", "1"))

_lock = threading.Lock()
_latest = {}          # client_id -> {"weights": [...], "bias": float}


def load_bootstrap(path):
    with open(path) as fh:
        m = json.load(fh)
    return list(m["coefficients"]), float(m["intercept"])


BOOT_W, BOOT_B = load_bootstrap(MODEL_PATH)


def trimmed_mean(values, k):
    v = sorted(values)
    v = v[k:len(v) - k] if len(v) > 2 * k else v
    return sum(v) / len(v)


def aggregate():
    with _lock:
        peers = list(_latest.values())
        ids = list(_latest)
    if not peers:
        return BOOT_W, BOOT_B, 0, ids

    cols = list(zip(*[p["weights"] for p in peers]))
    biases = [p["bias"] for p in peers]
    if AGGREGATION == "mean" or len(peers) == 1:
        w = [sum(c) / len(c) for c in cols]
        b = sum(biases) / len(biases)
    elif AGGREGATION == "trimmed" and len(peers) > 2 * TRIM:
        w = [trimmed_mean(c, TRIM) for c in cols]
        b = trimmed_mean(biases, TRIM)
    else:
        w = [statistics.median(c) for c in cols]
        b = statistics.median(biases)
    return w, b, len(peers), ids


class Aggregator(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/update":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode())
            cid = str(data["client_id"])
            w = [float(x) for x in data["weights"]]
            if len(w) != F.DIM:
                return self._send(400, {"error": f"expected {F.DIM} weights, got {len(w)}"})
            with _lock:
                _latest[cid] = {"weights": w, "bias": float(data["bias"])}
            print(f"[update] {cid}  peers={len(_latest)}", flush=True)
            self._send(200, {"ok": True, "peers": len(_latest)})
        except Exception as exc:
            self._send(400, {"error": str(exc)})

    def do_GET(self):
        if self.path != "/weights":
            return self._send(404, {"error": "not found"})
        w, b, k, ids = aggregate()
        f_tol = max(0, (k - 1) // 2)      # median is robust only while K >= 2f+1
        self._send(200, {"weights": w, "bias": b, "n_clients": k,
                         "clients": ids, "aggregation": AGGREGATION,
                         "byzantine_tolerance": f_tol,
                         "robust": f_tol >= 1})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"[*] FedZTA Cloud Aggregator  agg={AGGREGATION}  dim={F.DIM}  port=5000",
          flush=True)
    print("[!] Coordinate-wise median requires K >= 2f+1; with fewer than 3 peers "
          "the /weights response reports byzantine_tolerance=0", flush=True)
    HTTPServer(("0.0.0.0", 5000), Aggregator).serve_forever()
