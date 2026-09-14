"""FedZTA Edge Gateway: continuous-learning WAF for an ARM IoT node.

Pure Python, zero dependencies. Inspects every request with the federated global
model, trains locally on the outcome, and periodically exchanges only model
weights with the Cloud Aggregator -- never raw payloads.

Changes over the previous revision:
  * Feature transform comes from fedzta_features, shared verbatim with the Cloud,
    so Edge and Cloud bucket n-grams identically. Previously the Edge used a
    3-feature vector while the simulation that produced the published results
    used a different 4-feature one.
  * Initial weights are loaded from fed_model.json rather than hardcoded. The
    previous hardcoded vector classified 100% of traffic as malicious.
  * Every upload carries a stable client_id so the Aggregator can take a median
    across peers instead of across a time window.
"""
import json
import os
import socket
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import fedzta_features as F

CLOUD_URL = os.environ.get("FEDZTA_CLOUD", "http://192.168.1.144:5000")
CLIENT_ID = os.environ.get("FEDZTA_CLIENT_ID", socket.gethostname())
MODEL_PATH = os.environ.get("FEDZTA_MODEL", "fed_model.json")
SYNC_INTERVAL = float(os.environ.get("FEDZTA_SYNC", "15"))
LEARNING_RATE = 0.05
BLOCK_THRESHOLD = 0.5


class ContinuousSGD:
    def __init__(self, coef, intercept):
        self.weights = list(coef)
        self.bias = float(intercept)
        self.local_updates = 0
        self.lock = threading.Lock()

    def predict(self, features):
        return F.predict_proba(features, self.weights, self.bias)

    def partial_fit(self, features, label):
        with self.lock:
            error = F.predict_proba(features, self.weights, self.bias) - label
            for i, f in enumerate(features):
                self.weights[i] -= LEARNING_RATE * error * f
            self.bias -= LEARNING_RATE * error
            self.local_updates += 1

    def snapshot(self):
        with self.lock:
            return {"client_id": CLIENT_ID, "weights": list(self.weights),
                    "bias": self.bias, "n_samples": self.local_updates}

    def load(self, weights, bias):
        with self.lock:
            self.weights = list(weights)
            self.bias = float(bias)
            self.local_updates = 0


def load_model(path):
    with open(path) as fh:
        m = json.load(fh)
    cfg = m.get("config", {})
    if cfg.get("dim") and cfg["dim"] != F.DIM:
        raise SystemExit(f"model dim {cfg['dim']} != feature dim {F.DIM}")
    return m["coefficients"], m["intercept"]


classifier = ContinuousSGD(*load_model(MODEL_PATH))


def label_of(payload):
    """Weak supervision for the continuous-learning loop.

    The model's own confident predictions are used as pseudo-labels. This is an
    acknowledged limitation, not ground truth -- see the Discussion section.
    """
    p = classifier.predict(F.extract(payload))
    return 1 if p >= 0.9 else (0 if p <= 0.1 else None)


class Gateway(BaseHTTPRequestHandler):
    # HTTP/1.1 keep-alive on a single-threaded server serialises concurrent
    # connections: each client holds the one handler thread until it disconnects,
    # so throughput collapses to roughly one connection at a time. A threading
    # server is what a gateway would actually deploy.
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.unquote(parsed.query)
        payload = f"GET {parsed.path}?{query}" if query else f"GET {parsed.path}"

        features = F.extract(payload)
        prob = classifier.predict(features)
        blocked = prob >= BLOCK_THRESHOLD

        lbl = 1 if prob >= 0.9 else (0 if prob <= 0.1 else None)
        if lbl is not None:
            classifier.partial_fit(features, lbl)

        body = json.dumps({"blocked": blocked, "probability": round(prob, 6),
                           "client_id": CLIENT_ID}).encode()
        self.send_response(403 if blocked else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def sync_loop():
    while True:
        time.sleep(SYNC_INTERVAL)
        try:
            payload = json.dumps(classifier.snapshot()).encode()
            req = urllib.request.Request(f"{CLOUD_URL}/update", data=payload,
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
            urllib.request.urlopen(req, timeout=10).read()
            with urllib.request.urlopen(f"{CLOUD_URL}/weights", timeout=10) as r:
                g = json.loads(r.read().decode())
            if len(g["weights"]) == F.DIM:
                classifier.load(g["weights"], g["bias"])
                print(f"[sync] global model applied from {g.get('n_clients', '?')} peers",
                      flush=True)
            else:
                print(f"[sync] dim mismatch {len(g['weights'])} != {F.DIM}", flush=True)
        except Exception as exc:
            print(f"[sync] failed: {exc}", flush=True)


if __name__ == "__main__":
    print(f"[*] FedZTA Edge Gateway  id={CLIENT_ID}  dim={F.DIM}  cloud={CLOUD_URL}",
          flush=True)
    threading.Thread(target=sync_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Gateway).serve_forever()
