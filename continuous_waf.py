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
  * Updates are signed with HMAC-SHA256 under an enrolment secret. An aggregator
    that accepts unauthenticated updates has an unbounded f, which makes its
    Byzantine guarantee vacuous no matter how robust the aggregation rule is.
"""
import json
import os
import shutil
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import fedzta_auth as AUTH
import fedzta_features as F

CLOUD_URL = os.environ.get("FEDZTA_CLOUD", "http://localhost:5000")
MODEL_PATH = os.environ.get("FEDZTA_MODEL", "fed_model.json")
SECRET_PATH = os.environ.get("FEDZTA_SECRET", "gateway_secret.json")
SYNC_INTERVAL = float(os.environ.get("FEDZTA_SYNC", "15"))
LEARNING_RATE = 0.05
BLOCK_THRESHOLD = 0.15
SHADOW_MODE = os.environ.get("FEDZTA_SHADOW", "0") == "1"
FAIL_OPEN = os.environ.get("FEDZTA_FAIL_OPEN", "1") == "1"
LOCAL_WEIGHTS = "local_weights.json"
METRICS = {"requests": 0, "blocks": 0, "shadow_blocks": 0}
METRICS_LOCK = threading.Lock()


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
            return {"weights": list(self.weights), "bias": self.bias,
                    "n_samples": self.local_updates}

    def load(self, weights, bias):
        with self.lock:
            self.weights = list(weights)
            self.bias = float(bias)
            self.local_updates = 0


def load_secret(path):
    """Enrolment credential issued by enroll_peer.py. Fail closed if absent: a
    gateway that cannot authenticate must not fall back to unsigned updates."""
    if not os.path.exists(path):
        raise SystemExit(f"no enrolment secret at {path}; run enroll_peer.py "
                         f"on the aggregator and deploy the gateway half")
    if os.stat(path).st_mode & 0o077:
        print(f"[!] {path} is group/world accessible; tighten to 0600", flush=True)
    with open(path) as fh:
        cfg = json.load(fh)
    return cfg["client_id"], cfg["secret"]


def load_model(path):
    with open(path) as fh:
        m = json.load(fh)
    cfg = m.get("config", {})
    if cfg.get("dim") and cfg["dim"] != F.DIM:
        raise SystemExit(f"model dim {cfg['dim']} != feature dim {F.DIM}")
    return m["coefficients"], m["intercept"]


def load_local_model():
    if os.path.exists(LOCAL_WEIGHTS):
        try:
            with open(LOCAL_WEIGHTS) as f:
                m = json.load(f)
                return m["weights"], m["bias"]
        except Exception:
            pass
    return load_model(MODEL_PATH)

CLIENT_ID, SECRET = load_secret(SECRET_PATH)
classifier = ContinuousSGD(*load_local_model())


class Gateway(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 5
    
    def inspect_request(self, method):
        try:
            self._inspect_request(method)
        except Exception as e:
            if FAIL_OPEN:
                body = b'{"blocked": false, "error": "fail_open"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            else:
                body = b'{"blocked": true, "error": "fail_closed"}'
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

    def _inspect_request(self, method):
        if self.path == '/health':
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = b'{"status": "ok"}'
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps(METRICS).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
            
        with METRICS_LOCK:
            METRICS["requests"] += 1
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.unquote(parsed.query)
        contexts = []
        if parsed.path:
            contexts.append(parsed.path)
        if query:
            contexts.append(query)
        
        # Extract headers
        for h in ['User-Agent', 'Referer', 'Cookie']:
            val = self.headers.get(h)
            if val:
                contexts.append(val)
                
        # Read body for POST/PUT up to 8KB
        if method in ['POST', 'PUT']:
            try:
                length = int(self.headers.get('Content-Length', 0))
            except ValueError:
                self.send_error(400, "Bad Request")
                return
            if length > 0:
                length = min(length, 8192) # 8 KB cap
                body_payload = self.rfile.read(length).decode(errors='ignore')
                if body_payload:
                    contexts.append(body_payload)
                    
        max_prob = 0.0
        best_features = None
        
        # Score each context independently
        for ctx in contexts:
            features = F.extract(ctx)
            prob = classifier.predict(features)
            
            # Active Learning (Pseudo-labeling) REMOVED to prevent Model Drift.
            # Local updates should only occur via a verified Anchor Set or Honeypot.
            pass
                
            if prob > max_prob:
                max_prob = prob
                best_features = features
                
        blocked = max_prob >= BLOCK_THRESHOLD
        
        if blocked:
            with METRICS_LOCK:
                if SHADOW_MODE:
                    METRICS["shadow_blocks"] += 1
                else:
                    METRICS["blocks"] += 1

        body = json.dumps({"blocked": blocked, "probability": round(max_prob, 6),
                           "client_id": CLIENT_ID, "shadow_mode": SHADOW_MODE}).encode()
        if SHADOW_MODE:
            self.send_response(200) # Never block in shadow mode
        else:
            self.send_response(403 if blocked else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.inspect_request("GET")
        
    def do_POST(self):
        self.inspect_request("POST")
        
    def do_PUT(self):
        self.inspect_request("PUT")

    def log_message(self, *args):
        pass


def sync_loop():
    while True:
        time.sleep(SYNC_INTERVAL)
        try:
            snap = classifier.snapshot()
            message = AUTH.build_update(CLIENT_ID, snap["weights"], snap["bias"],
                                        snap["n_samples"], SECRET)
            payload = json.dumps(message).encode()
            req = urllib.request.Request(f"{CLOUD_URL}/update", data=payload,
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
            urllib.request.urlopen(req, timeout=10).read()
            with urllib.request.urlopen(f"{CLOUD_URL}/weights", timeout=10) as r:
                g = json.loads(r.read().decode())
            if len(g["weights"]) == F.DIM:
                classifier.load(g["weights"], g["bias"])
                import tempfile
                with tempfile.NamedTemporaryFile('w', delete=False) as tf:
                    json.dump({"weights": g["weights"], "bias": g["bias"]}, tf)
                    tf.flush()
                    os.fsync(tf.fileno())
                shutil.move(tf.name, LOCAL_WEIGHTS)
                print(f"[sync] global model applied from {g.get('n_clients', '?')} peers and persisted to disk",
                      flush=True)
            else:
                print(f"[sync] dim mismatch {len(g['weights'])} != {F.DIM}", flush=True)
        except urllib.error.HTTPError as exc:
            detail = {401: "rejected: gateway not enrolled or bad signature",
                      429: "rejected: rate limited",
                      409: "rejected: update failed the norm gate"}.get(
                          exc.code, f"HTTP {exc.code}")
            print(f"[sync] {detail}", flush=True)
        except Exception as exc:
            print(f"[sync] failed: {exc}", flush=True)



def anchor_set_loop():
    while True:
        import time
        time.sleep(60)
        try:
            import os
            if os.path.exists("anchor_set.json"):
                import json
                with open("anchor_set.json") as f:
                    data = json.load(f)
                for item in data:
                    features = F.extract(item["payload"])
                    classifier.partial_fit(features, item["label"])
                print(f"[anchor] Replayed {len(data)} verified samples", flush=True)
        except Exception:
            pass

if __name__ == "__main__":
    threading.Thread(target=anchor_set_loop, daemon=True).start()
    print(f"[*] FedZTA Edge Gateway  id={CLIENT_ID}  dim={F.DIM}  cloud={CLOUD_URL}",
          flush=True)
    threading.Thread(target=sync_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Gateway).serve_forever()
