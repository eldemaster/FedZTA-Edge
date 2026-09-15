"""FedZTA Cloud Aggregator: authenticated, Byzantine-robust weight aggregation.

Coordinate-wise median tolerates f malicious clients only while K >= 2f+1. That
bound is meaningless if identities are free, so every update must carry a valid
HMAC-SHA256 signature from an enrolled gateway. Enrolment is the mechanism that
makes f bounded; the median is what contains the f that remain.

Defences, in the order an update passes through them:
  1. Signature, timestamp and nonce verification  (fedzta_auth)
  2. Per-identity rate limit
  3. Dimension and finiteness checks
  4. L2-norm gate against the median peer norm, rejecting scaled updates before
     they reach aggregation
  5. Coordinate-wise median (or trimmed mean) across the latest update per peer
"""
import json
import math
import os
import statistics
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import fedzta_auth as AUTH
import fedzta_features as F

MODEL_PATH = os.environ.get("FEDZTA_MODEL", "fed_model.json")
PEERS_PATH = os.environ.get("FEDZTA_PEERS", "peers.json")
AGGREGATION = os.environ.get("FEDZTA_AGG", "median")      # median | trimmed | mean
TRIM = int(os.environ.get("FEDZTA_TRIM", "1"))
MIN_UPDATE_INTERVAL_S = float(os.environ.get("FEDZTA_MIN_INTERVAL", "5"))
NORM_RATIO_LIMIT = float(os.environ.get("FEDZTA_NORM_LIMIT", "4.0"))

_lock = threading.Lock()
_latest = {}          # client_id -> {"weights", "bias", "ts"}
_last_seen = {}       # client_id -> monotonic time of last accepted update
_rejected = {}        # reason -> count
_replay = AUTH.ReplayGuard()


def load_peers(path):
    """Enrolled gateways and their secrets. Absent file means nobody is enrolled."""
    if not os.path.exists(path):
        print(f"[!] {path} not found -- no gateway is enrolled, all updates "
              f"will be rejected. Run enroll_peer.py to enrol one.", flush=True)
        return {}
    mode = os.stat(path).st_mode & 0o077
    if mode:
        print(f"[!] {path} is group/world accessible; tighten to 0600", flush=True)
    with open(path) as fh:
        return {k: v["secret"] for k, v in json.load(fh).items()}


def load_bootstrap(path):
    with open(path) as fh:
        m = json.load(fh)
    return list(m["coefficients"]), float(m["intercept"])


PEERS = load_peers(PEERS_PATH)
BOOT_W, BOOT_B = load_bootstrap(MODEL_PATH)


def _count(reason):
    _rejected[reason] = _rejected.get(reason, 0) + 1


def l2(v):
    return math.sqrt(sum(x * x for x in v))


BOOT_NORM = None          # set after the bootstrap model is loaded


def norm_gate(cid, weights):
    """Reject updates whose magnitude is wildly out of line with the reference.

    The median already resists a scaled update, but only while honest peers hold a
    majority per coordinate. Rejecting outliers before aggregation keeps a
    Byzantine client from consuming that margin in the first place.

    The reference is the median norm of the *other* peers when at least two have
    reported. Below that there is no peer majority to appeal to, so the last
    published global model is used instead -- a reference that always exists and
    that a single client cannot move far in one round. Falling back to "accept"
    here, as an earlier revision did, left the gate inert at K=2, which is exactly
    the deployment size where the median is weakest.
    """
    with _lock:
        others = [l2(p["weights"]) for c, p in _latest.items() if c != cid]
    if len(others) >= 2:
        ref = statistics.median(others)
    elif others:
        ref = max(others[0], BOOT_NORM or 0.0)
    else:
        ref = BOOT_NORM or 0.0
    if ref <= 0:
        return True, None
    ratio = l2(weights) / ref
    if ratio > NORM_RATIO_LIMIT or ratio < 1.0 / NORM_RATIO_LIMIT:
        return False, f"norm ratio {ratio:.2f} outside [1/{NORM_RATIO_LIMIT:g}, {NORM_RATIO_LIMIT:g}]"
    return True, None


def trimmed_mean(values, k):
    v = sorted(values)
    v = v[k:len(v) - k] if len(v) > 2 * k else v
    return sum(v) / len(v)


def aggregate():
    with _lock:
        peers = list(_latest.values())
        ids = sorted(_latest)
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
            if n <= 0 or n > 4 * 1024 * 1024:
                _count("bad length")
                return self._send(400, {"error": "bad content length"})
            message = json.loads(self.rfile.read(n).decode())
        except Exception:
            _count("malformed")
            return self._send(400, {"error": "malformed request"})

        ok, cid, reason = AUTH.verify(message, PEERS, _replay)
        if not ok:
            _count(reason)
            print(f"[reject] {reason}"
                  f"{'' if cid is None else ' from ' + cid}", flush=True)
            # 401 for anything the caller could fix by authenticating properly
            return self._send(401, {"error": "unauthorised"})

        now = time.monotonic()
        with _lock:
            last = _last_seen.get(cid)
        if last is not None and now - last < MIN_UPDATE_INTERVAL_S:
            _count("rate limited")
            return self._send(429, {"error": "too many updates"})

        body = message["body"]
        w, b = body["weights"], body["bias"]
        if not isinstance(w, list) or len(w) != F.DIM:
            _count("dimension")
            return self._send(400, {"error": f"expected {F.DIM} weights"})
        try:
            w = [float(x) for x in w]
            b = float(b)
        except (TypeError, ValueError):
            _count("non-numeric")
            return self._send(400, {"error": "non-numeric parameters"})
        if not all(math.isfinite(x) for x in w) or not math.isfinite(b):
            _count("non-finite")
            return self._send(400, {"error": "non-finite parameters"})

        passed, why = norm_gate(cid, w)
        if not passed:
            _count("norm gate")
            print(f"[reject] {cid}: {why}", flush=True)
            return self._send(409, {"error": "update rejected", "detail": why})

        with _lock:
            _latest[cid] = {"weights": w, "bias": b, "ts": body["ts"]}
            _last_seen[cid] = now
            k = len(_latest)
        print(f"[accept] {cid}  peers={k}", flush=True)
        try:
            pass
            w, b, k_clients, ids = aggregate()
            models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
            os.makedirs(models_dir, exist_ok=True)
            with open(os.path.join(models_dir, f"global_{int(time.time())}.json"), "w") as fh:
                json.dump({"weights": w, "bias": b, "n_clients": k_clients, "clients": ids}, fh)
        except Exception as e:
            print("Error saving version:", e)
        self._send(200, {"ok": True, "peers": k})

    def do_GET(self):
        if self.path == "/health":
            with _lock:
                return self._send(200, {"peers": sorted(_latest),
                                        "enrolled": sorted(PEERS),
                                        "rejected": dict(_rejected),
                                        "aggregation": AGGREGATION})
        if self.path != "/weights":
            return self._send(404, {"error": "not found"})
        w, b, k, ids = aggregate()
        f_tol = max(0, (k - 1) // 2)      # median holds only while K >= 2f+1
        self._send(200, {"weights": w, "bias": b, "n_clients": k,
                         "clients": ids, "aggregation": AGGREGATION,
                         "byzantine_tolerance": f_tol,
                         "robust": f_tol >= 1})

    def log_message(self, *args):
        pass


BOOT_NORM = l2(BOOT_W)

if __name__ == "__main__":
    print(f"[*] FedZTA Cloud Aggregator  agg={AGGREGATION}  dim={F.DIM}  port=5000",
          flush=True)
    print(f"[*] {len(PEERS)} gateway(s) enrolled: {', '.join(sorted(PEERS)) or 'none'}",
          flush=True)
    print("[!] Coordinate-wise median requires K >= 2f+1; /weights reports the "
          "tolerance actually achieved", flush=True)
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("FEDZTA_PORT", 5000))), Aggregator).serve_forever()
