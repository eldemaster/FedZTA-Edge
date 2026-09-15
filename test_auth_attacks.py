"""Adversarial tests against the live FedZTA control plane.

Each case is an attack the previous, unauthenticated aggregator accepted.
Attacks that would alter the global model are constructed to be rejected; the
one case that is legitimately accepted replays the current global weights, so
running this suite does not move the deployed model.
"""
import json
import time
import urllib.error
import urllib.request

import fedzta_auth as AUTH

import os
CLOUD = os.environ.get("FEDZTA_CLOUD", "http://localhost:5000")


RATE_WINDOW_S = 6


def post_when_allowed(build, tries=5):
    """Send, retrying past the per-identity rate limiter.

    The live gateways sync on their own schedule, so a test send can collide with
    one and draw a 429 that has nothing to do with the case under test.

    `build` must be a callable returning a FRESH message: retrying with the same
    message replays its nonce, and the replay guard would reject the retry with
    401 before the case under test was ever reached.
    """
    for _ in range(tries):
        code, body = post(build())
        if code != 429:
            return code, body
        time.sleep(RATE_WINDOW_S)
    return 429, "still rate limited"


def post(obj):
    req = urllib.request.Request(f"{CLOUD}/update",
                                 data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()[:80]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:80]
    except Exception as e:
        return 0, str(e)[:80]


def globals_now():
    with urllib.request.urlopen(f"{CLOUD}/weights", timeout=10) as r:
        return json.loads(r.read().decode())


def main():
    peers = {k: v["secret"] for k, v in json.load(open("peers.json")).items()}
    secret = peers["edge-web"]
    g = globals_now()
    w, b = g["weights"], g["bias"]

    print(f"{'#':>2}  {'attack':<44}{'expect':>8}{'got':>6}  result")
    print("-" * 78)
    results = []

    def case(n, name, build, expect):
        # The rate limiter runs before the dimension, finiteness and norm checks,
        # so a case expecting one of those verdicts must first clear the window.
        # Cases that expect 429 are asserting the limiter itself.
        code, _ = post(build()) if expect == 429 else post_when_allowed(build)
        ok = code == expect
        results.append(ok)
        print(f"{n:>2}  {name:<44}{expect:>8}{code:>6}  {'PASS' if ok else 'FAIL'}")

    # 1. the exact message format the previous aggregator accepted
    case(1, "unsigned update (old wire format)",
         lambda: {"client_id": "edge-web", "weights": w, "bias": b, "n_samples": 1}, 401)

    # 2. sybil: unenrolled identity, correctly signed with its own fresh secret
    rogue = AUTH.new_secret()
    case(2, "sybil identity, self-signed",
         lambda: AUTH.build_update("attacker-1", w, b, 1, rogue), 401)

    # 3. forged signature on a real identity
    def forged():
        m = AUTH.build_update("edge-web", w, b, 1, secret)
        m["sig"] = "0" * 64
        return m
    case(3, "forged signature on enrolled identity", forged, 401)

    # 4. tampered payload under a captured-looking signature
    def tampered():
        m = AUTH.build_update("edge-web", w, b, 1, secret)
        m["body"]["weights"] = [x * -12.0 for x in w]
        return m
    case(4, "tampered weights, stale signature", tampered, 401)

    # 5. replay of a valid message. The nonce is consumed during verification,
    #    which happens before the rate-limit check, so a message that draws a 429
    #    can never be retried as-is -- its nonce is already spent. Build a fresh
    #    message per attempt and replay whichever one was actually accepted.
    msg, first = None, None
    for _ in range(5):
        candidate = AUTH.build_update("edge-web", w, b, 1, secret)
        first, _ = post(candidate)
        if first == 200:
            msg = candidate
            break
        time.sleep(RATE_WINDOW_S)
    time.sleep(RATE_WINDOW_S)
    code, _ = post(msg) if msg else (0, "never accepted")
    ok = first == 200 and code == 401
    results.append(ok)
    print(f"{5:>2}  {'replay of a captured valid update':<44}{401:>8}{code:>6}  "
          f"{'PASS' if ok else 'FAIL'}  (first send {first})")

    # 6. stale timestamp outside the acceptance window
    case(6, "valid signature, timestamp 1h old",
         lambda: AUTH.build_update("edge-web", w, b, 1, secret, now=time.time() - 3600), 401)

    # 7. rate limit -- establish an accepted update, then immediately resend
    post_when_allowed(lambda: AUTH.build_update("edge-web", w, b, 1, secret))
    case(7, "second update inside the rate-limit window",
         lambda: AUTH.build_update("edge-web", w, b, 1, secret), 429)

    # 8. scaled-weight poisoning from a genuinely enrolled gateway
    case(8, "enrolled peer sends 50x scaled weights",
         lambda: AUTH.build_update("edge-web", [x * 50.0 for x in w], b * 50.0, 1, secret), 409)

    # 9. wrong dimension
    case(9, "enrolled peer sends wrong dimension",
         lambda: AUTH.build_update("edge-web", w[:10], b, 1, secret), 400)

    # 10. non-finite parameters
    def nan():
        m = AUTH.build_update("edge-web", w, b, 1, secret)
        m["body"]["weights"] = ["NaN"] * len(w)
        m["sig"] = AUTH.sign(m["body"], secret)
        return m
    case(10, "enrolled peer sends NaN weights", nan, 400)

    print("-" * 78)
    print(f"{sum(results)}/{len(results)} attacks correctly handled")

    after = globals_now()
    moved = any(abs(x - y) > 1e-12 for x, y in zip(w, after["weights"]))
    print(f"global model altered by this suite: {'YES' if moved else 'no'}")
    print(f"peers={after['n_clients']} {after['clients']} "
          f"byzantine_tolerance={after['byzantine_tolerance']}")


if __name__ == "__main__":
    main()
