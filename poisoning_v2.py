"""Poisoning study v2: the DEPLOYED aggregation pipeline under five attacks.

Drives the real robust_cloud.norm_gate() and robust_cloud.aggregate() (imported,
not re-implemented), so the norm gate (rho = NORM_RATIO_LIMIT = 4), its
peer-median reference, stale-update behaviour, and median / trimmed-mean code
are exactly what ships. Auth, rate limiting and HTTP are out of scope: every
simulated client is assumed enrolled, i.e. f is bounded by enrolment.

Setup
  * K in {10, 20} clients, Dirichlet(alpha) non-IID source mix over
    {web benign, api benign, SQLi, XSS}, log-normal (heterogeneous) sizes.
    Payloads use the production augmentation from train_production_model.draw.
  * Clients do local minibatch logistic-regression SGD (numpy) from the latest
    global model and upload full weights, as the gateways do.
    NOTE: this is not sklearn SGDClassifier (speed); hyper-parameters differ.
  * Bootstrap global model: trained on a small clean server-held set (stand-in
    for fed_model.json); its norm seeds the gate reference.
  * Server per round: uploads arrive in random order; each passes (or skips,
    gate-off) norm_gate against the latest stored updates of the other peers;
    the aggregate over stored updates becomes the next global model. Rejected
    clients keep their previous stored update, as in the deployed server.
  * Attackers are omniscient/colluding: they see all honest uploads of the
    current round (worst case) and the previous global model.

Attacks (f malicious of K, f = round(frac*K), frac in 0,.1,.2,.3,.4)
  signflip   upload -12 * (honest-trained local weights)    [as poisoning_experiment.py]
  alie       Baruch et al. 2019: mu - z*sigma over honest uploads, per coordinate,
             pushed against sign(mu); z = Phi^-1((K-s)/K), s = floor(K/2+1) - f
  fang       Fang et al. 2020 full-knowledge attack on median / trimmed mean:
             per coordinate, deviate opposite to the benign update direction
             sign(mean_honest - prev_global), sampling within the Fang range
             (b = 2) beyond the honest max (or min)
  labelflip  data poisoning: malicious clients train honestly on flipped labels
  normbound  designed to pass the gate: -honest_mean direction, scaled to
             NORM_MARGIN * rho * (median honest norm); all colluders send it

Metrics (global model after the last round, held-out payloads disjoint from every
client): ROC-AUC (final round, worst round, mean of last 3); TPR and FPR at the deployed BLOCK_THRESHOLD (0.15); fraction of
malicious / honest uploads rejected by the gate. Mean and 95% CI (Student t)
over seeds.

Usage: python poisoning_v2.py [--seeds 8] [--rounds 10] [--out poisoning_v2_results.json]
"""
import argparse
import json
import os
import sys
import time
import multiprocessing as mp
import zlib

import numpy as np
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("FEDZTA_MODEL", os.path.join(HERE, "fed_model.json"))
os.environ.setdefault("FEDZTA_PEERS", os.path.join(HERE, "no_such_peers.json"))
sys.path.insert(0, HERE)

import fedzta_features as F          # noqa: E402
import robust_cloud as RC            # noqa: E402
import train_production_model as TPM  # noqa: E402

KS = [10, 20]
FRACS = [0.0, 0.1, 0.2, 0.3, 0.4]
ATTACKS = ["signflip", "alie", "fang", "labelflip", "normbound"]
AGGS = ["mean", "median", "trimmed"]
GATES = ["on", "off"]
DIRICHLET_ALPHA = 1.0
BASE_MIX = np.array([0.35, 0.35, 0.15, 0.15])   # web, api, sqli, xss
MIX_FLOOR = 0.1                                 # keep both labels present on every client
SIZE_MU, SIZE_SIGMA, SIZE_MIN, SIZE_MAX = np.log(450), 0.6, 120, 1500
LOCAL_EPOCHS, BATCH, LR, L2 = 10, 32, 5.0, 1e-4   # picked on seed 42 clean runs only
SIGNFLIP_BOOST = 12.0
NORM_MARGIN = 0.95
FANG_B = 2.0
N_BOOT = 300
PER_SOURCE_CAP = {"web": 6000, "api": 6000, "sqli": 3000, "xss": 3000}
N_TEST = 2000                                   # per label
THRESH = 0.15                                   # continuous_waf.BLOCK_THRESHOLD

_DATA = None


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -250, 250)))


def local_train(w, b, X, y, rng):
    w, b = w.copy(), float(b)
    n = len(y)
    for _ in range(LOCAL_EPOCHS):
        o = rng.permutation(n)
        for s in range(0, n, BATCH):
            i = o[s:s + BATCH]
            g = sigmoid(X[i] @ w + b) - y[i]
            w -= LR * (X[i].T @ g / len(i) + L2 * w)
            b -= LR * g.mean()
    return w, b


def prepare(seeds):
    """Fetch corpora once, featurise a capped sample per seed (parent process)."""
    print("[*] downloading corpora", flush=True)
    raw = {k: TPM.fetch(v) for k, v in TPM.SRC.items()}
    out = {}
    for seed in seeds:
        rng = np.random.default_rng(seed)
        pools = {k: TPM.split_pool(raw[k], rng) for k in TPM.SRC}
        lab = {"web": 0, "api": 0, "sqli": 1, "xss": 1}
        tr, te = {}, {}
        for k, (a, b) in pools.items():
            n = PER_SOURCE_CAP[k]
            tr[k] = TPM.build(TPM.draw(a, n, lab[k], rng))
            te[k] = TPM.build(TPM.draw(b, N_TEST // 2, lab[k], rng))
        Xt = np.vstack([te[k][0] for k in te]); yt = np.concatenate([te[k][1] for k in te])
        out[seed] = {"train": tr, "Xt": Xt, "yt": yt}
        print(f"    seed {seed}: featurised", flush=True)
    return out


def make_clients(seed, K, rng):
    tr = _DATA[seed]["train"]
    names = ["web", "api", "sqli", "xss"]
    clients = []
    for _ in range(K):
        p = rng.dirichlet(DIRICHLET_ALPHA * 4 * BASE_MIX)
        p = (1 - MIX_FLOOR) * p + MIX_FLOOR * BASE_MIX
        n = int(np.clip(rng.lognormal(SIZE_MU, SIZE_SIGMA), SIZE_MIN, SIZE_MAX))
        cnt = rng.multinomial(n, p)
        Xs, ys = [], []
        for nm, c in zip(names, cnt):
            X, y = tr[nm]
            idx = rng.integers(0, len(y), c)
            Xs.append(X[idx]); ys.append(y[idx])
        clients.append({"X": np.vstack(Xs), "y": np.concatenate(ys), "n": n})
    return clients


def evaluate(w, b, Xt, yt):
    from sklearn.metrics import roc_auc_score
    z = Xt @ w + b
    p = sigmoid(z)
    pos = yt == 1
    return {"auc": float(roc_auc_score(yt, z)),
            "tpr": float((p[pos] >= THRESH).mean()),
            "fpr": float((p[~pos] >= THRESH).mean())}


def craft(attack, honest_W, honest_b, prev_w, prev_b, f, K, rng):
    """Return f malicious (w, b) uploads (model-poisoning attacks only)."""
    Hw, Hb = np.array(honest_W), np.array(honest_b)
    mu_w, mu_b = Hw.mean(0), Hb.mean()
    if attack == "alie":
        s = int(np.floor(K / 2 + 1)) - f
        z = float(stats.norm.ppf(np.clip((K - s) / K, 1e-6, 1 - 1e-6)))
        sd_w, sd_b = Hw.std(0), Hb.std()
        w = mu_w - z * sd_w * np.sign(mu_w)
        b = mu_b - z * sd_b * np.sign(mu_b)
        return [(w.copy(), b)] * f
    if attack == "fang":
        s_w = np.sign(mu_w - prev_w); s_b = np.sign(mu_b - prev_b)
        out = []
        for _ in range(f):
            def one(vals, s):
                mx, mn = vals.max(0), vals.min(0)
                u = rng.uniform(1.0, FANG_B, size=np.shape(mx))
                # s=-1: benign would decrease -> push up above max; s=+1: push below min
                hi = np.where(mx > 0, mx * u, mx / u)
                lo = np.where(mn > 0, mn / u, mn * u)
                return np.where(s <= 0, hi, lo)
            out.append((one(Hw, s_w), float(one(Hb, s_b))))
        return out
    if attack == "normbound":
        ref = float(np.median(np.linalg.norm(Hw, axis=1)))
        d = -mu_w / (np.linalg.norm(mu_w) + 1e-12)
        w = d * NORM_MARGIN * RC.NORM_RATIO_LIMIT * ref
        return [(w.copy(), -mu_b * RC.NORM_RATIO_LIMIT * NORM_MARGIN)] * f
    raise ValueError(attack)


def run(seed, K, frac, attack, agg, gate, rounds, setup):
    """One FL run through the deployed robust_cloud code."""
    f = int(round(frac * K))
    rng = np.random.default_rng(zlib.crc32(repr((seed, K, frac, attack, agg, gate)).encode()))
    clients, byz, boot = setup["clients"], setup["byz_order"][:f], setup["boot"]
    byz = set(int(i) for i in byz)
    D = _DATA[seed]
    RC._latest.clear()
    RC.AGGREGATION, RC.TRIM = agg, int(os.environ.get("FEDZTA_TRIM", "1"))
    RC.BOOT_NORM = RC.l2(list(boot[0]))
    gw, gb = boot[0].copy(), float(boot[1])
    auc_hist = []
    rej_mal = tot_mal = rej_hon = tot_hon = 0
    for r in range(rounds):
        up = {}
        for c in range(K):
            cl = clients[c]
            y = 1 - cl["y"] if (c in byz and attack == "labelflip") else cl["y"]
            lr_rng = np.random.default_rng(seed * 100003 + c * 1009 + r)
            up[c] = local_train(gw, gb, cl["X"], y, lr_rng)
        model_byz = [c for c in byz] if attack in ("signflip", "alie", "fang", "normbound") else []
        if attack == "signflip":
            for c in model_byz:
                up[c] = (-SIGNFLIP_BOOST * up[c][0], -SIGNFLIP_BOOST * up[c][1])
        elif model_byz:
            hon = [c for c in range(K) if c not in byz]
            crafted = craft(attack, [up[c][0] for c in hon], [up[c][1] for c in hon],
                            gw, gb, len(model_byz), K, rng)
            for c, m in zip(model_byz, crafted):
                up[c] = m
        for c in rng.permutation(K):
            c = int(c)
            w, b = up[c]
            ok = True
            if gate == "on":
                ok, _ = RC.norm_gate(str(c), [float(x) for x in w])
            if c in byz:
                tot_mal += 1; rej_mal += (not ok)
            else:
                tot_hon += 1; rej_hon += (not ok)
            if ok:
                RC._latest[str(c)] = {"weights": [float(x) for x in w], "bias": float(b), "ts": r}
        aw, ab, _, _ = RC.aggregate()
        gw, gb = np.array(aw), float(ab)
        auc_hist.append(evaluate(gw, gb, D["Xt"], D["yt"])["auc"])
    m = evaluate(gw, gb, D["Xt"], D["yt"])
    # final-round AUC can be an oscillation artefact (the mean aggregator can flip
    # sign each round), so also keep the per-round history and its minimum.
    m["auc_rounds"] = auc_hist
    m["auc_worst"] = float(min(auc_hist))
    m["auc_last3"] = float(np.mean(auc_hist[-3:]))
    m["gate_reject_malicious"] = rej_mal / tot_mal if tot_mal else None
    m["gate_reject_honest"] = rej_hon / tot_hon if tot_hon else None
    return m


def seed_task(args):
    seed, rounds = args
    out, t0 = [], time.time()
    D = _DATA[seed]
    for K in KS:
        srng = np.random.default_rng(seed * 7 + K)
        clients = make_clients(seed, K, srng)
        byz_order = srng.permutation(K)
        # bootstrap: small clean server-held set (stand-in for the shipped fed_model.json)
        tr = D["train"]
        Xb = np.vstack([tr[k][0][:N_BOOT // 4] for k in tr]); yb = np.concatenate([tr[k][1][:N_BOOT // 4] for k in tr])
        boot = local_train(np.zeros(F.DIM), 0.0, Xb, yb, np.random.default_rng(seed))
        # pooled reference: all client data, centrally trained
        Xp = np.vstack([c["X"] for c in clients]); yp = np.concatenate([c["y"] for c in clients])
        pw, pb = np.zeros(F.DIM), 0.0
        for e in range(3):
            pw, pb = local_train(pw, pb, Xp, yp, np.random.default_rng(seed + e))
        ref = evaluate(pw, pb, D["Xt"], D["yt"]); ref.update(seed=seed, K=K, kind="pooled_reference")
        out.append(ref)
        bm = evaluate(boot[0], boot[1], D["Xt"], D["yt"]); bm.update(seed=seed, K=K, kind="bootstrap_model")
        out.append(bm)
        setup = {"clients": clients, "byz_order": byz_order, "boot": boot}
        for agg in AGGS:
            for gate in GATES:
                for fr in FRACS:
                    for att in (["none"] if fr == 0 else ATTACKS):
                        m = run(seed, K, fr, att, agg, gate, rounds, setup)
                        m.update(seed=seed, K=K, frac=fr, f=int(round(fr * K)), attack=att,
                                 agg=agg, gate=gate, kind="fl")
                        out.append(m)
    print(f"    seed {seed} done in {time.time() - t0:.0f}s", flush=True)
    return out


def ci(vals):
    v = np.array([x for x in vals if x is not None], dtype=float)
    if len(v) == 0:
        return None
    n = len(v)
    mean = float(v.mean())
    h = float(stats.t.ppf(0.975, n - 1) * v.std(ddof=1) / np.sqrt(n)) if n > 1 else float("nan")
    return {"mean": mean, "ci95": h, "n": n}


def summarise(rows):
    cells = {}
    for r in rows:
        if r["kind"] != "fl":
            continue
        key = (r["K"], r["agg"], r["gate"], r["attack"], r["frac"])
        cells.setdefault(key, []).append(r)
    summ = []
    for (K, agg, gate, att, fr), rs in sorted(cells.items()):
        summ.append({"K": K, "agg": agg, "gate": gate, "attack": att, "frac": fr,
                     "f": rs[0]["f"], "n_seeds": len(rs),
                     **{m: ci([x[m] for x in rs]) for m in
                        ("auc", "auc_worst", "auc_last3", "tpr", "fpr", "gate_reject_malicious", "gate_reject_honest")}})
    refs = {}
    for r in rows:
        if r["kind"] in ("pooled_reference", "bootstrap_model"):
            refs.setdefault((r["kind"], r["K"]), []).append(r)
    ref_s = [{"kind": k, "K": K, **{m: ci([x[m] for x in rs]) for m in ("auc", "tpr", "fpr")}}
             for (k, K), rs in sorted(refs.items())]
    return summ, ref_s


def main():
    global _DATA
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=8)
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--workers", type=int, default=os.cpu_count())
    ap.add_argument("--out", default=os.path.join(HERE, "poisoning_v2_results.json"))
    a = ap.parse_args()
    seeds = list(range(42, 42 + a.seeds))
    _DATA = prepare(seeds)
    t0 = time.time()
    with mp.get_context("fork").Pool(min(a.workers, len(seeds))) as p:      # fork: children inherit _DATA
        parts = p.map(seed_task, [(s, a.rounds) for s in seeds])
    rows = [r for part in parts for r in part]
    summ, refs = summarise(rows)
    cfg = {"seeds": seeds, "rounds": a.rounds, "Ks": KS, "fracs": FRACS, "attacks": ATTACKS,
           "aggregators": AGGS, "gate": GATES, "norm_ratio_limit": RC.NORM_RATIO_LIMIT,
           "trim": int(os.environ.get("FEDZTA_TRIM", "1")), "block_threshold": THRESH,
           "dirichlet_alpha": DIRICHLET_ALPHA, "base_mix_web_api_sqli_xss": BASE_MIX.tolist(),
           "mix_floor": MIX_FLOOR, "client_size_lognormal": [float(SIZE_MU), SIZE_SIGMA, SIZE_MIN, SIZE_MAX],
           "local": {"epochs": LOCAL_EPOCHS, "batch": BATCH, "lr": LR, "l2": L2},
           "signflip_boost": SIGNFLIP_BOOST, "normbound_margin": NORM_MARGIN, "fang_b": FANG_B,
           "n_bootstrap_samples": N_BOOT, "dim": F.DIM, "runtime_s": time.time() - t0,
           "ci": "95% Student-t over seeds"}
    with open(a.out, "w") as fh:
        json.dump({"config": cfg, "references": refs, "summary": summ, "runs": rows}, fh, indent=1)
    print(f"[+] wrote {a.out}  ({len(rows)} runs, {time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
