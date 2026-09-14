"""Measured bandwidth comparison: centralised log shipping vs federated weights.

The previous analysis compared a one-shot raw upload against a SINGLE round of
weights from a SINGLE node, and quoted a dataset size that appears in the paper
as three different numbers. This measures the actual payload bytes of the
training corpus and charges federation for every round, every node and both
directions.
"""
import json
import urllib.request

import fedzta_features as F

RAW = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
ROUNDS, K_NODES = 20, 2
N_BENIGN, N_ATTACK = 3000, 1000


def fetch(paths):
    out = []
    for p in paths:
        with urllib.request.urlopen(RAW + p, timeout=90) as r:
            out += [l.decode("utf-8", "ignore").strip() for l in r if l.strip()]
    return sorted(set(out))


def main():
    cfg = json.load(open("fed_model.json"))["config"]
    web = fetch(["Discovery/Web-Content/raft-small-words.txt"])
    api = fetch(["Discovery/Web-Content/api/api-seen-in-wild.txt",
                 "Discovery/Web-Content/api/api-endpoints.txt",
                 "Discovery/Web-Content/graphql.txt"])
    sqli = fetch(["Fuzzing/Databases/SQLi/Generic-SQLi.txt"])
    xss = fetch(["Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
                 "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
                 "Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt",
                 "Fuzzing/XSS/robot-friendly/XSS-Somdev.txt",
                 "Fuzzing/XSS/robot-friendly/XSS-Vectors-Mario.txt",
                 "Fuzzing/XSS/robot-friendly/XSS-EnDe-xssAttacks.txt"])

    def mean_len(pool):
        return sum(len(f"GET /search?q={p}") for p in pool) / len(pool)

    per_node = N_BENIGN * mean_len(web) + N_ATTACK * mean_len(xss + sqli)
    centralised = per_node + (N_BENIGN * mean_len(api) + N_ATTACK * mean_len(xss + sqli))

    update = (cfg["dim"] + 1) * 4
    federated = ROUNDS * K_NODES * 2 * update       # upload + broadcast, every round

    print(f"Mean request length: web {mean_len(web):.1f} B | api {mean_len(api):.1f} B "
          f"| sqli {mean_len(sqli):.1f} B | xss {mean_len(xss):.1f} B")
    print(f"\nCentralised log shipping")
    print(f"  {K_NODES} nodes x {N_BENIGN + N_ATTACK} requests, raw payloads")
    print(f"  total {centralised / 1024:.1f} KB")
    print(f"\nFederated weight exchange")
    print(f"  {cfg['dim']} coefficients + 1 intercept = {update} B per update")
    print(f"  {ROUNDS} rounds x {K_NODES} nodes x 2 directions")
    print(f"  total {federated / 1024:.1f} KB")
    red = 100.0 * (1 - federated / centralised)
    print(f"\nReduction: {red:.2f}%  ({centralised / federated:.0f}x less traffic)")
    print(f"Per-round steady-state cost: {K_NODES * 2 * update} B "
          f"({K_NODES * 2 * update / 1024:.2f} KB)")

    # Steady-state operation: the centralised cost grows with inspected traffic,
    # while the federated cost is fixed per synchronisation regardless of volume.
    MEAN_REQ = (mean_len(web) + mean_len(api)) / 2
    print("\n" + "=" * 74)
    print("STEADY-STATE DAILY COST, 2 gateways, by sustained request rate")
    print("=" * 74)
    print(f"{'rate':>10}{'requests/day':>16}{'centralised':>14}{'federated':>13}{'reduction':>12}")
    scenarios = []
    for rate, sync_s in ((10, 300), (100, 300), (452, 300), (452, 15)):
        per_day = rate * 86400 * K_NODES
        cen = per_day * MEAN_REQ
        fed = (86400 / sync_s) * K_NODES * 2 * update
        r = 100.0 * (1 - fed / cen)
        scenarios.append({"rate_rps": rate, "sync_s": sync_s, "centralised_bytes": cen,
                          "federated_bytes": fed, "reduction_pct": r})
        print(f"{rate:>7} rps{per_day:>16,}{cen / 1e6:>11.1f} MB"
              f"{fed / 1e6:>10.1f} MB{r:>11.2f}%")
    print("=" * 74)
    print(f"Federated cost is constant at {(86400/300)*K_NODES*2*update/1e6:.1f} MB/day "
          f"(5 min sync) no matter how much traffic each gateway inspects.")
    print(f"Break-even: centralised is cheaper only below "
          f"{((86400/300)*K_NODES*2*update)/(MEAN_REQ*86400*K_NODES):.2f} req/s per node.")

    res = {"scenarios": scenarios, "centralised_bytes": centralised, "federated_bytes": federated,
           "update_bytes": update, "rounds": ROUNDS, "nodes": K_NODES,
           "reduction_pct": red, "mean_request_bytes": MEAN_REQ}
    json.dump(res, open("bandwidth_results.json", "w"), indent=2)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        rates = [10 ** (i / 8.0) for i in range(-8, 25)]
        cen_d = [r * 86400 * K_NODES * MEAN_REQ / 1e6 for r in rates]
        fed_d = [(86400 / 300) * K_NODES * 2 * update / 1e6] * len(rates)
        fig, ax = plt.subplots(figsize=(7.5, 5))
        ax.loglog(rates, cen_d, "-", color="#d62728", lw=2,
                  label="Centralised log shipping")
        ax.loglog(rates, fed_d, "-", color="#2ca02c", lw=2,
                  label=f"Federated weights ({update} B, 5 min sync)")
        cross = fed_d[0] * 1e6 / (86400 * K_NODES * MEAN_REQ)
        ax.axvline(cross, color="gray", ls=":", label=f"break-even {cross:.2f} req/s")
        ax.axvline(452, color="#1f77b4", ls="--", alpha=0.7,
                   label="measured gateway throughput 452 req/s")
        ax.set_xlabel("Sustained request rate per gateway (req/s)", fontsize=11)
        ax.set_ylabel("Data to the Cloud per day (MB, log scale)", fontsize=11)
        ax.set_title("Bandwidth scaling: federated cost is independent of traffic",
                     fontsize=12)
        ax.legend(fontsize=9, loc="upper left")
        ax.grid(True, which="both", ls="--", alpha=0.4)
        fig.tight_layout()
        fig.savefig("fl_bandwidth.pdf")
        print("[+] fl_bandwidth.pdf written")
    except Exception as exc:
        print(f"[!] plot skipped: {exc}")


if __name__ == "__main__":
    main()
