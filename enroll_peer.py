"""Enrol an edge gateway with the Cloud Aggregator.

Generates a 256-bit secret, records it in the aggregator's peer file and writes
the gateway's half for deployment. Both files are created 0600.

    python3 enroll_peer.py edge-web
    scp gateway_secret_edge-web.json edge-web-host:~/gateway_secret.json

The gateway secret is a credential: it is what bounds f in the Byzantine
analysis. Anything that can read it can register as that gateway.
"""
import json
import os
import stat
import sys

import fedzta_auth as AUTH

PEERS_PATH = os.environ.get("FEDZTA_PEERS", "peers.json")


def write_private(path, obj):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh, indent=2)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: enroll_peer.py <client-id>")
    cid = sys.argv[1]

    peers = {}
    if os.path.exists(PEERS_PATH):
        with open(PEERS_PATH) as fh:
            peers = json.load(fh)
    if cid in peers:
        sys.exit(f"{cid} is already enrolled; remove it from {PEERS_PATH} to re-issue")

    secret = AUTH.new_secret()
    peers[cid] = {"secret": secret}
    write_private(PEERS_PATH, peers)

    out = f"gateway_secret_{cid}.json"
    write_private(out, {"client_id": cid, "secret": secret})

    print(f"[+] enrolled {cid}")
    print(f"    aggregator : {PEERS_PATH} ({len(peers)} peer(s), mode 0600)")
    print(f"    gateway    : {out} -> deploy as ~/gateway_secret.json")
    print(f"[!] restart the aggregator to load the new peer")


if __name__ == "__main__":
    main()
