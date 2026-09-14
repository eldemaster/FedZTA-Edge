"""Authenticated weight updates for the FedZTA control plane.

Without authentication the Byzantine defence is vacuous: coordinate-wise median
tolerates f malicious clients only while f is bounded, and anyone who can reach
the aggregator can register arbitrarily many identities. An attacker with five
sybils owns the median outright regardless of how robust the rule is.

Each gateway is enrolled with a 256-bit secret and signs every update with
HMAC-SHA256 over a canonical serialisation. HMAC is used rather than a public-key
signature so the edge keeps its zero-dependency, ~10 MB footprint -- `hmac` and
`hashlib` are standard library, Ed25519 is not.

Threat model for this layer: an attacker on the network path may observe, replay,
reorder or forge update messages, but does not hold an enrolled secret. A
compromised gateway that holds a valid secret is a Byzantine client, which is what
the aggregation rule -- not this module -- is there to contain.
"""
import hashlib
import hmac
import json
import secrets
import time

SECRET_BYTES = 32
CLOCK_SKEW_S = 120          # accept timestamps within this window
NONCE_TTL_S = 300           # remember nonces at least as long as the skew window


def new_secret():
    """Generate an enrolment secret. 256 bits from the OS CSPRNG."""
    return secrets.token_hex(SECRET_BYTES)


def canonical(payload):
    """Deterministic byte encoding of the signed fields.

    Signing a re-serialised dict is only safe if the serialisation is canonical;
    sorted keys and fixed separators ensure sender and receiver agree byte for byte.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def sign(payload, secret):
    return hmac.new(bytes.fromhex(secret), canonical(payload), hashlib.sha256).hexdigest()


def build_update(client_id, weights, bias, n_samples, secret, now=None):
    """Assemble a signed update message."""
    body = {
        "client_id": client_id,
        "weights": weights,
        "bias": bias,
        "n_samples": n_samples,
        "ts": int(now if now is not None else time.time()),
        "nonce": secrets.token_hex(16),
    }
    return {"body": body, "sig": sign(body, secret)}


class ReplayGuard:
    """Rejects nonces already seen inside the acceptance window."""

    def __init__(self, ttl=NONCE_TTL_S):
        self.ttl = ttl
        self._seen = {}

    def check_and_record(self, nonce, now):
        self._evict(now)
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True

    def _evict(self, now):
        cutoff = now - self.ttl
        for k in [k for k, v in self._seen.items() if v < cutoff]:
            del self._seen[k]


def verify(message, secrets_by_client, replay_guard=None, now=None,
           skew=CLOCK_SKEW_S):
    """Validate a signed update.

    Returns (ok, client_id_or_None, reason). The signature is checked before any
    field is trusted, and compared in constant time.
    """
    now = now if now is not None else time.time()

    if not isinstance(message, dict):
        return False, None, "malformed message"
    body, sig = message.get("body"), message.get("sig")
    if not isinstance(body, dict) or not isinstance(sig, str):
        return False, None, "missing body or signature"

    cid = body.get("client_id")
    if not isinstance(cid, str) or cid not in secrets_by_client:
        # Same response for unknown and malformed, so the endpoint does not
        # confirm which identifiers are enrolled.
        return False, None, "unknown client"

    expected = sign(body, secrets_by_client[cid])
    if not hmac.compare_digest(expected, sig):
        return False, None, "bad signature"

    ts = body.get("ts")
    if not isinstance(ts, int) or abs(now - ts) > skew:
        return False, cid, "timestamp outside acceptance window"

    nonce = body.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return False, cid, "missing nonce"
    if replay_guard is not None and not replay_guard.check_and_record(nonce, now):
        return False, cid, "replayed nonce"

    return True, cid, "ok"
