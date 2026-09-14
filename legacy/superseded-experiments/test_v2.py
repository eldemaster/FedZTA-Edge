import urllib.parse
import math

FEDERATED_COEF = [1.21, -0.46, 3.63, -4.8]
FEDERATED_INTERCEPT = -3.44

def extract_features(payload):
    payload = urllib.parse.unquote(payload)
    length = len(payload)
    benign_chars = sum(1 for c in payload if c in "/?&=-_.")
    malicious_chars = sum(1 for c in payload if c in "<>'\"();\\\\|")
    if length > 0:
        prob = [float(payload.count(c)) / length for c in dict.fromkeys(list(payload))]
        entropy = - sum(p * math.log(p, 2) for p in prob)
    else:
        entropy = 0.0
    return [length, benign_chars, malicious_chars, entropy]

def predict(payload):
    features = extract_features(payload)
    score = sum(f * c for f, c in zip(features, FEDERATED_COEF)) + FEDERATED_INTERCEPT
    return score

print("=== EVASIONS ===")
payloads = [
    ("/?q=<svg>", "Short XSS Evasion"),
    ("/?q=' OR 1=1--", "SQLi")
]
for p, desc in payloads:
    s = predict(p)
    print(f"[{desc}] Score: {s:.2f} | Result: {'BLOCKED' if s >= 0 else 'PASSED'}")

print("\n=== FALSE POSITIVE TEST (Legitimate) ===")
legit = [
    "/api/v1/sensors/temp",
    "/api/v1/sensors/temperature/metrics/dashboard?token=abcdef1234567890",
    "/css/style.css?v=1.2.3"
]
for p in legit:
    s = predict(p)
    print(f"Payload: {p} | Score: {s:.2f} | Result: {'BLOCKED' if s >= 0 else 'PASSED'}")
