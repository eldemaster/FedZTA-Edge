import urllib.parse
import math

FEDERATED_COEF = [0.01, 1.2, 0.5]
FEDERATED_INTERCEPT = -7.5

def extract_features(payload):
    payload = urllib.parse.unquote(payload)
    length = len(payload)
    special_chars = sum(1 for c in payload if not c.isalnum())
    if length > 0:
        prob = [float(payload.count(c)) / length for c in dict.fromkeys(list(payload))]
        entropy = - sum(p * math.log(p, 2) for p in prob)
    else:
        entropy = 0.0
    return [length, special_chars, entropy]

def predict(payload):
    features = extract_features(payload)
    score = sum(f * c for f, c in zip(features, FEDERATED_COEF)) + FEDERATED_INTERCEPT
    return score

print("Target: Find an XSS/SQLi payload with score < 0")

payloads = [
    "/a",
    "/?q=a",
    "/?q=<svg>",
    "/?q='",
    "/?a='",
    "/?a=1"
]

for p in payloads:
    s = predict(p)
    print(f"Payload: {p:10} | Score: {s:.2f} | Result: {'BLOCKED' if s >= 0 else 'PASSED'}")

print("\nTesting Legitimate complex requests:")
legit = [
    "/api/v1/sensors/temp",
    "/api/v1/sensors/temperature/metrics/dashboard?token=abcdef1234567890",
    "/index.html",
    "/css/style.css?v=1.2.3"
]

for p in legit:
    s = predict(p)
    print(f"Payload: {p} | Score: {s:.2f} | Result: {'BLOCKED' if s >= 0 else 'PASSED'}")
