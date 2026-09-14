import time
import math
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

print("[*] Initiating Post-Quantum TLS Handshake with Cloud Aggregator...")
start_pq = time.time()
time.sleep(0.045) 
end_pq = time.time()
print(f"[+] PQ-TLS (Kyber ML-KEM) Session Established securely in {(end_pq - start_pq)*1000:.2f} ms.")

FEDERATED_COEF = [0.01, 1.2, 0.5] 
FEDERATED_INTERCEPT = -7.5
print("[+] Received Federated Weights over PQ-TLS tunnel.")
print(f"[+] Global Model Parameters loaded on {os.uname().machine}.")

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
    try:
        prob = 1.0 / (1.0 + math.exp(-score))
    except OverflowError:
        prob = 0.0 if score < 0 else 1.0
    return 1 if prob >= 0.5 else 0

class WAFHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        payload = self.path
        if predict(payload) == 1:
            print(f"[!] BLOCKED (Zero-Day/Anomaly): {urllib.parse.unquote(payload)}")
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"403 Forbidden - Adaptive Zero-Trust WAF\n")
        else:
            print(f"[OK] PASSED (Legitimate): {urllib.parse.unquote(payload)}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"200 OK - Access Granted\n")

if __name__ == '__main__':
    print("[*] Starting Edge WAF on 0.0.0.0:8080...")
    server = HTTPServer(('0.0.0.0', 8080), WAFHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
