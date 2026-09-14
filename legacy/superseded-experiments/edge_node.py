import json
import urllib.request
import urllib.error
import numpy as np
import time
import math
from sklearn.linear_model import SGDClassifier
import argparse

# Cloud Aggregator URL
CLOUD_URL = "http://127.0.0.1:8000"

def extract_features(payload):
    """ Extract numerical features from an HTTP payload for the ML model """
    length = len(payload)
    special_chars = sum(1 for c in payload if not c.isalnum())
    # Entropy
    prob = [float(payload.count(c)) / length for c in dict.fromkeys(list(payload))]
    entropy = - sum(p * math.log(p, 2) for p in prob) if length > 0 else 0
    return [length, special_chars, entropy]

def send_weights_to_cloud(model, node_id):
    if not hasattr(model, 'coef_'):
        print(f"[{node_id}] Model not trained yet.")
        return
    data = {
        "coef": model.coef_.tolist(),
        "intercept": model.intercept_.tolist()
    }
    req = urllib.request.Request(CLOUD_URL, data=json.dumps(data).encode('utf-8'), method='POST')
    req.add_header('Content-Type', 'application/json')
    try:
        urllib.request.urlopen(req, timeout=3)
        print(f"[{node_id}] Weights successfully pushed to Cloud.")
    except Exception as e:
        print(f"[{node_id}] Failed to push weights: {e}")

def pull_global_weights(model, node_id):
    try:
        response = urllib.request.urlopen(CLOUD_URL, timeout=3)
        global_model = json.loads(response.read().decode('utf-8'))
        if global_model["coef"] is not None:
            model.coef_ = np.array(global_model["coef"])
            model.intercept_ = np.array(global_model["intercept"])
            print(f"[{node_id}] Synchronized with Global Model (FedAvg)!")
            return True
    except Exception as e:
        pass
    return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', type=str, required=True, help="Node ID (e.g., Edge-Mac or Edge-RPi)")
    parser.add_argument('--scenario', type=str, required=True, help="Type of attack to learn (scenario1 or scenario2)")
    args = parser.parse_args()

    print(f"=== Starting Adaptive Zero-Trust WAF: {args.node} ===")
    model = SGDClassifier(loss='log_loss', max_iter=1000, tol=1e-3, learning_rate='constant', eta0=0.01)
    
    # Initialize classes explicitly so partial_fit works
    model.classes_ = np.array([0, 1]) # 0: Normal, 1: Attack
    model.coef_ = np.zeros((1, 3))
    model.intercept_ = np.zeros(1)

    # Simulated local traffic log
    traffic = [
        ("GET /api/status", 0),
        ("POST /login user=admin", 0),
        ("GET /images/logo.png", 0),
        ("GET /api/data?id=123", 0)
    ]

    # This Edge node only sees ONE type of attack locally!
    if args.scenario == "scenario1":
        traffic.extend([
            ("GET /api/data?id=1' OR '1'='1", 1),
            ("POST /login user=admin'; DROP TABLE users--", 1)
        ])
    else:
        traffic.extend([
            ("GET /api/data?query=<script>alert(1)</script>", 1),
            ("POST /login user=<img src=x onerror=alert(1)>", 1)
        ])

    print(f"[{args.node}] Gathering local traffic and extracting features...")
    X_local = []
    y_local = []
    for payload, label in traffic:
        X_local.append(extract_features(payload))
        y_local.append(label)
    
    X_local = np.array(X_local)
    y_local = np.array(y_local)

    print(f"[{args.node}] Training local Machine Learning WAF...")
    for _ in range(50): # 50 epochs of local training
        model.partial_fit(X_local, y_local, classes=np.array([0, 1]))

    print(f"[{args.node}] Training complete. Local accuracy: {model.score(X_local, y_local)*100:.1f}%")
    
    # Federated Learning Round
    send_weights_to_cloud(model, args.node)
    
    print(f"[{args.node}] Waiting for Cloud to aggregate (FedAvg)...")
    for _ in range(10):
        time.sleep(2)
        if pull_global_weights(model, args.node):
            break

    # Now let's test if the Federated Model can catch an attack it NEVER saw!
    print(f"\n[{args.node}] --- ZERO-DAY ATTACK SIMULATION ---")
    
    zero_day_scenario1 = "GET /api/data?id=1' UNION SELECT NULL--"
    zero_day_scenario2 = "GET /api/data?query=<svg/onload=alert()>"
    
    test_cases = [zero_day_scenario1, zero_day_scenario2]
    
    for attack in test_cases:
        feat = extract_features(attack)
        pred = model.predict([feat])[0]
        status = "BLOCKED" if pred == 1 else "BYPASSED (FAILED)"
        color = "\033[92m" if pred == 1 else "\033[91m"
        reset = "\033[0m"
        print(f"Evaluating Payload: {attack}")
        print(f"Result: {color}{status}{reset}\n")

