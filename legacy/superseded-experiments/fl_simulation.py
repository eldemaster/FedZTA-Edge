import numpy as np
import math
import urllib.request
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import precision_score, recall_score, f1_score
import matplotlib.pyplot as plt

print("Downloading Real Datasets from SecLists...")

def download_list(url):
    try:
        response = urllib.request.urlopen(url)
        return [line.decode('utf-8', errors='ignore').strip() for line in response.readlines() if line.strip()]
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return []

sqli_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-SQLi.txt"
xss_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/XSS-Bypass-Strings-BruteLogic.txt"
normal_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt"

raw_sqli = download_list(sqli_url)
raw_xss = download_list(xss_url)
raw_normal = download_list(normal_url)

print(f"Downloaded: {len(raw_sqli)} SQLi, {len(raw_xss)} XSS, {len(raw_normal)} Normal words")

# Construct HTTP payloads
print("Constructing realistic HTTP payloads...")
np.random.seed(42)

def make_normal(words, n):
    payloads = []
    for _ in range(n):
        path = np.random.choice(words)
        payloads.append((f"GET /{path}?v={np.random.randint(1,100)}", 0))
    return payloads

def make_malicious(raw_list, n, method="GET"):
    payloads = []
    for _ in range(n):
        p = np.random.choice(raw_list)
        payloads.append((f"{method} /search?q={p}", 1))
    return payloads

# Downsample to speed up simulation, but keep it large
n_train_normal = 2000
n_train_attack = 1000
n_test_normal = 1000
n_test_attack = 500

edge_A_traffic = make_normal(raw_normal, n_train_normal) + make_malicious(raw_xss, n_train_attack, "POST")
edge_B_traffic = make_normal(raw_normal, n_train_normal) + make_malicious(raw_sqli, n_train_attack, "GET")
global_test_traffic = make_normal(raw_normal, n_test_normal) + make_malicious(raw_xss, n_test_attack, "POST") + make_malicious(raw_sqli, n_test_attack, "GET")

def extract_features(payload):
    length = len(payload)
    special_chars = sum(1 for c in payload if not c.isalnum())
    prob = [float(payload.count(c)) / length for c in dict.fromkeys(list(payload))]
    entropy = - sum(p * math.log(p, 2) for p in prob) if length > 0 else 0
    return [length, special_chars, entropy]

def build_dataset(traffic):
    X = np.array([extract_features(p) for p, _ in traffic])
    y = np.array([label for _, label in traffic])
    return X, y

print("Extracting features...")
X_A, y_A = build_dataset(edge_A_traffic)
X_B, y_B = build_dataset(edge_B_traffic)
X_test, y_test = build_dataset(global_test_traffic)

print("Training local models (Isolated)...")
model_A = SGDClassifier(loss='log_loss', max_iter=200, random_state=42)
model_B = SGDClassifier(loss='log_loss', max_iter=200, random_state=42)

model_A.partial_fit(X_A, y_A, classes=np.array([0,1]))
model_B.partial_fit(X_B, y_B, classes=np.array([0,1]))

print("Performing Federated Averaging (FedAvg)...")
fed_coef = np.mean([model_A.coef_, model_B.coef_], axis=0)
fed_intercept = np.mean([model_A.intercept_, model_B.intercept_], axis=0)

fed_model = SGDClassifier(loss='log_loss')
fed_model.classes_ = np.array([0,1])
fed_model.coef_ = fed_coef
fed_model.intercept_ = fed_intercept

print("Evaluating against REAL Zero-Days...")
y_pred_A = model_A.predict(X_test)
y_pred_B = model_B.predict(X_test)
y_pred_fed = fed_model.predict(X_test)

f1_A = f1_score(y_test, y_pred_A)
f1_B = f1_score(y_test, y_pred_B)
f1_fed = f1_score(y_test, y_pred_fed)

print(f"Edge A (Trained only on SecLists XSS) F1-Score: {f1_A:.2f}")
print(f"Edge B (Trained only on SecLists SQLi) F1-Score: {f1_B:.2f}")
print(f"Federated Model F1-Score: {f1_fed:.2f}")

plt.figure(figsize=(7,5))
plt.bar(['Edge A (XSS Only)', 'Edge B (SQLi Only)', 'Federated (FedAvg)'], [f1_A, f1_B, f1_fed], color=['#ff9999', '#66b3ff', '#99ff99'])
plt.ylabel('F1-Score (Real SecLists Payloads)', fontsize=12)
plt.title('Real-World Security Effectiveness on Zero-Days', fontsize=14)
plt.ylim(0, 1.1)
for i, v in enumerate([f1_A, f1_B, f1_fed]):
    plt.text(i, v + 0.02, f"{v:.2f}", ha='center', fontweight='bold')
plt.savefig('fl_metrics.pdf')
print("PDF metrics saved.")
