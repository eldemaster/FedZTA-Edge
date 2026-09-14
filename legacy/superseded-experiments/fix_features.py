with open("fl_simulation.py", "r") as f:
    code = f.read()

old_feat = """def extract_features(payload):
    length = len(payload)
    special_chars = sum(1 for c in payload if not c.isalnum())
    prob = [float(payload.count(c)) / length for c in dict.fromkeys(list(payload))]
    entropy = - sum(p * math.log(p, 2) for p in prob) if length > 0 else 0
    return [length, special_chars, entropy]"""

new_feat = """def extract_features(payload):
    length = len(payload)
    benign_chars = sum(1 for c in payload if c in "/?&=-_.")
    malicious_chars = sum(1 for c in payload if c in "<>'\\\"();\\\\|")
    prob = [float(payload.count(c)) / length for c in dict.fromkeys(list(payload))]
    entropy = - sum(p * math.log(p, 2) for p in prob) if length > 0 else 0
    return [length, benign_chars, malicious_chars, entropy]"""

if old_feat in code:
    code = code.replace(old_feat, new_feat)
    code = code.replace("print(f\"Federated Model F1-Score: {f1_fed:.2f}\")", "print(f\"Federated Model F1-Score: {f1_fed:.2f}\")\nprint(\"COEF:\", fed_model.coef_)\nprint(\"INTERCEPT:\", fed_model.intercept_)")
    with open("fl_simulation_v2.py", "w") as f:
        f.write(code)
    print("SUCCESS")
else:
    print("FAILED TO MATCH")
