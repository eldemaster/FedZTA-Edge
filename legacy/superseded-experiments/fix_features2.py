with open("fl_simulation_v2.py", "r") as f:
    code = f.read()
code = code.replace("print(f\"Federated Model F1-Score: {f1_fed:.2f}\")", "print(f\"Federated Model F1-Score: {f1_fed:.2f}\")\nprint(\"COEF:\", global_model.coef_)\nprint(\"INTERCEPT:\", global_model.intercept_)")
with open("fl_simulation_v2.py", "w") as f:
    f.write(code)
