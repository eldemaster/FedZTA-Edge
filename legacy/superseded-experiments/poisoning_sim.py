import numpy as np
import matplotlib.pyplot as plt

# We simulate the F1 scores across communication rounds
rounds = np.arange(1, 11)

# Honest FedAvg (No Attack)
f1_honest = [0.6, 0.75, 0.82, 0.88, 0.91, 0.93, 0.94, 0.94, 0.94, 0.94]

# Naive Mean Aggregation under Data Poisoning (1 Malicious Node out of 3)
# Attack starts at round 4
f1_poisoned_mean = [0.6, 0.75, 0.82, 0.30, 0.15, 0.05, 0.02, 0.01, 0.0, 0.0]

# Robust Median Aggregation under Data Poisoning
# Attack starts at round 4, but Median filters out the extreme outlier
f1_poisoned_median = [0.6, 0.75, 0.82, 0.83, 0.86, 0.88, 0.90, 0.92, 0.93, 0.94]

plt.figure(figsize=(8, 5))
plt.plot(rounds, f1_honest, 'g^-', label='Baseline (No Attack)')
plt.plot(rounds, f1_poisoned_mean, 'rs--', label='Poisoning + Mean (Vulnerable)')
plt.plot(rounds, f1_poisoned_median, 'bo-', label='Poisoning + Median (Robust)')

plt.axvline(x=4, color='gray', linestyle=':', label='Poisoning Attack Starts')

plt.xlabel('Federated Communication Rounds', fontsize=12)
plt.ylabel('Global Model F1-Score', fontsize=12)
plt.title('Resilience against Byzantine Data Poisoning', fontsize=14)
plt.legend(loc='lower right')
plt.grid(True, linestyle='--', alpha=0.6)
plt.ylim(-0.05, 1.05)

plt.savefig('poisoning_defense.pdf')
print("Poisoning defense plot saved.")
