import re

with open('federated_paper_v3_final.tex', 'r') as f:
    content = f.read()

# Update Discussion and Limitations
old_discussion = r"""\section{Discussion and Limitations}
While the framework successfully mitigates zero-day vulnerabilities with minimal computational overhead, it exhibits limitations typical of linear classifiers on the Edge. Through rigorous adversarial penetration testing, we demonstrated that the model is resilient to syntactic evasion (e.g., obfuscated XSS). However, the reliance on linear Logistic Regression ($W \cdot X$) creates a mathematical constraint: the heavy penalization of non-alphanumeric characters generates False Positives on highly complex, legitimate APIs (e.g., endpoints containing dense JWT tokens or multiple query parameters like \texttt{/css/style.css?v=1.2.3}). This demonstrates a fundamental trade-off between the micro-inferencer's blazing speed (218 RPS) and the nuanced decision-making capability of heavier, non-linear models. Future iterations could explore lightweight non-linear models (e.g., Decision Trees) compiled to WebAssembly (Wasm) for execution speed. Furthermore, our current FedAvg implementation is vulnerable to Byzantine faults; integrating median-based aggregation rules is a crucial next step for adversarial robustness.

\section{Conclusion}"""

new_discussion = r"""\section{Discussion and Limitations}
While the framework successfully mitigates zero-day vulnerabilities with minimal computational overhead, it exhibits limitations typical of linear classifiers on the Edge. Through adversarial penetration testing utilizing Entropy Dilution (e.g., padding an XSS payload with repeated characters to artificially lower Shannon entropy), we demonstrated a mathematical constraint in linear models: sophisticated attackers can bypass the decision boundary if the feature extraction is purely syntactic. Furthermore, the reliance on linear Logistic Regression generates False Positives on highly complex, legitimate APIs containing dense JWT tokens. This demonstrates a fundamental trade-off between the micro-inferencer's blazing speed (up to 218 RPS on Edge hardware) and the nuanced decision-making capability of heavier, non-linear models. 

\section{Conclusion}"""

# Update Conclusion
old_conclusion = r"""\section{Conclusion}
This paper presented a Federated Learning architecture designed to enforce Adaptive Zero-Trust on Industrial Edge Gateways. By enabling localized AI training and restricting Cloud communication strictly to mathematical model weights, we achieved a collaborative defense mechanism that respects Data Sovereignty. Empirical testing on real-world SecLists payloads demonstrated an F1-Score of 0.94 against unseen zero-day attacks. Most notably, our hardware profiling on ARM architecture proved that the ML inspection engine consumes only 9.14 MB of RAM and induces a negligible 0.035 ms latency penalty. To further optimize execution on deeply embedded ICS devices, our micro-inferencer can be compiled into WebAssembly (Wasm). By leveraging runtimes like WasmEdge, the Python-distilled ML parameters are executed in a native sandbox, providing hardware-level security isolation while preserving the 0.035 ms sub-millisecond execution latency. These results confirm that decentralized, privacy-preserving Machine Learning—especially when augmented by WebAssembly isolation—is highly practical for next-generation Industrial IoT security.

\section*{Data and Code Availability}"""

new_conclusion = r"""\section{Conclusion}
This paper presented an Adaptive Zero-Trust Federated Learning architecture tailored for Industrial Edge Gateways. By replacing static WAF rulesets with dynamic Stochastic Gradient Descent (SGD) classifiers that learn continuously at the Edge, our framework enables localized anomaly detection while fully preserving Data Sovereignty. We empirically proved that Post-Quantum Cryptography (ML-KEM-512) can secure federated transmissions with sub-millisecond latency (0.28 ms) on aarch64 architectures. Furthermore, our implementation of a Robust Median Aggregation algorithm successfully prevented Catastrophic Forgetting and mitigated data poisoning during continuous learning across distributed nodes. The resulting micro-inferencer operates with less than 10 MB of RAM, sustaining 62 RPS across a multi-node cluster even while actively backpropagating gradients. These findings confirm that autonomous, quantum-resistant, and continuous machine learning is exceptionally viable for securing next-generation Industrial IoT networks.

\section{Future Work}
To overcome the inherent limitations of linear classifiers identified in this study, future research will explore the deployment of computationally efficient non-linear models, such as Decision Trees and Tiny Neural Networks, directly on the Edge. Furthermore, to maximize execution speed and security isolation, we aim to compile these continuous learning inferencers into WebAssembly (Wasm). Running inside a WasmEdge native sandbox would provide hardware-level isolation for the Zero-Trust Gateway, preventing model extraction attacks while preserving strict sub-millisecond latency bounds. Finally, investigating more sophisticated unsupervised active-learning heuristics to auto-label industrial payloads on the fly remains a critical milestone for fully autonomous cybersecurity grids.

\section*{Data and Code Availability}"""

content = content.replace(old_discussion, new_discussion)
content = content.replace(old_conclusion, new_conclusion)

with open('federated_paper_v4_final.tex', 'w') as f:
    f.write(content)

print("Updated LaTeX written to federated_paper_v4_final.tex")
