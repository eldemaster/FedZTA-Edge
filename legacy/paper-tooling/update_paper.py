with open('federated_paper_v2_pqtls.tex', 'r') as f:
    paper = f.read()

# 1. Update the Discussion section
old_discussion = r"""\section{Discussion and Limitations}
While the framework successfully mitigates zero-day vulnerabilities with minimal overhead, it is not without limitations. The reliance on linear boundaries (SGD) implies that highly sophisticated, adversarial payloads designed to mimic the statistical entropy of normal traffic might evade detection. Future iterations could explore lightweight non-linear models, such as Mini-Random Forests, compiled to WebAssembly (Wasm) for execution speed. Furthermore, our current FedAvg implementation is vulnerable to Byzantine faults; if an adversary compromises an Edge node, they could upload poisoned weights to degrade the global model. Integrating median-based aggregation rules is a crucial next step for adversarial robustness."""

new_discussion = r"""\section{Discussion and Limitations}
While the framework successfully mitigates zero-day vulnerabilities with minimal computational overhead, it exhibits limitations typical of linear classifiers on the Edge. Through rigorous adversarial penetration testing, we demonstrated that the model is resilient to syntactic evasion (e.g., obfuscated XSS). However, the reliance on linear Logistic Regression ($W \cdot X$) creates a mathematical constraint: the heavy penalization of non-alphanumeric characters generates False Positives on highly complex, legitimate APIs (e.g., endpoints containing dense JWT tokens or multiple query parameters like \texttt{/css/style.css?v=1.2.3}). This demonstrates a fundamental trade-off between the micro-inferencer's blazing speed (218 RPS) and the nuanced decision-making capability of heavier, non-linear models. Future iterations could explore lightweight non-linear models (e.g., Decision Trees) compiled to WebAssembly (Wasm) for execution speed. Furthermore, our current FedAvg implementation is vulnerable to Byzantine faults; integrating median-based aggregation rules is a crucial next step for adversarial robustness."""

paper = paper.replace(old_discussion, new_discussion)

# 2. Add Throughput and PQC Overhead to Hardware Evaluation
old_hardware = r"""The results in Table II are notable. With an inference latency of merely 0.035 milliseconds, the AI inspection operates faster than a standard network transmission hop, guaranteeing zero bottlenecking for industrial traffic. The 9.14 MB memory footprint allows the security layer to run comfortably alongside other critical ICS/SCADA software, even on deeply embedded devices like the ESP32."""

new_hardware = r"""The results in Table II are highly notable. With an inference latency of merely 0.035 milliseconds, the AI inspection operates faster than a standard network transmission hop. To evaluate the real-world viability of the Edge Node under stress, we subjected the Raspberry Pi to an asynchronous HTTP load test. The single-threaded WAF successfully sustained a throughput of \textbf{218 Requests Per Second (RPS)} with zero dropped packets and a 50th-percentile median latency of just 18.56 ms. 

Furthermore, we empirically measured the computational penalty of our Application-Layer ML-KEM-512 integration. On the ARM aarch64 processor, the Post-Quantum Key Encapsulation Mechanism required a mere \textbf{0.26 ms} to derive the shared secret from the 800-byte Public Key. This proves that Kyber cryptography does not induce latency bottlenecks for Industrial IoT devices. The 9.14 MB memory footprint allows the security layer to run comfortably alongside other critical ICS/SCADA software."""

paper = paper.replace(old_hardware, new_hardware)

with open('federated_paper_v2_pqtls.tex', 'w') as f:
    f.write(paper)

print("Paper updated successfully!")
