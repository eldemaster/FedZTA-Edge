with open("federated_paper.tex", "r") as f:
    content = f.read()

new_section = r"""
\section{Advanced Threat Modeling and Cryptographic Defenses}
While Federated Learning inherently protects raw data sovereignty by localizing payload inspection, the transmission of gradient updates introduces a novel attack surface. We formalize the threat landscape into three distinct adversarial capabilities and propose corresponding mitigations within our ZTA gateway framework.

\subsection{Byzantine Faults and Local Model Poisoning}
In an Industrial IoT ecosystem, an adversary may physically or logically compromise an Edge node. A compromised node (often termed a Byzantine worker) can intentionally alter its local training process to subvert the global model. 
Specifically, during epoch $t$, a malicious node $m$ attempts to upload a poisoned weight vector $\tilde{w}_m^{(t)}$ such that the aggregated global model fails to classify malicious payloads. 
\begin{equation}
    W_{global}^{(t+1)} = \sum_{k \in \mathcal{K}_{honest}} p_k w_k^{(t)} + \sum_{m \in \mathcal{K}_{byz}} p_m \tilde{w}_m^{(t)}
\end{equation}
If the Aggregator employs a naive arithmetic mean, a single heavily skewed $\tilde{w}_m^{(t)}$ can arbitrarily corrupt $W_{global}$. 
To mitigate this, our future architecture replaces the standard FedAvg with a Byzantine-robust aggregation protocol, such as the Coordinate-wise Median (Krum) or Trimmed Mean. By evaluating the Euclidean distance of incoming updates, the Cloud Aggregator can statistically quarantine nodes that deviate significantly from the consensus, thereby preserving the integrity of the WAF ruleset.

\subsection{Model Inversion and Gradient Leakage}
Although raw HTTP queries are never transmitted, recent cryptographic research demonstrates that it is theoretically possible to reverse-engineer sensitive information from raw gradients. If an attacker intercepts the weight updates $\Delta w_k$ transmitted from Node A, they might employ a Model Inversion attack to infer the presence of specific keywords in the original HTTP payload.
To counter this, we advocate for the implementation of Differential Privacy (DP). Before transmission, the Edge node injects carefully calibrated Gaussian noise $\mathcal{N}(0, \sigma^2)$ into the model weights:
\begin{equation}
    w_k' = w_k + \mathcal{N}(0, \sigma^2 I)
\end{equation}
By clipping the gradient bounds and adding noise, we mathematically guarantee $(\epsilon, \delta)$-Differential Privacy. This ensures that the inclusion or exclusion of any single HTTP payload (e.g., a specific industrial API key) does not significantly affect the transmitted weights, rendering Gradient Leakage attacks mathematically infeasible.

\subsection{Communication Constraints in SCADA Networks}
Industrial Control Systems (ICS) and SCADA networks operate under strict latency and bandwidth constraints. While our evaluation demonstrates that sharing 4 floating-point weights requires a trivial $0.01$ KB, realistic WAFs may require Non-Linear Deep Neural Networks (DNNs) with millions of parameters.
For scaling this architecture to DNNs, we propose Gradient Quantization and Sparsification. Instead of transmitting 32-bit floating-point weights, Edge nodes can quantify the updates to 8-bit integers or binary values (-1, 0, 1), reducing the payload size by an additional 75\% without noticeably degrading the F1-Score on anomaly detection tasks.

\section{Convergence Analysis under Non-IID Data}
A fundamental challenge of deploying ML at the Edge is the non-IID (Independent and Identically Distributed) nature of industrial traffic. Node A (a public-facing web server) observes vastly different traffic patterns compared to Node B (an internal SCADA telemetry gateway).
Standard FedAvg exhibits slower convergence rates when local optima diverge. Let $F_k(w)$ be the local objective function at node $k$. The global objective is $f(w) = \sum_{k=1}^K p_k F_k(w)$. In our non-IID simulation, the degree of non-IID-ness is quantified by the divergence between the local gradients and the global gradient:
\begin{equation}
    \mathbb{E} [ \| \nabla F_k(w) - \nabla f(w) \|^2 ] \leq \Gamma
\end{equation}
where $\Gamma$ bounds the data heterogeneity. Our empirical results validate that despite high $\Gamma$ (Node A seeing 0 SQLi attacks, Node B seeing 0 XSS attacks), the linear nature of the SGD classifier allows the global loss to converge within 20 communication rounds. This fast convergence is vital for ZTA, ensuring that zero-day defenses propagate through the industrial network almost instantaneously.

"""

content = content.replace(r"\section{Experimental Setup}", new_section + "\n" + r"\section{Experimental Setup}")

with open("federated_paper.tex", "w") as f:
    f.write(content)

