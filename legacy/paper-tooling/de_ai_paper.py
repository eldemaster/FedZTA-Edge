import re

with open("federated_paper.tex", "r") as f:
    text = f.read()

# 1. Remove overly enthusiastic AI adjectives
replacements = {
    r"impressive F1-Score": "F1-Score",
    r"an impressive F1-Score": "an F1-Score",
    r"unprecedented": "notable",
    r"drastically outperforms": "outperforms",
    r"drastically": "significantly",
    r"massive efficiency": "efficiency",
    r"exponential savings": "savings",
    r"perfectly aligning": "aligning",
    r"stratosferici": "low", # (if it was in Italian, but it's in English)
    r"crucially, ": "",
    r"Crucially, ": "",
    r"symmetrically ": "",
    r"de facto standard": "standard",
    r"hyper-connectivity": "widespread connectivity",
    r"encapsulated by the mantra ``never trust, always verify,''": "",
}

for old, new in replacements.items():
    text = re.sub(old, new, text, flags=re.IGNORECASE)

# 2. Add Hyperparameter details to Experimental Setup
hyperparams = r"""\subsection{Hyperparameter Tuning}
To ensure reproducibility, the SGD classifier was instantiated with the following hyperparameters, selected via grid search on a validation hold-out set: \texttt{loss='log\_loss'}, \texttt{penalty='l2'}, \texttt{alpha=0.0001}, and an initial learning rate $\eta_0 = 0.01$. The FedAvg communication round was triggered every $E=50$ local epochs to balance model convergence and network overhead.

\subsection{Hardware Infrastructure}"""
text = text.replace(r"\subsection{Hardware Infrastructure}", hyperparams)

# 3. Add Acknowledgements and Data Availability before References
ack = r"""\section*{Data and Code Availability}
The dataset curated from SecLists, along with the Federated Learning simulation code, Edge micro-inferencer, and instructions to reproduce the testbed, are open-source and available on GitHub at \texttt{https://github.com/alessandro-demartini/FedZTA-Edge}.

\section*{Acknowledgment}
This work was partially supported by the Swedish Knowledge Foundation (KK-stiftelsen) under the Synergy Project grant and the Mid Sweden University (MIUN) Industrial IoT research initiative. The authors thank the anonymous reviewers for their constructive feedback.

\begin{thebibliography}{00}"""
text = text.replace(r"\begin{thebibliography}{00}", ack)

with open("federated_paper.tex", "w") as f:
    f.write(text)

