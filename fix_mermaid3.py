import re

with open('generate_website_v5_mermaid.py', 'r') as f:
    content = f.read()

old_waf = """        "mermaid": \"\"\"graph TD
    subgraph Edge Network (Raspberry Pi)
        A[Incoming Traffic] --> B[WAF Feature Extraction]
        B --> C[Local SGD Model]
        C -->|Block/Allow| D[Protected IoT Device]
    end
    subgraph Cloud Aggregator (Ubuntu)
        E[Robust Median Function]
    end
    C -.->|Encrypted Gradients (ML-KEM-512)| E
    E -.->|Global Weights Update| C\"\"\""""

new_waf = """        "mermaid": \"\"\"graph TD
    subgraph Edge_Network [Edge Network - Raspberry Pi]
        A["Incoming Traffic"] --> B["WAF Feature Extraction"]
        B --> C["Local SGD Model"]
        C -->|"Block/Allow"| D["Protected IoT Device"]
    end
    subgraph Cloud_Aggregator [Cloud Aggregator - Ubuntu]
        E["Robust Median Function"]
    end
    C -.->|"Encrypted Gradients (ML-KEM-512)"| E
    E -.->|"Global Weights Update"| C\"\"\""""

content = content.replace(old_waf, new_waf)

with open('generate_website_v5_mermaid.py', 'w') as f:
    f.write(content)

