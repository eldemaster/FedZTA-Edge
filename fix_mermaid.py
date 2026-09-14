import re

with open('generate_website_v5_mermaid.py', 'r') as f:
    content = f.read()

old_aiot = """        "mermaid": \"\"\"graph LR
    A[IoT Sensor Data] --> B[Edge Node 1 (Layer 1-3)]
    B -->|Intermediate Tensors| C[Edge Node 2 (Layer 4-6)]
    C -->|Intermediate Tensors| D[Cloud Server (Layer 7-12)]
    D --> E[Final Inference Output]
    style B fill:#3b82f6,stroke:#fff,stroke-width:2px,color:#fff
    style C fill:#8b5cf6,stroke:#fff,stroke-width:2px,color:#fff\"\"\""""

new_aiot = """        "mermaid": \"\"\"graph LR
    A["IoT Sensor Data"] --> B["Edge Node 1 (Layer 1-3)"]
    B -->|"Intermediate Tensors"| C["Edge Node 2 (Layer 4-6)"]
    C -->|"Intermediate Tensors"| D["Cloud Server (Layer 7-12)"]
    D --> E["Final Inference Output"]
    style B fill:#3b82f6,stroke:#fff,stroke-width:2px,color:#fff
    style C fill:#8b5cf6,stroke:#fff,stroke-width:2px,color:#fff\"\"\""""

content = content.replace(old_aiot, new_aiot)

old_pentest = """Agent->>OS: Execute `nmap -sV target`"""
new_pentest = """Agent->>OS: Execute nmap -sV target"""
content = content.replace(old_pentest, new_pentest)

old_pentest2 = """Agent->>OS: Execute `searchsploit`"""
new_pentest2 = """Agent->>OS: Execute searchsploit"""
content = content.replace(old_pentest2, new_pentest2)

old_pentest3 = """Agent->>User: "Exploit strategy formulated. Proceed?" """
new_pentest3 = """Agent->>User: Exploit strategy formulated. Proceed?"""
content = content.replace(old_pentest3, new_pentest3)


with open('generate_website_v5_mermaid.py', 'w') as f:
    f.write(content)

