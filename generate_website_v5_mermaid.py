import os
import subprocess
import html

# Handcrafted advanced descriptions and Mermaid diagrams
PROJECT_DATA = {
    "Zero-Trust WAF": {
        "title": "Adaptive Zero-Trust WAF",
        "desc": "The primary ongoing research project (Thesis). A distributed Web Application Firewall that utilizes Continuous and Federated Learning in pure Python, protected by Post-Quantum cryptographic tunnels (ML-KEM-512) to defeat zero-day vulnerabilities and secure Industrial Data Spaces.",
        "extended_desc": "In modern Industrial Data Spaces, traditional signature-based firewalls fail to protect against zero-day exploits and polymorphic payloads. This project introduces a completely decentralized, Edge-Native Web Application Firewall. Instead of relying on static rules, it employs a custom Stochastic Gradient Descent (SGD) algorithm written in pure Python, allowing it to continuously learn from localized traffic patterns. To preserve data sovereignty, raw HTTP logs never leave the edge; only mathematical gradients are shared. The transmission of these gradients is secured using NIST-standardized Post-Quantum Cryptography (ML-KEM-512) to ensure long-term confidentiality against Quantum attacks.",
        "color1": "#ef4444", "color2": "#7f1d1d",
        "tech": ["Python", "PQCrypto (ML-KEM)", "SGD", "Robust Median Aggregation"],
        "impl": "Built entirely in pure Python (using standard libraries) to maintain an ultra-low RAM footprint (<10 MB). Continuous learning is driven by a custom SGD, synchronizing gradients via a Robust Median Aggregator on the Cloud to prevent Catastrophic Forgetting.",
        "mermaid": """graph TD
    subgraph Edge Network (Raspberry Pi)
        A[Incoming Traffic] --> B[WAF Feature Extraction]
        B --> C[Local SGD Model]
        C -->|Block/Allow| D[Protected IoT Device]
    end
    subgraph Cloud Aggregator (Ubuntu)
        E[Robust Median Function]
    end
    C -.->|Encrypted Gradients (ML-KEM-512)| E
    E -.->|Global Weights Update| C""",
        "diagram_desc": "The architecture highlights the separation between local continuous learning and global federated synchronization, secured by Quantum-Resistant tunnels."
    },
    "PentestGPT": {
        "title": "PentestGPT",
        "desc": "An autonomous AI-driven agent designed to automate Penetration Testing operations. It leverages Large Language Models to analyze vulnerabilities, suggest attack vectors, and guide the security researcher through complex exploit chains.",
        "extended_desc": "Penetration testing is a highly manual, time-consuming process that requires deep domain expertise. PentestGPT bridges this gap by functioning as an autonomous copilot. It interprets the output of standard security tools (like Nmap, Gobuster, and Metasploit) and uses advanced prompt engineering to reason about the network topology. The system maintains a persistent context window, allowing it to build complex, multi-stage attack trees. It can dynamically pivot through networks, identifying logical flaws that traditional vulnerability scanners would miss.",
        "color1": "#ef4444", "color2": "#b91c1c",
        "tech": ["Python", "LangChain", "OpenAI API", "Bash"],
        "impl": "Implemented using LangChain to manage context windows. The agent directly interfaces with the host OS via secure subshells, parsing tool outputs and feeding them back into the LLM loop for autonomous decision-making.",
        "mermaid": """sequenceDiagram
    participant User
    participant Agent as PentestGPT
    participant OS as Local Bash Shell
    participant Target as Target Network
    
    User->>Agent: "Scan target and find exploits"
    Agent->>OS: Execute `nmap -sV target`
    OS->>Target: Port Scan
    Target-->>OS: Raw Results
    OS-->>Agent: Parsed Nmap Output
    Agent->>Agent: LLM Reasoning (Find CVEs)
    Agent->>OS: Execute `searchsploit`
    OS-->>Agent: Exploit found
    Agent->>User: "Exploit strategy formulated. Proceed?" """,
        "diagram_desc": "The sequence diagram illustrates the Agentic RAG loop: the LLM interacts with the operating system to execute tools, interprets the raw output, and autonomously decides the next stage of the attack."
    },
    "DistributedAIoT": {
        "title": "Distributed AIoT Orchestration",
        "desc": "An advanced research framework focused on Collaborative Inference and dynamic Large Language Model (LLM) partitioning across Edge devices.",
        "extended_desc": "Running massive neural networks on singular Edge devices is physically impossible due to VRAM constraints. This project explores Semantic Orchestration to optimize distributed computing in IoT networks. By analyzing the computation graph of a model, the framework dynamically shards (partitions) the network into smaller blocks. These blocks are deployed across multiple heterogeneous devices (e.g., a mix of Raspberry Pis and Jetson Nanos). The devices compute their local forward pass and transmit the intermediate tensor activations over the network to the next node in the pipeline.",
        "color1": "#3b82f6", "color2": "#8b5cf6",
        "tech": ["Python", "PyTorch", "gRPC", "Docker"],
        "impl": "The system utilizes PyTorch for dynamic computation graph splitting. gRPC is used for low-latency tensor transmission, while Docker ensures reproducible containerization across heterogeneous ARM/x86 architectures.",
        "mermaid": """graph LR
    A[IoT Sensor Data] --> B[Edge Node 1 (Layer 1-3)]
    B -->|Intermediate Tensors| C[Edge Node 2 (Layer 4-6)]
    C -->|Intermediate Tensors| D[Cloud Server (Layer 7-12)]
    D --> E[Final Inference Output]
    style B fill:#3b82f6,stroke:#fff,stroke-width:2px,color:#fff
    style C fill:#8b5cf6,stroke:#fff,stroke-width:2px,color:#fff""",
        "diagram_desc": "Pipeline parallelism in action: the Neural Network is sharded horizontally. Instead of sending raw data to the Cloud, edge devices process the initial layers locally, drastically reducing bandwidth and preserving privacy."
    },
    "Open5GS": {
        "title": "Open5GS",
        "desc": "A comprehensive, open-source C++ implementation of the 5G Core Network and 4G Evolved Packet Core (EPC).",
        "extended_desc": "The transition to 5G Standalone (SA) architectures requires a completely redesigned, cloud-native Core Network. Open5GS is an industry-grade, open-source implementation of the 3GPP Release 16 specifications. It provides essential Network Functions (NFs) such as AMF (Access and Mobility Management Function), SMF (Session Management Function), and UPF (User Plane Function). This laboratory setup allows researchers to deploy a private, fully functional 5G network to study ultra-reliable low-latency communication (URLLC), network slicing, and edge computing integration without relying on commercial telecom vendors.",
        "color1": "#10b981", "color2": "#065f46",
        "tech": ["C", "C++", "SCTP", "MongoDB"],
        "impl": "Developed with a highly optimized multi-threaded architecture in C/C++. It relies on MongoDB to store subscriber contexts and uses SCTP for reliable signaling transport.",
        "mermaid": """graph TD
    A[5G UE / Phone] <-->|Radio| B[gNodeB / Base Station]
    B <-->|N1/N2| C(AMF)
    B <-->|N3| D(UPF)
    C <-->|N11| E(SMF)
    E <-->|N4| D
    D <-->|N6| F[Internet / Edge Cloud]
    classDef core fill:#10b981,stroke:#000,stroke-width:2px,color:#fff;
    class C,D,E core;""",
        "diagram_desc": "The 5G Service-Based Architecture (SBA). The Control Plane (AMF/SMF) is cleanly separated from the User Plane (UPF), allowing the UPF to be deployed directly at the Edge for ultra-low latency."
    },
    "Flower": {
        "title": "Flower (FL Framework)",
        "desc": "A leading open-source framework for Federated Learning. Designed to be framework-agnostic, Flower scales distributed training from a few devices to millions of clients.",
        "extended_desc": "Federated Learning is notoriously difficult to deploy due to the extreme heterogeneity of client devices (different OS, frameworks, network speeds). Flower abstracts these complexities away. It introduces a modular architecture where the Aggregator and the Clients communicate via strict gRPC interfaces. This allows researchers to train a TensorFlow model on an Android phone, a PyTorch model on a Raspberry Pi, and a JAX model on a Cloud VM, all participating in the exact same Federated Learning round. It is the de-facto standard for scaling FL research into production.",
        "color1": "#f43f5e", "color2": "#be123c",
        "tech": ["Python", "gRPC", "Protobuf"],
        "impl": "Architected around a highly scalable gRPC communication layer with strict Protobuf schemas. This allows clients written in Python, C++, or Java (Android) to seamlessly exchange model weights with the central Python-based Aggregation server.",
        "mermaid": """graph TD
    A((Global Server))
    B[Client 1: PyTorch / ARM]
    C[Client 2: TensorFlow / x86]
    D[Client 3: CoreML / iOS]
    
    A -- Distributes Model --> B
    A -- Distributes Model --> C
    A -- Distributes Model --> D
    
    B -- Uploads Gradients --> A
    C -- Uploads Gradients --> A
    D -- Uploads Gradients --> A""",
        "diagram_desc": "Flower's framework-agnostic topology. The central server orchestrates the federated rounds, completely oblivious to the underlying hardware or machine learning library used by the local clients."
    }
}

# Fallback generic data
GENERIC_DATA = {
    "extended_desc": "This repository represents a vital component of the ongoing laboratory research. While specific high-level architectural documentation may be pending, the codebase explores advanced paradigms in distributed computing, networking, or artificial intelligence. Researchers utilize this module to simulate, benchmark, or deploy next-generation edge-native architectures, contributing to the broader scope of Zero-Trust and IoT resilience.",
    "mermaid": """graph LR
    A[Local Node] -->|Data/Compute| B(Core Framework)
    B -->|Output/Sync| C[Distributed Network]""",
    "diagram_desc": "A generalized structural flow representing the distributed nature of this repository's architecture."
}

def get_projects():
    cmd = "find /home/eldemaster/Documents /home/eldemaster/agentic-rag-for-dummies -name '.git' -type d 2>/dev/null"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return [p.strip()[:-5] for p in res.stdout.split('\n') if p.strip()]

projects = get_projects()
projects.append("/home/eldemaster/ (Script Zero-Trust WAF)")
os.makedirs("/home/eldemaster/portfolio_site", exist_ok=True)

# Generate Index
index_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ubuntu Lab - Portfolio</title>
    <style>
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }
        .header { text-align: center; margin-bottom: 50px; }
        h1 { color: #f8fafc; font-size: 3.5rem; margin: 0; font-weight: 800; letter-spacing: -1px; }
        .subtitle { color: #94a3b8; font-size: 1.2rem; margin-top: 10px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 30px; max-width: 1300px; margin: 0 auto; }
        .card { background: #1e293b; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); cursor: pointer; text-decoration: none; color: inherit; display: flex; flex-direction: column; border: 1px solid #334155; }
        .card:hover { transform: translateY(-8px) scale(1.02); box-shadow: 0 20px 35px -5px rgba(0,0,0,0.6); border-color: #475569; }
        .svg-bg { width: 100%; height: 220px; display: flex; align-items: center; justify-content: center; position: relative; overflow: hidden; }
        .svg-bg svg { position: absolute; inset: 0; width: 100%; height: 100%; opacity: 0.8; }
        .svg-bg .title-overlay { position: relative; z-index: 10; color: white; font-size: 1.8rem; font-weight: bold; text-shadow: 0 4px 10px rgba(0,0,0,0.5); text-align: center; padding: 0 20px;}
        .card-content { padding: 25px; flex-grow: 1; display: flex; flex-direction: column; }
        .card h2 { margin: 0 0 12px 0; font-size: 1.4rem; color: #f1f5f9; }
        .card p { margin: 0; color: #94a3b8; font-size: 0.95rem; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Ubuntu Research Lab</h1>
        <div class="subtitle">Advanced Cybersecurity & Federated Learning Portfolio</div>
    </div>
    <div class="grid">
"""

def generate_svg_bg(color1, color2):
    return f"""
    <svg preserveAspectRatio="none" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <linearGradient id="grad_{color1.strip('#')}" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="{color1}" />
                <stop offset="100%" stop-color="{color2}" />
            </linearGradient>
            <pattern id="pattern_{color1.strip('#')}" x="0" y="0" width="10" height="10" patternUnits="userSpaceOnUse">
                <circle cx="2" cy="2" r="1" fill="#ffffff" fill-opacity="0.1"/>
            </pattern>
        </defs>
        <rect width="100" height="100" fill="url(#grad_{color1.strip('#')})" />
        <rect width="100" height="100" fill="url(#pattern_{color1.strip('#')})" />
        <path d="M-20,100 L50,-20 L120,100 Z" fill="#ffffff" fill-opacity="0.05" />
        <path d="M120,-20 L30,120 L-20,-20 Z" fill="#000000" fill-opacity="0.1" />
    </svg>
    """

for p in projects:
    name_key = p.split('/')[-1] if not "(Script" in p else "Zero-Trust WAF"
    
    data = PROJECT_DATA.get(name_key, {
        "title": name_key,
        "desc": "Project archived on the Ubuntu server. This repository contains scripts, documentation, and source code related to the laboratory's ongoing research activities.",
        "color1": "#475569", "color2": "#1e293b",
        "tech": ["Python", "Research", "Documentation"],
        "impl": "Technical implementation details are documented within the repository's internal specifications."
    })
    
    title = data['title']
    desc = data['desc']
    ext_desc = data.get('extended_desc', GENERIC_DATA['extended_desc'])
    mermaid_code = data.get('mermaid', GENERIC_DATA['mermaid'])
    diagram_desc = data.get('diagram_desc', GENERIC_DATA['diagram_desc'])
    c1, c2 = data['color1'], data['color2']
    tech_tags = data['tech']
    impl = data['impl']
    
    safe_name = "".join([c if c.isalnum() else "_" for c in name_key])
    short_desc = desc[:130] + "..." if len(desc) > 130 else desc
    svg_bg = generate_svg_bg(c1, c2)
    tags_html = "".join([f'<span class="badge">{t}</span>' for t in tech_tags])
    
    index_html += f"""
        <a href="{safe_name}.html" class="card">
            <div class="svg-bg">
                {svg_bg}
                <div class="title-overlay">{title}</div>
            </div>
            <div class="card-content">
                <p>{short_desc}</p>
            </div>
        </a>
    """
    
    page_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title} - Details</title>
        <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
        <script>mermaid.initialize({{startOnLoad:true, theme: 'dark'}});</script>
        <style>
            body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 0; }}
            .hero {{ width: 100%; height: 400px; position: relative; display: flex; align-items: flex-end; overflow: hidden; }}
            .hero-bg {{ position: absolute; inset: 0; z-index: 1; }}
            .hero-bg svg {{ width: 100%; height: 100%; object-fit: cover; }}
            .overlay {{ position: relative; z-index: 10; padding: 60px 40px; background: linear-gradient(to top, #0f172a, transparent); width: 100%; }}
            .overlay h1 {{ color: white; font-size: 3.5rem; margin: 0; font-weight: 800; letter-spacing: -1px; text-shadow: 0 4px 10px rgba(0,0,0,0.5); }}
            
            .content {{ max-width: 1000px; margin: 40px auto; padding: 0 30px; font-size: 1.15rem; line-height: 1.8; color: #cbd5e1; }}
            .path {{ background: #1e293b; padding: 18px 25px; border-radius: 12px; font-family: monospace; color: #38bdf8; margin-bottom: 40px; border: 1px solid #334155; display: inline-block; }}
            .back {{ display: inline-flex; align-items: center; margin-bottom: 30px; text-decoration: none; color: #38bdf8; font-weight: 600; padding: 10px 20px; background: #1e293b; border-radius: 8px; transition: all 0.2s; }}
            .back:hover {{ background: #38bdf8; color: #0f172a; }}
            
            h2 {{ color: #f8fafc; font-size: 2rem; border-bottom: 2px solid #334155; padding-bottom: 10px; margin-top: 40px; margin-bottom: 20px; }}
            p {{ font-size: 1.15rem; margin-bottom: 20px; text-align: justify; }}
            
            .tech-stack {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 30px; }}
            .badge {{ background: {c1}40; border: 1px solid {c1}; color: {c1}; padding: 8px 16px; border-radius: 20px; font-size: 0.95rem; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; }}
            .impl-box {{ background: #1e293b; border-left: 5px solid {c1}; padding: 25px; border-radius: 0 12px 12px 0; margin-top: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
            .impl-box h3 {{ color: #f8fafc; margin-top: 0; margin-bottom: 15px; font-size: 1.3rem; }}
            
            .diagram-container {{ background: #1e293b; padding: 30px; border-radius: 16px; margin: 40px 0; border: 1px solid #334155; text-align: center; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.5); }}
            .mermaid {{ display: flex; justify-content: center; }}
            .diagram-caption {{ margin-top: 20px; font-size: 1rem; color: #94a3b8; font-style: italic; border-top: 1px solid #334155; padding-top: 15px; }}
        </style>
    </head>
    <body>
        <div class="hero">
            <div class="hero-bg">{svg_bg}</div>
            <div class="overlay">
                <h1>{title}</h1>
            </div>
        </div>
        <div class="content">
            <a href="index.html" class="back">← Back to Portfolio</a>
            <br>
            <div class="path">📁 Repository: {p}</div>
            
            <h2>Deep Dive & Research Context</h2>
            <p>{desc}</p>
            <p>{ext_desc}</p>
            
            <h2>Architecture Diagram</h2>
            <div class="diagram-container">
                <div class="mermaid">
{mermaid_code}
                </div>
                <div class="diagram-caption">Figure 1: {diagram_desc}</div>
            </div>
            
            <h2>Technologies Used</h2>
            <div class="tech-stack">
                {tags_html}
            </div>
            
            <div class="impl-box">
                <h3>Technical Implementation</h3>
                <p style="margin:0; font-size:1.1rem; color:#94a3b8;">{impl}</p>
            </div>
            <br><br>
        </div>
    </body>
    </html>
    """
    with open(f"/home/eldemaster/portfolio_site/{safe_name}.html", 'w') as f:
        f.write(page_html)

index_html += """
    </div>
</body>
</html>
"""
with open("/home/eldemaster/portfolio_site/index.html", 'w') as f:
    f.write(index_html)

print("Website updated with massive text blocks and Mermaid.js diagrams!")
