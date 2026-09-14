import os
import subprocess
from urllib.parse import quote

# Handcrafted descriptions, tailored SVG backgrounds, technologies, and implementation details
PROJECT_DATA = {
    "DistributedAIoT": {
        "title": "Distributed AIoT Orchestration",
        "desc": "An advanced research framework focused on Collaborative Inference and dynamic Large Language Model (LLM) partitioning across Edge devices. This project explores semantic orchestration to optimize distributed computing in resource-constrained IoT networks, reducing latency while preserving data privacy.",
        "color1": "#3b82f6", "color2": "#8b5cf6",
        "tech": ["Python", "PyTorch", "gRPC", "Docker"],
        "impl": "The system utilizes PyTorch for the underlying neural networks, leveraging dynamic computation graphs to split the model during inference. gRPC is used for low-latency communication between the edge nodes, while Docker ensures reproducible containerization across heterogeneous ARM and x86 architectures."
    },
    "PentestGPT": {
        "title": "PentestGPT",
        "desc": "An autonomous AI-driven agent designed to automate Penetration Testing operations. It leverages Large Language Models to analyze vulnerabilities, suggest attack vectors, and guide the security researcher through complex exploit chains in an interactive, context-aware manner.",
        "color1": "#ef4444", "color2": "#b91c1c",
        "tech": ["Python", "LangChain", "OpenAI API", "Bash"],
        "impl": "Implemented using LangChain to manage LLM context windows and prompt chains. The agent directly interfaces with the host OS via secure subshells to parse outputs from tools like nmap and metasploit, feeding the results back into the LLM loop for autonomous decision-making."
    },
    "leaf": {
        "title": "LEAF",
        "desc": "A modular benchmarking framework tailored for Federated Learning environments. It provides standardized datasets, rigorous evaluation metrics, and reproducible simulation environments to assess the performance of federated algorithms in highly non-IID scenarios.",
        "color1": "#10b981", "color2": "#047857",
        "tech": ["Python", "NumPy", "SciPy", "JSON"],
        "impl": "Built on top of NumPy and SciPy for highly optimized matrix operations during statistical distribution generation. It relies on a modular JSON-based schema to define Non-IID data distributions, ensuring that federated benchmarks are mathematically rigorous and highly reproducible."
    },
    "MLPerf-Tiny": {
        "title": "MLPerf Tiny",
        "desc": "A suite of standardized benchmarks to evaluate the efficiency of deep neural networks on embedded devices and microcontrollers (TinyML). It allows researchers to precisely measure latency, power consumption, and accuracy on ultra-low-power architectures.",
        "color1": "#f59e0b", "color2": "#b45309",
        "tech": ["C++", "TensorFlow Lite Micro", "ARM Cortex-M"],
        "impl": "The core benchmark suite is written in C++ to run bare-metal on microcontrollers. It uses TensorFlow Lite Micro as the inference engine, highly optimized with CMSIS-NN libraries to maximize performance on ARM Cortex-M processors."
    },
    "llm_wiki": {
        "title": "LLM Wiki Builder",
        "desc": "An innovative pipeline that utilizes Large Language Models to read, comprehend, and synthesize vast document archives. It automatically generates and maintains a structured, indexed wiki that can be easily queried using natural language.",
        "color1": "#8b5cf6", "color2": "#4c1d95",
        "tech": ["Python", "ChromaDB", "FastAPI", "Markdown"],
        "impl": "Uses ChromaDB as a vector database to store document embeddings. The extraction pipeline chunks PDF and TXT files, generates embeddings via a local embedding model, and uses an LLM via FastAPI to dynamically generate interconnected Markdown files."
    },
    "Gabriel": {
        "title": "Gabriel Framework",
        "desc": "An edge-native platform designed for Wearable Cognitive Assistance. Gabriel leverages ultra-low latency processing on Cloudlets to analyze real-time video streams from smart glasses, providing instant instructions and feedback to the user.",
        "color1": "#06b6d4", "color2": "#0369a1",
        "tech": ["Java", "Python", "OpenCV", "WebSockets"],
        "impl": "Features a robust asynchronous networking layer using WebSockets to stream high-framerate video from Android wearables to an Edge Cloudlet. The backend utilizes OpenCV and custom CNNs to perform object detection in real-time."
    },
    "split-learning-demo": {
        "title": "Split Learning Simulation",
        "desc": "A practical implementation of the Split Learning paradigm. This project demonstrates how to divide the training of a neural network between edge devices and a central server, exchanging only intermediate activations (smashed data) to protect the privacy of the original dataset.",
        "color1": "#ec4899", "color2": "#be185d",
        "tech": ["Python", "PyTorch", "Socket.io"],
        "impl": "Implements a custom PyTorch subclass that cleanly splits the forward and backward passes. Smashed data (activations) and gradients are serialized and transmitted over a Socket.io event-driven network, allowing devices to train collaboratively without revealing raw data."
    },
    "DRL-for-edge-computing": {
        "title": "DRL for Edge Computing",
        "desc": "An academic exploration into the use of Deep Reinforcement Learning (DRL) for dynamic resource allocation in Mobile Edge Computing (MEC) networks. The RL agents learn optimal task offloading strategies to minimize delays and energy consumption.",
        "color1": "#14b8a6", "color2": "#0f766e",
        "tech": ["Python", "TensorFlow", "OpenAI Gym"],
        "impl": "The MEC environment is simulated using a custom OpenAI Gym environment. The agent uses a Deep Q-Network (DQN) implemented in TensorFlow, trained via Experience Replay to continuously adapt its offloading policies based on network bandwidth and server CPU loads."
    },
    "Flower": {
        "title": "Flower (FL Framework)",
        "desc": "A leading open-source framework for Federated Learning. Designed to be framework-agnostic (supporting PyTorch, TensorFlow, etc.), Flower scales distributed training from a few devices in a lab setting to millions of clients on a global scale.",
        "color1": "#f43f5e", "color2": "#be123c",
        "tech": ["Python", "gRPC", "Protobuf"],
        "impl": "Architected around a highly scalable gRPC communication layer with strict Protobuf schemas. This allows clients written in Python, C++, or Java (Android) to seamlessly exchange model weights with the central Python-based Aggregation server."
    },
    "EdgeAISIM": {
        "title": "EdgeAISim",
        "desc": "A powerful Python-based toolkit developed for simulating and modeling the behavior of Artificial Intelligence models in Edge environments. It enables researchers to profile latency, bandwidth, and memory consumption prior to physical deployment.",
        "color1": "#6366f1", "color2": "#4338ca",
        "tech": ["Python", "SimPy", "Pandas"],
        "impl": "Built on top of SimPy for discrete-event simulation. It uses Pandas to log and analyze the lifecycle of virtual AI tasks, simulating CPU clock cycles, memory bottlenecks, and network jitter to provide a mathematically accurate representation of edge hardware."
    },
    "PipeEdge": {
        "title": "PipeEdge",
        "desc": "A distributed inference framework that implements pipelining for large-scale models (e.g., Transformers) sharded across multiple edge devices. It heavily optimizes communication overhead and latency for cooperative AI inference.",
        "color1": "#8b5cf6", "color2": "#db2777",
        "tech": ["Python", "PyTorch", "MPI"],
        "impl": "Utilizes Message Passing Interface (MPI) for ultra-fast, low-level inter-node communication. The framework intercepts PyTorch's computation graph to automatically shard Transformer blocks across different nodes, pipelining micro-batches to maximize GPU utilization."
    },
    "kubeedge": {
        "title": "KubeEdge",
        "desc": "An official Kubernetes extension designed specifically for Edge Computing. It provides robust infrastructure support for networking, application deployment, and metadata synchronization between the Cloud and resource-constrained peripheral devices.",
        "color1": "#3b82f6", "color2": "#1e40af",
        "tech": ["Go", "Kubernetes", "MQTT"],
        "impl": "Written entirely in Go. It introduces 'EdgeCore' (a lightweight Kubelet replacement) and an 'EdgeHub' that uses MQTT for bidirectional multiplexed communication with the Cloud, allowing edge nodes to operate autonomously even when disconnected."
    },
    "Open5GS": {
        "title": "Open5GS",
        "desc": "A comprehensive, open-source C++ implementation of the 5G Core Network and 4G Evolved Packet Core (EPC). It is a foundational tool for telecommunications research, offering a scalable and private mobile network infrastructure.",
        "color1": "#10b981", "color2": "#065f46",
        "tech": ["C", "C++", "SCTP", "MongoDB"],
        "impl": "Developed with a highly optimized multi-threaded architecture in C/C++. It relies on MongoDB to store subscriber contexts and uses SCTP for reliable signaling transport, ensuring telco-grade performance for Next Generation Core (NGC) components."
    },
    "Simu5G": {
        "title": "Simu5G",
        "desc": "An advanced simulation model for the user-plane of 5G NR (New Radio) and LTE-A networks. Built on the OMNeT++ simulator, it allows for detailed analysis of network performance, latency, and Quality of Service (QoS) in complex scenarios.",
        "color1": "#0ea5e9", "color2": "#0369a1",
        "tech": ["C++", "OMNeT++", "INET Framework"],
        "impl": "Tightly integrated with the OMNeT++ discrete-event simulator and the INET framework. It provides detailed C++ implementations of the MAC, RLC, and PDCP layers of the 5G protocol stack, enabling packet-level simulation of radio interference and scheduling."
    },
    "EdgeSimPy": {
        "title": "EdgeSimPy",
        "desc": "A Python-based simulator for Edge Computing environments. It provides intuitive abstractions for edge servers, network devices, and applications, greatly facilitating the validation of resource management and task scheduling algorithms.",
        "color1": "#eab308", "color2": "#a16207",
        "tech": ["Python", "NetworkX", "Mesa"],
        "impl": "Uses NetworkX to model complex network topologies and Mesa for agent-based modeling. This allows researchers to script complex mobility models and orchestration algorithms (e.g., container migration) using pure, readable Python code."
    },
    "UERANSIM": {
        "title": "UERANSIM",
        "desc": "The definitive open-source state-of-the-art simulator for 5G User Equipment (UE) and Radio Access Networks (gNodeB). It is widely used to test 5G Core Networks by generating simulated device traffic and realistic signaling protocols.",
        "color1": "#f97316", "color2": "#c2410c",
        "tech": ["C++", "SCTP", "NGAP"],
        "impl": "Engineered in modern C++ (C++17). It implements the complete Control Plane (NGAP) and User Plane (GTP-U) protocols from scratch, bypassing the kernel stack via raw sockets to inject realistically crafted 5G signaling packets into the network."
    },
    "EdgeMesh": {
        "title": "EdgeMesh",
        "desc": "An advanced edge routing and mesh networking solution. It builds a peer-to-peer network among edge devices, ensuring fault tolerance, load balancing, and ultra-fast communication even in the absence of constant Cloud connectivity.",
        "color1": "#6366f1", "color2": "#312e81",
        "tech": ["Go", "LibP2P", "CoreDNS"],
        "impl": "Leverages LibP2P to establish secure, NAT-traversing peer-to-peer tunnels between Edge nodes. It integrates with CoreDNS to provide dynamic, localized service discovery without relying on central Kubernetes API servers."
    },
    "FedScale": {
        "title": "FedScale",
        "desc": "An extensible engine and benchmark for large-scale Federated Learning. It provides highly realistic non-IID datasets and simulators capable of mimicking the heterogeneous behavior (e.g., drop-outs, latency spikes) of millions of real-world mobile devices.",
        "color1": "#14b8a6", "color2": "#042f2e",
        "tech": ["Python", "Ray", "PyTorch"],
        "impl": "Uses Ray as the distributed execution engine to orchestrate thousands of virtual clients across a cluster. It introduces a stochastic system-speed model to artificially inject realistic network delays and hardware stragglers during the PyTorch training phases."
    },
    "FedML": {
        "title": "FedML",
        "desc": "A unified and scalable library for distributed Machine Learning. It supports federated training in any environment, from a single IoT device (Edge AI) to multi-GPU clusters, rapidly accelerating both academic research and enterprise deployment.",
        "color1": "#3b82f6", "color2": "#172554",
        "tech": ["Python", "MPI", "PyTorch", "gRPC"],
        "impl": "Features a highly modular architecture that abstracts the communication backend (supporting both MPI for HPC clusters and gRPC for edge/mobile devices). It defines standard APIs for Aggregators and Trainers, allowing seamless swapping of optimization algorithms like FedAvg or FedProx."
    },
    "openyurt": {
        "title": "OpenYurt",
        "desc": "An open-source system that non-intrusively extends native Kubernetes to Edge devices. It is specifically engineered to ensure high availability of peripheral applications, even during unstable network conditions or prolonged Cloud disconnections.",
        "color1": "#84cc16", "color2": "#3f6212",
        "tech": ["Go", "Kubernetes", "YurtHub"],
        "impl": "Introduces 'YurtHub', a transparent local proxy deployed on every edge node. YurtHub caches Kubernetes API responses locally; if the cloud connection is lost, it serves the cached state to the Kubelet, preventing pod eviction and ensuring uninterrupted service."
    },
    "DataSpaceTest": {
        "title": "Edge-Native Data Space (PoC)",
        "desc": "An experimental Proof of Concept for an Edge-based Industrial Data Space. It implements architectures for secure, traceable, and federated sharing of industrial data, in strict compliance with data sovereignty principles (e.g., Gaia-X standards).",
        "color1": "#06b6d4", "color2": "#164e63",
        "tech": ["Python", "Flask", "OAuth2", "Docker"],
        "impl": "Developed using Flask to expose standardized REST APIs for data exchange. It integrates a custom OAuth2 authorization server that issues verifiable credentials, ensuring that only authenticated consortium members can query the edge databases."
    },
    "agentic-rag-for-dummies": {
        "title": "Agentic RAG for Dummies",
        "desc": "An educational implementation of Retrieval-Augmented Generation (RAG) integrated with autonomous agents. It simplifies complex concepts like vector search, context retrieval, and tool-use for LLMs, serving as a clean boilerplate for generative AI apps.",
        "color1": "#a855f7", "color2": "#581c87",
        "tech": ["Python", "LangChain", "FAISS", "Ollama"],
        "impl": "Uses FAISS (Facebook AI Similarity Search) for ultra-fast local vector retrieval. The logic is orchestrated via LangChain, routing user queries to local LLMs (via Ollama) which are equipped with custom Python tools to fetch and synthesize context before answering."
    },
    "Zero-Trust WAF": {
        "title": "Adaptive Zero-Trust WAF",
        "desc": "The primary ongoing research project (Thesis). A distributed Web Application Firewall that utilizes Continuous and Federated Learning in pure Python, protected by Post-Quantum cryptographic tunnels (ML-KEM-512) to defeat zero-day vulnerabilities and secure Industrial Data Spaces.",
        "color1": "#ef4444", "color2": "#7f1d1d",
        "tech": ["Python", "PQCrypto (ML-KEM)", "SGD", "HTTP Server"],
        "impl": "Built entirely in pure Python (using standard libraries like http.server and math) to maintain an ultra-low RAM footprint of <10 MB. Post-Quantum cryptography is integrated via native C-bindings (pqcrypto). Continuous learning is driven by a custom Stochastic Gradient Descent (SGD) algorithm, synchronizing gradients via a Robust Median Aggregator on the Cloud."
    }
}

def get_projects():
    cmd = "find /home/eldemaster/Documents /home/eldemaster/agentic-rag-for-dummies -name '.git' -type d 2>/dev/null"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return [p.strip()[:-5] for p in res.stdout.split('\n') if p.strip()]

projects = get_projects()
projects.append("/home/eldemaster/ (Script Zero-Trust WAF)")

os.makedirs("/home/eldemaster/portfolio_site", exist_ok=True)

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
        
        .card { 
            background: #1e293b; border-radius: 20px; overflow: hidden; 
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); 
            cursor: pointer; text-decoration: none; color: inherit; display: flex; flex-direction: column; 
            border: 1px solid #334155;
        }
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
        "tech": ["Unknown"],
        "impl": "Technical implementation details are currently unavailable or undocumented for this repository."
    })
    
    title = data['title']
    desc = data['desc']
    c1, c2 = data['color1'], data['color2']
    tech_tags = data['tech']
    impl = data['impl']
    
    safe_name = "".join([c if c.isalnum() else "_" for c in name_key])
    short_desc = desc[:130] + "..." if len(desc) > 130 else desc
    
    svg_bg = generate_svg_bg(c1, c2)
    
    # Add to index
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
    
    # Generate tech tags HTML
    tags_html = "".join([f'<span class="badge">{t}</span>' for t in tech_tags])
    
    # Generate individual page
    page_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title} - Details</title>
        <style>
            body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 0; }}
            .hero {{ width: 100%; height: 450px; position: relative; display: flex; align-items: flex-end; overflow: hidden; }}
            .hero-bg {{ position: absolute; inset: 0; z-index: 1; }}
            .hero-bg svg {{ width: 100%; height: 100%; object-fit: cover; }}
            .overlay {{ position: relative; z-index: 10; padding: 60px 40px; background: linear-gradient(to top, #0f172a, transparent); width: 100%; }}
            .overlay h1 {{ color: white; font-size: 4rem; margin: 0; font-weight: 800; letter-spacing: -1px; text-shadow: 0 4px 10px rgba(0,0,0,0.5); }}
            
            .content {{ max-width: 900px; margin: 40px auto; padding: 0 30px; font-size: 1.15rem; line-height: 1.8; color: #cbd5e1; }}
            .path {{ background: #1e293b; padding: 18px 25px; border-radius: 12px; font-family: monospace; color: #38bdf8; margin-bottom: 40px; border: 1px solid #334155; }}
            .back {{ display: inline-flex; align-items: center; margin-bottom: 30px; text-decoration: none; color: #38bdf8; font-weight: 600; padding: 10px 20px; background: #1e293b; border-radius: 8px; transition: all 0.2s; }}
            .back:hover {{ background: #38bdf8; color: #0f172a; }}
            
            h2 {{ color: #f8fafc; font-size: 2rem; border-bottom: 2px solid #334155; padding-bottom: 10px; margin-top: 40px; margin-bottom: 20px; }}
            p {{ font-size: 1.15rem; margin-bottom: 20px; }}
            
            .tech-stack {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 30px; }}
            .badge {{ background: {c1}40; border: 1px solid {c1}; color: {c1}; padding: 8px 16px; border-radius: 20px; font-size: 0.95rem; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; }}
            .impl-box {{ background: #1e293b; border-left: 5px solid {c1}; padding: 25px; border-radius: 0 12px 12px 0; margin-top: 20px; }}
            .impl-box h3 {{ color: #f8fafc; margin-top: 0; margin-bottom: 15px; font-size: 1.3rem; }}
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
            <div class="path">📁 Repository: {p}</div>
            
            <h2>Project Overview</h2>
            <p>{desc}</p>
            
            <h2>Technologies Used</h2>
            <div class="tech-stack">
                {tags_html}
            </div>
            
            <div class="impl-box">
                <h3>Technical Implementation</h3>
                <p style="margin:0; font-size:1.1rem; color:#94a3b8;">{impl}</p>
            </div>
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

print("Website updated with Technical Implementation details!")
