import os
import subprocess
from urllib.parse import quote

# Handcrafted descriptions and tailored SVG backgrounds for each project
PROJECT_DATA = {
    "DistributedAIoT": {
        "title": "Distributed AIoT Orchestration",
        "desc": "Un framework di ricerca avanzato incentrato sulla Collaborative Inference e sul partizionamento dinamico di Large Language Models (LLM) su dispositivi Edge. Il progetto esplora l'orchestrazione semantica per ottimizzare il calcolo distribuito in reti IoT a risorse vincolate, riducendo la latenza e preservando la privacy dei dati.",
        "color1": "#3b82f6", "color2": "#8b5cf6" # Blue to Purple
    },
    "PentestGPT": {
        "title": "PentestGPT",
        "desc": "Un agente autonomo basato su Intelligenza Artificiale progettato per automatizzare le operazioni di Penetration Testing. Utilizza i Large Language Models per analizzare vulnerabilità, suggerire vettori di attacco e guidare il ricercatore attraverso complesse catene di exploit in modo interattivo e contestuale.",
        "color1": "#ef4444", "color2": "#b91c1c" # Red
    },
    "leaf": {
        "title": "LEAF",
        "desc": "Un framework di benchmark modulare progettato per ambienti di Federated Learning. Fornisce dataset standardizzati, metriche rigorose e ambienti di simulazione riproducibili per valutare le prestazioni degli algoritmi di apprendimento federato in scenari non-IID.",
        "color1": "#10b981", "color2": "#047857" # Green
    },
    "MLPerf-Tiny": {
        "title": "MLPerf Tiny",
        "desc": "Una suite di benchmark standardizzati per valutare l'efficienza delle reti neurali profonde su dispositivi embedded e microcontrollori (TinyML). Permette di misurare latenza, consumo energetico e accuratezza su architetture a bassissimo consumo.",
        "color1": "#f59e0b", "color2": "#b45309" # Orange
    },
    "llm_wiki": {
        "title": "LLM Wiki Builder",
        "desc": "Un innovativo sistema pipeline che utilizza i Large Language Models per leggere, comprendere e sintetizzare vasti archivi di documenti. Genera e mantiene automaticamente una wiki strutturata, indicizzata e facilmente interrogabile in linguaggio naturale.",
        "color1": "#8b5cf6", "color2": "#4c1d95" # Purple
    },
    "Gabriel": {
        "title": "Gabriel Framework",
        "desc": "Una piattaforma edge-native progettata per la Wearable Cognitive Assistance. Gabriel sfrutta l'elaborazione a bassissima latenza sui Cloudlet per analizzare flussi video in tempo reale provenienti da smart glasses, fornendo istruzioni e feedback istantaneo all'utente.",
        "color1": "#06b6d4", "color2": "#0369a1" # Cyan
    },
    "split-learning-demo": {
        "title": "Split Learning Simulation",
        "desc": "Un'implementazione pratica del paradigma di Split Learning. Il progetto dimostra come dividere l'addestramento di una rete neurale tra dispositivi edge e un server centrale, scambiando solo le attivazioni intermedie (smashed data) per proteggere la privacy del dataset originale.",
        "color1": "#ec4899", "color2": "#be185d" # Pink
    },
    "DRL-for-edge-computing": {
        "title": "DRL for Edge Computing",
        "desc": "Un'esplorazione accademica sull'uso del Deep Reinforcement Learning (DRL) per l'allocazione dinamica delle risorse nelle reti Mobile Edge Computing (MEC). Gli agenti RL imparano a scaricare (offload) i task computazionali per minimizzare ritardi e consumi energetici.",
        "color1": "#14b8a6", "color2": "#0f766e" # Teal
    },
    "Flower": {
        "title": "Flower (FL Framework)",
        "desc": "Un framework open-source leader per il Federated Learning. Progettato per essere framework-agnostic (supporta PyTorch, TensorFlow, ecc.), Flower scala l'addestramento distribuito da pochi dispositivi in laboratorio a milioni di client su scala globale.",
        "color1": "#f43f5e", "color2": "#be123c" # Rose
    },
    "EdgeAISIM": {
        "title": "EdgeAISim",
        "desc": "Un potente toolkit in Python sviluppato per la simulazione e la modellazione del comportamento dei modelli di Intelligenza Artificiale in ambienti Edge. Permette ai ricercatori di profilare latenza, banda e consumo di memoria prima del deployment fisico.",
        "color1": "#6366f1", "color2": "#4338ca" # Indigo
    },
    "PipeEdge": {
        "title": "PipeEdge",
        "desc": "Un framework di inferenza distribuita che implementa il pipelining per modelli di grandi dimensioni (es. Transformers) frammentati su più dispositivi edge. Ottimizza la comunicazione e la latenza per l'inferenza AI cooperativa.",
        "color1": "#8b5cf6", "color2": "#db2777" # Purple-Pink
    },
    "kubeedge": {
        "title": "KubeEdge",
        "desc": "Un'estensione ufficiale di Kubernetes progettata specificamente per l'Edge Computing. Fornisce supporto infrastrutturale per il networking, il deployment delle applicazioni e la sincronizzazione dei metadati tra il Cloud e i dispositivi periferici a risorse vincolate.",
        "color1": "#3b82f6", "color2": "#1e40af" # Blue
    },
    "Open5GS": {
        "title": "Open5GS",
        "desc": "Un'implementazione open-source completa e in C++ della Core Network 5G e dell'Evolved Packet Core (EPC) 4G. È uno strumento fondamentale per la ricerca sulle telecomunicazioni, offrendo un'infrastruttura di rete mobile privata e scalabile.",
        "color1": "#10b981", "color2": "#065f46" # Emerald
    },
    "Simu5G": {
        "title": "Simu5G",
        "desc": "Un modello di simulazione avanzato per la user-plane delle reti 5G NR (New Radio) e LTE-A. Basato sul simulatore OMNeT++, permette l'analisi dettagliata delle performance di rete, della latenza e della qualità del servizio (QoS) in scenari complessi.",
        "color1": "#0ea5e9", "color2": "#0369a1" # Light Blue
    },
    "EdgeSimPy": {
        "title": "EdgeSimPy",
        "desc": "Un simulatore Python-based per ambienti Edge Computing. Offre astrazioni facili da usare per server edge, dispositivi di rete e applicazioni, facilitando la validazione di algoritmi di resource management e task scheduling.",
        "color1": "#eab308", "color2": "#a16207" # Yellow
    },
    "UERANSIM": {
        "title": "UERANSIM",
        "desc": "L'unico simulatore open-source state-of-the-art per User Equipment (UE) e Radio Access Network (gNodeB) in ambito 5G. Viene utilizzato per testare le Core Network 5G generando traffico di dispositivi simulati e protocolli di segnalazione reali.",
        "color1": "#f97316", "color2": "#c2410c" # Orange
    },
    "EdgeMesh": {
        "title": "EdgeMesh",
        "desc": "Una soluzione avanzata di routing e mesh networking per l'Edge. Costruisce una rete peer-to-peer tra i dispositivi edge, garantendo tolleranza ai guasti, load balancing e comunicazione ultra-veloce anche in assenza di connettività Cloud costante.",
        "color1": "#6366f1", "color2": "#312e81" # Indigo Dark
    },
    "FedScale": {
        "title": "FedScale",
        "desc": "Un motore e benchmark estensibile per il Federated Learning su vasta scala. Fornisce dataset realistici (non-IID) e simulatori capaci di imitare il comportamento eterogeneo (drop-out, latenza) di milioni di dispositivi mobili nel mondo reale.",
        "color1": "#14b8a6", "color2": "#042f2e" # Teal Dark
    },
    "FedML": {
        "title": "FedML",
        "desc": "Una libreria unificata e scalabile per il Machine Learning distribuito. Supporta l'addestramento federato in qualsiasi ambiente, dal singolo dispositivo IoT (Edge AI) ai cluster multi-GPU, accelerando la ricerca e il deployment aziendale.",
        "color1": "#3b82f6", "color2": "#172554" # Blue Dark
    },
    "openyurt": {
        "title": "OpenYurt",
        "desc": "Un sistema open-source che estende Kubernetes nativo ai dispositivi Edge in modo non intrusivo. È progettato per garantire un'alta disponibilità delle applicazioni periferiche, anche in condizioni di rete instabili o disconnessioni prolungate dal master Cloud.",
        "color1": "#84cc16", "color2": "#3f6212" # Lime
    },
    "DataSpaceTest": {
        "title": "Edge-Native Data Space (PoC)",
        "desc": "Un Proof of Concept sperimentale per uno Spazio Dati industriale basato sull'Edge. Implementa architetture per la condivisione sicura, tracciabile e federata dei dati industriali, in conformità con i principi di sovranità del dato (es. standard Gaia-X).",
        "color1": "#06b6d4", "color2": "#164e63" # Cyan Dark
    },
    "agentic-rag-for-dummies": {
        "title": "Agentic RAG for Dummies",
        "desc": "Un'implementazione didattica di Retrieval-Augmented Generation (RAG) integrata con agenti autonomi. Semplifica i concetti complessi di vector search, context retrieval e tool-use per LLM, fungendo da boilerplate per applicazioni AI generative.",
        "color1": "#a855f7", "color2": "#581c87" # Purple
    },
    "Zero-Trust WAF": {
        "title": "Adaptive Zero-Trust WAF",
        "desc": "Progetto principale di ricerca corrente (Tesi). Un Web Application Firewall distribuito che utilizza Continuous e Federated Learning in puro Python, protetto da tunnel crittografici Post-Quantistici (ML-KEM-512) per sconfiggere vulnerabilità zero-day e proteggere gli Spazi Dati Industriali.",
        "color1": "#ef4444", "color2": "#7f1d1d" # Red Dark
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
        <!-- Abstract Tech Shapes -->
        <path d="M-20,100 L50,-20 L120,100 Z" fill="#ffffff" fill-opacity="0.05" />
        <path d="M120,-20 L30,120 L-20,-20 Z" fill="#000000" fill-opacity="0.1" />
    </svg>
    """

for p in projects:
    name_key = p.split('/')[-1] if not "(Script" in p else "Zero-Trust WAF"
    
    data = PROJECT_DATA.get(name_key, {
        "title": name_key,
        "desc": "Progetto archiviato nel server Ubuntu. Questo repository contiene script, documentazione e codice sorgente relativi alle attività di ricerca nel laboratorio.",
        "color1": "#475569", "color2": "#1e293b"
    })
    
    title = data['title']
    desc = data['desc']
    c1, c2 = data['color1'], data['color2']
    
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
            
            h2 {{ color: #f8fafc; font-size: 2rem; border-bottom: 2px solid #334155; padding-bottom: 10px; margin-top: 40px; }}
            p {{ font-size: 1.15rem; }}
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
            <a href="index.html" class="back">← Torna al Portfolio</a>
            <div class="path">📁 Repository: {p}</div>
            <h2>Panoramica del Progetto</h2>
            <p>{desc}</p>
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

print("Sito generato con descrizioni e grafica avanzate in /home/eldemaster/portfolio_site")
