import os
import json
import subprocess

def get_projects():
    cmd = "find /home/eldemaster/Documents /home/eldemaster/agentic-rag-for-dummies -name '.git' -type d 2>/dev/null"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return [p.strip()[:-5] for p in res.stdout.split('\n') if p.strip()]

def get_description(proj_dir):
    readme_paths = [os.path.join(proj_dir, 'README.md'), os.path.join(proj_dir, 'readme.md'), os.path.join(proj_dir, 'README.txt')]
    for rp in readme_paths:
        if os.path.exists(rp):
            try:
                with open(rp, 'r', encoding='utf-8') as f:
                    content = f.read(1000) # read first 1000 chars
                    
                    # Extract the first non-empty paragraph or header
                    lines = [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('<') and not line.strip().startswith('[')]
                    if lines:
                        desc = " ".join(lines[:3]) # get first 3 lines
                        if len(desc) > 150:
                            desc = desc[:147] + "..."
                        # Clean up markdown
                        desc = desc.replace('#', '').strip()
                        return desc
            except:
                pass
    
    # If no README, guess by contents
    files = os.listdir(proj_dir)
    exts = list(set([f.split('.')[-1] for f in files if '.' in f]))
    if 'py' in exts: return "Progetto Python (Nessun README trovato)."
    if 'js' in exts or 'ts' in exts: return "Progetto Web/Node.js (Nessun README trovato)."
    if 'cpp' in exts or 'c' in exts: return "Progetto C/C++ (Nessun README trovato)."
    return "Nessuna descrizione disponibile."

projects = get_projects()
projects.append("/home/eldemaster/ (Script Zero-Trust WAF)")

output = {}
for p in projects:
    if p == "/home/eldemaster/ (Script Zero-Trust WAF)":
        output[p] = "Script Python per il Firewall Zero-Trust Edge, Federated Learning e PQC TLS (Progetto Corrente)."
    else:
        output[p] = get_description(p)

print(json.dumps(output))
