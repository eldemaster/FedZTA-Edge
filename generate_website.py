import os
import json
import subprocess
from urllib.parse import quote

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
                    content = f.read(1500)
                    lines = [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('<') and not line.strip().startswith('[')]
                    if lines:
                        return " ".join(lines[:10]) # Get a longer description for the dedicated page
            except:
                pass
    return "Nessuna descrizione dettagliata disponibile per questo progetto."

projects = get_projects()
projects.append("/home/eldemaster/ (Script Zero-Trust WAF)")

os.makedirs("/home/eldemaster/portfolio_site", exist_ok=True)

# Generate Homepage
index_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ubuntu Lab - Portfolio</title>
    <style>
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f1f5f9; color: #334155; margin: 0; padding: 40px; }
        .header { text-align: center; margin-bottom: 50px; }
        h1 { color: #0f172a; font-size: 3rem; margin: 0; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 30px; max-width: 1200px; margin: 0 auto; }
        .card { background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); transition: transform 0.2s; cursor: pointer; text-decoration: none; color: inherit; display: block; }
        .card:hover { transform: translateY(-5px); }
        .card img { width: 100%; height: 200px; object-fit: cover; }
        .card-content { padding: 20px; }
        .card h2 { margin: 0 0 10px 0; font-size: 1.2rem; color: #1e293b; }
        .card p { margin: 0; color: #64748b; font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Ubuntu Research Lab</h1>
        <p>Interactive Project Portfolio</p>
    </div>
    <div class="grid">
"""

for p in projects:
    name = p.split('/')[-1] if not "(Script" in p else "Zero-Trust WAF"
    safe_name = "".join([c if c.isalnum() else "_" for c in name])
    desc = get_description(p)
    short_desc = desc[:100] + "..." if len(desc) > 100 else desc
    
    seed = quote(name)
    img_url = f"https://picsum.photos/seed/{seed}/600/400"
    
    # Add to index
    index_html += f"""
        <a href="{safe_name}.html" class="card">
            <img src="{img_url}" alt="{name}">
            <div class="card-content">
                <h2>{name}</h2>
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
        <title>{name} - Details</title>
        <style>
            body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #fff; color: #334155; margin: 0; padding: 0; }}
            .hero {{ width: 100%; height: 400px; background-image: url('{img_url}'); background-size: cover; background-position: center; position: relative; }}
            .overlay {{ position: absolute; inset: 0; background: linear-gradient(to top, rgba(0,0,0,0.8), transparent); display: flex; align-items: flex-end; padding: 40px; }}
            .overlay h1 {{ color: white; font-size: 3.5rem; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }}
            .content {{ max-width: 900px; margin: 40px auto; padding: 0 20px; font-size: 1.1rem; line-height: 1.8; }}
            .path {{ background: #f1f5f9; padding: 15px; border-radius: 8px; font-family: monospace; color: #0f172a; margin-bottom: 30px; }}
            .back {{ display: inline-block; margin-bottom: 20px; text-decoration: none; color: #3b82f6; font-weight: bold; }}
            .back:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="hero">
            <div class="overlay">
                <h1>{name}</h1>
            </div>
        </div>
        <div class="content">
            <a href="index.html" class="back">← Back to Portfolio</a>
            <div class="path">📁 Repository Path: {p}</div>
            <h2>Project Description</h2>
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

print("Sito generato con successo in /home/eldemaster/portfolio_site")
