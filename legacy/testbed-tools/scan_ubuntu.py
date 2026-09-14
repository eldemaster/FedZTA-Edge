import os

def scan_dir(base_dir, max_depth=3):
    projects = []
    if not os.path.exists(base_dir): return projects
    
    for root, dirs, files in os.walk(base_dir):
        # Ignore hidden directories like .cache, .local, .cargo, etc. except .git
        dirs[:] = [d for d in dirs if not d.startswith('.') or d == '.git']
        
        depth = root[len(base_dir):].count(os.sep)
        if depth >= max_depth:
            dirs.clear()
            continue
            
        is_project = False
        if '.git' in dirs:
            is_project = True
        else:
            for ext in ['.py', '.js', '.cpp', '.ino', '.tex', '.md', '.rs']:
                if any(f.endswith(ext) for f in files):
                    is_project = True
                    break
            if any(f in ['package.json', 'Cargo.toml', 'platformio.ini', 'CMakeLists.txt', 'Makefile'] for f in files):
                is_project = True
        
        # Don't classify standard venv or hidden folders as standalone projects unless they have a git repo
        if "venv" in root.split(os.sep):
            is_project = False
            
        if is_project and '.git' not in root:
            projects.append(root)
            dirs.clear() # stop descending
    return projects

all_projects = scan_dir('/home/eldemaster', max_depth=3)
for p in sorted(all_projects):
    print(p)
