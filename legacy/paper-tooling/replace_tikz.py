import re

with open("federated_paper.tex", "r") as f:
    content = f.read()

# Regex to match the entire tikzpicture environment
pattern = r"\\begin\{tikzpicture\}.*?\\end\{tikzpicture\}"

replacement = r"\\includegraphics[width=\\columnwidth]{fl_architecture.pdf}"

new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

with open("federated_paper.tex", "w") as f:
    f.write(new_content)

print("TikZ replaced.")
