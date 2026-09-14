with open('train_production_model.py', 'r') as f:
    lines = f.readlines()

new_lines = []
in_eval = False
for line in lines:
    if line.startswith('    print("\\n" + "=" * 86)'):
        in_eval = True
        
    if line.startswith('    print("\\n" + "=" * 90)'):
        in_eval = False

    if in_eval:
        new_lines.append("    " + line)
    else:
        new_lines.append(line)

with open('train_production_model.py', 'w') as f:
    f.writelines(new_lines)
