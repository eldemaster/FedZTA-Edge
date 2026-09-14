with open('train_production_model.py', 'r') as f:
    code = f.read()

code = code.replace('"Edge B (API)"', '"Edge B (api)"')

with open('train_production_model.py', 'w') as f:
    f.write(code)
