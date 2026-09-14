import re

with open('generate_website_v5_mermaid.py', 'r') as f:
    content = f.read()

old_flower = """        "mermaid": \"\"\"graph TD
    A((Global Server))
    B[Client 1: PyTorch / ARM]
    C[Client 2: TensorFlow / x86]
    D[Client 3: CoreML / iOS]"""

new_flower = """        "mermaid": \"\"\"graph TD
    A(("Global Server"))
    B["Client 1: PyTorch / ARM"]
    C["Client 2: TensorFlow / x86"]
    D["Client 3: CoreML / iOS"]"""

content = content.replace(old_flower, new_flower)

old_open5gs = """        "mermaid": \"\"\"graph TD
    A[5G UE / Phone] <-->|Radio| B[gNodeB / Base Station]
    B <-->|N1/N2| C(AMF)
    B <-->|N3| D(UPF)
    C <-->|N11| E(SMF)
    E <-->|N4| D
    D <-->|N6| F[Internet / Edge Cloud]"""

new_open5gs = """        "mermaid": \"\"\"graph TD
    A["5G UE / Phone"] <-->|"Radio"| B["gNodeB / Base Station"]
    B <-->|"N1/N2"| C("AMF")
    B <-->|"N3"| D("UPF")
    C <-->|"N11"| E("SMF")
    E <-->|"N4"| D
    D <-->|"N6"| F["Internet / Edge Cloud"]"""

content = content.replace(old_open5gs, new_open5gs)

with open('generate_website_v5_mermaid.py', 'w') as f:
    f.write(content)

