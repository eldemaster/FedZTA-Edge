import urllib.request
import pqcrypto.kem.ml_kem_512 as ml_kem
import time
import os

print(f"[*] Edge Node ({os.uname().machine}) starting...")

req = urllib.request.urlopen('http://192.168.1.144:9000/pubkey')
public_key = req.read()
print(f"[+] Received ML-KEM Public Key ({len(public_key)} bytes).")

start = time.time()
ciphertext, shared_secret = ml_kem.encaps(public_key)
end = time.time()

print(f"[+] Encapsulation complete in {(end-start)*1000:.2f} ms.")
print(f"[!] Post-Quantum Shared Secret Derived: {shared_secret.hex()[:32]}...")

req = urllib.request.Request('http://192.168.1.144:9000/exchange', data=ciphertext, method='POST')
urllib.request.urlopen(req)
print("[+] Ciphertext sent to Cloud.")
