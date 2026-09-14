import urllib.request
import pqcrypto.kem.ml_kem_512 as ml_kem

print("[*] Edge Node starting... Connecting to Traffic Monitor (Port 9001)")
# Fetch Public Key through Monitor
req = urllib.request.urlopen('http://192.168.1.144:9001/pubkey')
public_key = req.read()

ciphertext, shared_secret = ml_kem.encaps(public_key)

# Send Ciphertext through Monitor
req = urllib.request.Request('http://192.168.1.144:9001/exchange', data=ciphertext, method='POST')
urllib.request.urlopen(req)
print("[+] Transaction complete.")
