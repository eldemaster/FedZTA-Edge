from http.server import BaseHTTPRequestHandler, HTTPServer
import pqcrypto.kem.ml_kem_512 as ml_kem

print("[*] Cloud Aggregator (Ubuntu x86_64) starting...")
public_key, secret_key = ml_kem.keygen()
print(f"[+] ML-KEM-512 Keypair generated. PubKey Size: {len(public_key)} bytes.")

class PQC_Aggregator(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/pubkey':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(public_key)
            print("[+] Public Key sent to Edge Node.")

    def do_POST(self):
        if self.path == '/exchange':
            length = int(self.headers['Content-Length'])
            ciphertext = self.rfile.read(length)
            
            shared_secret = ml_kem.decaps(secret_key, ciphertext)
            
            print(f"[+] Received Ciphertext ({len(ciphertext)} bytes) from Edge.")
            print(f"[!] Post-Quantum Shared Secret Derived: {shared_secret.hex()[:32]}...")
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Key Exchange Successful\n")

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 9000), PQC_Aggregator)
    server.serve_forever()
