import json
import numpy as np
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

# Global state
clients_weights = []
global_weights = {"coef": None, "intercept": None}
MIN_CLIENTS_TO_AGGREGATE = 2
lock = threading.Lock()

class FedAvgHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Edge nodes request the latest global weights
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        with lock:
            response = json.dumps(global_weights)
        self.wfile.write(response.encode('utf-8'))

    def do_POST(self):
        # Edge nodes submit their local weights
        global clients_weights, global_weights
        
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        local_model = json.loads(post_data.decode('utf-8'))
        
        with lock:
            clients_weights.append(local_model)
            print(f"[Cloud] Received weights from an Edge node. Total received: {len(clients_weights)}")
            
            # If we have enough models, perform FedAvg!
            if len(clients_weights) >= MIN_CLIENTS_TO_AGGREGATE:
                print(f"[Cloud] {MIN_CLIENTS_TO_AGGREGATE} models received. Performing Federated Averaging (FedAvg)...")
                
                # Aggregate coefficients
                all_coefs = np.array([m["coef"] for m in clients_weights])
                avg_coef = np.mean(all_coefs, axis=0)
                
                # Aggregate intercepts
                all_intercepts = np.array([m["intercept"] for m in clients_weights])
                avg_intercept = np.mean(all_intercepts, axis=0)
                
                global_weights["coef"] = avg_coef.tolist()
                global_weights["intercept"] = avg_intercept.tolist()
                
                print("[Cloud] Global model updated successfully!")
                # Reset for next round
                clients_weights = []

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "success"}')

def run(server_class=HTTPServer, handler_class=FedAvgHandler, port=8000):
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)
    print(f"[Cloud] Federated Learning Aggregator listening on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
