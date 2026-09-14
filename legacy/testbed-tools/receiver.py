from http.server import BaseHTTPRequestHandler, HTTPServer
class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        with open(self.path.lstrip('/'), 'wb') as f:
            f.write(self.rfile.read(length))
        self.send_response(200)
        self.end_headers()
HTTPServer(('0.0.0.0', 8080), Receiver).serve_forever()
