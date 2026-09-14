import socket
import threading

def hexdump(src, length=16):
    result = []
    digits = 2
    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join([b"%02X" % x for x in s])
        text = b''.join([bytes([x]) if 0x20 <= x < 0x7F else b'.' for x in s])
        result.append(b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text))
    return b'\n'.join(result).decode('utf-8')

def handle_client(client_socket, target_host, target_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((target_host, target_port))
    
    def forward(source, destination, label):
        try:
            while True:
                data = source.recv(4096)
                if len(data) == 0:
                    break
                print(f"\n[{label}] Captured {len(data)} bytes:")
                print(hexdump(data[:128])) # Print first 128 bytes of payload
                if len(data) > 128:
                    print(f"... (truncated {len(data)-128} bytes)")
                destination.send(data)
        except Exception:
            pass
        finally:
            source.close()
            destination.close()
            
    t1 = threading.Thread(target=forward, args=(client_socket, server_socket, "EDGE -> CLOUD"))
    t2 = threading.Thread(target=forward, args=(server_socket, client_socket, "CLOUD -> EDGE"))
    t1.start()
    t2.start()

def main():
    monitor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    monitor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    monitor.bind(('0.0.0.0', 9001))
    monitor.listen(5)
    print("[*] Traffic Monitor listening on port 9001. Forwarding to Cloud on 9000...")
    
    while True:
        client_socket, addr = monitor.accept()
        print(f"\n[+] New connection established from {addr[0]}:{addr[1]}")
        t = threading.Thread(target=handle_client, args=(client_socket, '127.0.0.1', 9000))
        t.start()

if __name__ == '__main__':
    main()
