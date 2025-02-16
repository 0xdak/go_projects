from http.server import HTTPServer, SimpleHTTPRequestHandler
import random
import socket
import concurrent.futures



def open_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                print(f"[!] Port {port} is already in use")
                return

        print(f"[+] Opening Port {port}")
        server = HTTPServer(("", port), SimpleHTTPRequestHandler)
        server.serve_forever()
    except Exception as e:
        print(f"[ERROR] Could not open port {port}: {e}")

unique_ports = set()
while len(unique_ports) < 30:
    unique_ports.add(random.randint(1, 65535))

with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
    for port in unique_ports:
        pool.submit(open_port, port)

