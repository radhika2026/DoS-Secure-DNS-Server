# DNS/https_dns_handler.py

import socket
import ssl
import re
from DNS.ssl_dns_handler import MySSLDNSHandler
import dns.message

class MyHTTPSDNSHandler(MySSLDNSHandler):
    def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/primary.zone", private_key_path=None, listen_address="0.0.0.0", port=443):
        super().__init__(forwarding_server, zone_file_path, private_key_path)
        self.listen_address = listen_address
        self.port = port

    def run(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="ssl_certs/server.crt", keyfile="ssl_certs/server.key")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.listen_address, self.port))
        sock.listen(5)
        
        print(f"HTTPS DNS Server (DoH) listening on {self.listen_address}:{self.port}")

        try:
            while True:
                client_socket, addr = sock.accept()
                with context.wrap_socket(client_socket, server_side=True) as https_socket:
                    headers = https_socket.recv(1024).decode('utf-8')
                    content_length = int(re.search(r'Content-Length: (\d+)', headers).group(1))
                    data = https_socket.recv(content_length)
                    
                    request = dns.message.from_wire(data)
                    response_data = self.handle_request(request)
                    
                    if response_data:
                        response_headers = f"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {len(response_data)}\r\n\r\n"
                        https_socket.send(response_headers.encode('utf-8') + response_data)
        except KeyboardInterrupt:
            print("Shutting down HTTPS DNS server...")
        finally:
            sock.close()
