# DNS/ssl_dns_handler.py

import socket
import ssl
from DNS.dns_handler import MyDNSHandler
import dns.message

class MySSLDNSHandler(MyDNSHandler):
    def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/primary.zone", private_key_path=None, listen_address="0.0.0.0", port=853):
        super().__init__(forwarding_server, zone_file_path, private_key_path)
        self.listen_address = listen_address
        self.port = port

    def run(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="ssl_certs/server.crt", keyfile="ssl_certs/server.key")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.listen_address, self.port))
        sock.listen(5)
        
        print(f"TLS DNS Server (DoT) listening on {self.listen_address}:{self.port}")

        try:
            while True:
                client_socket, addr = sock.accept()
                with context.wrap_socket(client_socket, server_side=True) as tls_socket:
                    data = tls_socket.recv(512)
                    request = dns.message.from_wire(data)
                    response_data = self.handle_request(request)
                    if response_data:
                        tls_socket.send(response_data)
        except KeyboardInterrupt:
            print("Shutting down TLS DNS server...")
        finally:
            sock.close()
