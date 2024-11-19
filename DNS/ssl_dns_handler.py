import socket
import ssl
import dns.message
import logging
from DNS.dns_handler import MyDNSHandler
import time

# Configure logging
logging.basicConfig(
    filename="/Users/harshil/Development/Dev_tests/folder_1/DoS-Secure-DNS-Server/baseline_experimentation/logs/ssl_handler.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class MySSLDNSHandler(MyDNSHandler):
    def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/primary.zone",
                 private_key_path=None, listen_address="0.0.0.0", port=853):
        super().__init__(forwarding_server, zone_file_path, private_key_path)
        self.listen_address = listen_address
        self.port = port

    def run(self):
        # Set up SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="ssl_certs/server.crt", keyfile="ssl_certs/server.key")

        # Create and bind the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.listen_address, self.port))
        sock.listen(5)

        logging.info(f"TLS DNS Server (DoT) listening on {self.listen_address}:{self.port}")

        try:
            while True:
                client_socket, addr = sock.accept()
                client_ip, client_port = addr

                logging.info(f"Connection accepted from {client_ip}:{client_port}")

                with context.wrap_socket(client_socket, server_side=True) as tls_socket:
                    try:
                        # Receive DNS query
                        data = tls_socket.recv(512)
                        start_time = time.time()

                        request = dns.message.from_wire(data)
                        query_name = str(request.question[0].name)
                        query_type = dns.rdatatype.to_text(request.question[0].rdtype)

                        logging.info(f"Received query: {query_name} ({query_type}) from {client_ip}:{client_port}")

                        # Handle the query
                        response_data = self.handle_request(request)
                        end_time = time.time()

                        response_time = end_time - start_time
                        logging.info(f"Query resolved: {query_name} ({query_type}) in {response_time:.3f} seconds")

                        # Send the response
                        if response_data:
                            tls_socket.send(response_data)
                            logging.info(f"Response sent for {query_name} to {client_ip}:{client_port}")
                        else:
                            logging.warning(f"No response data for query: {query_name} from {client_ip}:{client_port}")

                    except dns.exception.DNSException as e:
                        logging.error(f"Failed to process DNS query from {client_ip}:{client_port} - {str(e)}")
                    except Exception as e:
                        logging.error(f"Unexpected error with connection from {client_ip}:{client_port} - {str(e)}")

        except KeyboardInterrupt:
            logging.info("Shutting down TLS DNS server...")
        finally:
            sock.close()
            logging.info("TLS DNS Server (DoT) shut down")

    def handle_request(self, request):
        """
        Handles the DNS request, resolves the query, and prepares the response.
        """
        try:
            # Resolve the query
            reply = self.resolve(request)

            response = dns.message.make_response(request)

            if reply is not None:
                if hasattr(reply, 'rrset'):
                    response.answer.append(reply.rrset)
                else:
                    response.answer.append(reply)
            else:
                response.set_rcode(dns.rcode.NXRRSET)

            return response.to_wire()

        except dns.resolver.NXDOMAIN:
            logging.warning(f"Query not found: {str(request.question[0].name)}")
            return None
        except Exception as e:
            logging.error(f"Failed to handle request: {str(e)}")
            return None


# # OG Code
# # DNS/ssl_dns_handler.py

# import socket
# import ssl
# from DNS.dns_handler import MyDNSHandler
# import dns.message

# class MySSLDNSHandler(MyDNSHandler):
#     def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/primary.zone", private_key_path=None, listen_address="0.0.0.0", port=853):
#         super().__init__(forwarding_server, zone_file_path, private_key_path)
#         self.listen_address = listen_address
#         self.port = port

#     def run(self):
#         context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#         context.load_cert_chain(certfile="ssl_certs/server.crt", keyfile="ssl_certs/server.key")
        
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.bind((self.listen_address, self.port))
#         sock.listen(5)
        
#         print(f"TLS DNS Server (DoT) listening on {self.listen_address}:{self.port}")

#         try:
#             while True:
#                 client_socket, addr = sock.accept()
#                 with context.wrap_socket(client_socket, server_side=True) as tls_socket:
#                     data = tls_socket.recv(512)
#                     request = dns.message.from_wire(data)
#                     response_data = self.handle_request(request)
#                     if response_data:
#                         tls_socket.send(response_data)
#         except KeyboardInterrupt:
#             print("Shutting down TLS DNS server...")
#         finally:
#             sock.close()
