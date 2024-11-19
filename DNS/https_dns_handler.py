import socket
import ssl
import re
import dns.message
import logging
from DNS.ssl_dns_handler import MySSLDNSHandler
import time

# Configure logging
logging.basicConfig(
    filename="/Users/harshil/Development/Dev_tests/folder_1/DoS-Secure-DNS-Server/baseline_experimentation/logs/https_handler.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class MyHTTPSDNSHandler(MySSLDNSHandler):
    def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/primary.zone",
                 private_key_path=None, listen_address="0.0.0.0", port=443):
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

        logging.info(f"HTTPS DNS Server (DoH) listening on {self.listen_address}:{self.port}")

        try:
            while True:
                client_socket, addr = sock.accept()
                client_ip, client_port = addr
                logging.info(f"Connection accepted from {client_ip}:{client_port}")

                with context.wrap_socket(client_socket, server_side=True) as https_socket:
                    try:
                        # Read HTTP headers
                        headers = https_socket.recv(1024).decode('utf-8')
                        logging.info(f"Received HTTP headers from {client_ip}:{client_port}")

                        # Extract Content-Length
                        content_length_match = re.search(r'Content-Length: (\d+)', headers)
                        if not content_length_match:
                            logging.error(f"Content-Length not found in headers from {client_ip}:{client_port}")
                            continue

                        content_length = int(content_length_match.group(1))

                        # Read DNS query
                        data = https_socket.recv(content_length)
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
                            response_headers = (
                                f"HTTP/1.1 200 OK\r\n"
                                f"Content-Type: application/dns-message\r\n"
                                f"Content-Length: {len(response_data)}\r\n\r\n"
                            )
                            https_socket.send(response_headers.encode('utf-8') + response_data)
                            logging.info(f"Response sent for {query_name} to {client_ip}:{client_port}")
                        else:
                            logging.warning(f"No response data for query: {query_name} from {client_ip}:{client_port}")
                            response_headers = "HTTP/1.1 500 Internal Server Error\r\n\r\n"
                            https_socket.send(response_headers.encode('utf-8'))

                    except dns.exception.DNSException as e:
                        logging.error(f"Failed to process DNS query from {client_ip}:{client_port} - {str(e)}")
                    except Exception as e:
                        logging.error(f"Unexpected error with connection from {client_ip}:{client_port} - {str(e)}")

        except KeyboardInterrupt:
            logging.info("HTTPS DNS Server (DoH) shutting down...")
        finally:
            sock.close()
            logging.info("HTTPS DNS Server (DoH) shut down")

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
# # DNS/https_dns_handler.py

# import socket
# import ssl
# import re
# from DNS.ssl_dns_handler import MySSLDNSHandler
# import dns.message

# class MyHTTPSDNSHandler(MySSLDNSHandler):
#     def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/primary.zone", private_key_path=None, listen_address="0.0.0.0", port=443):
#         super().__init__(forwarding_server, zone_file_path, private_key_path)
#         self.listen_address = listen_address
#         self.port = port

#     def run(self):
#         context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#         context.load_cert_chain(certfile="ssl_certs/server.crt", keyfile="ssl_certs/server.key")

#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.bind((self.listen_address, self.port))
#         sock.listen(5)
        
#         print(f"HTTPS DNS Server (DoH) listening on {self.listen_address}:{self.port}")

#         try:
#             while True:
#                 client_socket, addr = sock.accept()
#                 with context.wrap_socket(client_socket, server_side=True) as https_socket:
#                     headers = https_socket.recv(1024).decode('utf-8')
#                     content_length = int(re.search(r'Content-Length: (\d+)', headers).group(1))
#                     data = https_socket.recv(content_length)
                    
#                     request = dns.message.from_wire(data)
#                     response_data = self.handle_request(request)
                    
#                     if response_data:
#                         response_headers = f"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {len(response_data)}\r\n\r\n"
#                         https_socket.send(response_headers.encode('utf-8') + response_data)
#         except KeyboardInterrupt:
#             print("Shutting down HTTPS DNS server...")
#         finally:
#             sock.close()
