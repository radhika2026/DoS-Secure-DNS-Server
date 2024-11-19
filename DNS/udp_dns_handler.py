import socket
import dns.message
import dns.resolver
import logging
import time
from DNS.dns_handler import MyDNSHandler

# Configure logging
logging.basicConfig(
    filename="/Users/harshil/Development/Dev_tests/folder_1/DoS-Secure-DNS-Server/baseline_experimentation/logs/udp_handler.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class MyUDPDNSHandler(MyDNSHandler):
    def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/test_primary.zone",
                 private_key_path="./keys/primary.pem", listen_address="", port=31111):
        super().__init__(forwarding_server, zone_file_path, private_key_path)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((listen_address, port))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)

    def run(self):
        try:
            while True:
                try:
                    # Receive data from the client
                    data, addr = self.socket.recvfrom(4096)
                    client_ip, client_port = addr
                except ConnectionResetError as e:
                    logging.error(f"Connection reset by peer: {e}")
                    continue

                # Try to decode as a zone transfer message
                try:
                    message = data.decode('utf-8')
                    if message.split(' ')[0] == "ZONE_TRANSFER":
                        zone_name = message.split(' ')[1]
                        target_host = message.split(' ')[2]
                        target_port = int(message.split(' ')[3])
                        try:
                            self.handle_zone_transfer(zone_name, target_host, target_port)
                            logging.info(f"Zone Transfer successful: {zone_name} to {target_host}:{target_port}")
                            self.socket.sendto("SUCCESS".encode(), addr)
                        except Exception as e:
                            logging.error(f"Zone Transfer failed: {zone_name} to {target_host}:{target_port} - {str(e)}")
                            self.socket.sendto("FAILURE".encode(), addr)
                        finally:
                            continue
                except UnicodeDecodeError:
                    # If not a zone transfer message, treat as a DNS query
                    logging.info(f"DNS query received from {client_ip}:{client_port}")

                # Process the DNS query
                try:
                    request = dns.message.from_wire(data)
                    query_name = str(request.question[0].name)
                    query_type = dns.rdatatype.to_text(request.question[0].rdtype)

                    logging.info(f"Received query: {query_name} ({query_type}) from {client_ip}:{client_port}")
                    start_time = time.time()

                    # Resolve the query
                    reply = self.resolve(request)

                    end_time = time.time()
                    response_time = end_time - start_time

                    logging.info(
                        f"Query resolved: {query_name} ({query_type}) for {client_ip}:{client_port} in {response_time:.3f} seconds"
                    )
                except dns.resolver.NXDOMAIN:
                    logging.warning(f"Query not found: {query_name} from {client_ip}:{client_port}")
                    continue
                except Exception as e:
                    logging.error(f"Failed to process query from {client_ip}:{client_port} - {str(e)}")
                    continue

                # Handle AXFR/IXFR responses
                if query_type in ["AXFR", "IXFR"]:
                    try:
                        self.socket.sendto(reply.to_wire(), addr)
                        logging.info(f"Zone transfer response sent for {query_name} to {client_ip}:{client_port}")
                    except Exception as e:
                        logging.error(f"Failed to send zone transfer response: {str(e)}")
                    continue

                # Build and send the DNS response
                response = dns.message.make_response(request)
                if reply is not None:
                    if hasattr(reply, 'rrset'):
                        response.answer.append(reply.rrset)
                    else:
                        response.answer.append(reply)
                else:
                    response.set_rcode(dns.rcode.NXRRSET)

                try:
                    self.socket.sendto(response.to_wire(), addr)
                    logging.info(f"Response sent for {query_name} to {client_ip}:{client_port}")
                except Exception as e:
                    logging.error(f"Failed to send response to {client_ip}:{client_port} - {str(e)}")

        except KeyboardInterrupt:
            logging.info("UDP DNS handler shutting down")
        finally:
            self.socket.close()




# # OG code
# import socket
# from DNS.dns_handler import MyDNSHandler
# import dns.message

# class MyUDPDNSHandler(MyDNSHandler):
#     def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/test_primary.zone",
#                  private_key_path="./keys/primary.pem", listen_address="", port=31111):
#         super().__init__(forwarding_server, zone_file_path, private_key_path)
#         self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         self.socket.bind((listen_address, port))
#         self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
#         # self.socket.settimeout(5)

#     def run(self):
#         try:
#             while True:
#                 try:
#                     data, addr = self.socket.recvfrom(4096)
#                 except ConnectionResetError as e:
#                     print(f"Connection reset by peer: {e}")
#                     continue

#                 message = ""
#                 try:
#                     message = data.decode('utf-8')
#                 except Exception:
#                     print("dns query received")

#                 if message.split(' ')[0] == "ZONE_TRANSFER":
#                     try:
#                         self.handle_zone_transfer(message.split(' ')[1], message.split(' ')[2],
#                                                   int(message.split(' ')[3]))
#                         print("Zone Transfer successful")
#                         self.socket.sendto("SUCCESS".encode(), addr)
#                     except Exception:
#                         print("Zone Transfer failed")
#                         self.socket.sendto("FAILURE".encode(), addr)
#                     finally:
#                         continue

#                 # print(request)
#                 try:
#                     request = dns.message.from_wire(data)
#                     reply = self.resolve(request)
#                 except dns.resolver.NXDOMAIN:
#                     print("NOT FOUND")
#                     continue

#                 if (dns.rdatatype.to_text(request.question[0].rdtype) == "AXFR" or
#                         dns.rdatatype.to_text(request.question[0].rdtype) == "IXFR"):
#                     self.socket.sendto(reply.to_wire(), addr)
#                     continue

#                 response = dns.message.make_response(request)

#                 if reply is not None:
#                     if hasattr(reply, 'rrset'):
#                         response.answer.append(reply.rrset)
#                     else:
#                         response.answer.append(reply)
#                 else:
#                     response.set_rcode(dns.rcode.NXRRSET)

#                 self.socket.sendto(response.to_wire(), addr)

#         except KeyboardInterrupt:
#             pass
#         finally:
#             self.socket.close()