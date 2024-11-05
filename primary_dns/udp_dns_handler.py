import socket
from primary_dns.dns_handler import MyDNSHandler
import dns.message

class MyUDPDNSHandler(MyDNSHandler):
    def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/test_primary.zone",
                 private_key_path="./keys/primary.pem", listen_address="", port=31111):
        super().__init__(forwarding_server, zone_file_path, private_key_path)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((listen_address, port))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        # self.socket.settimeout(5)

    def run(self):
        try:
            while True:
                try:
                    data, addr = self.socket.recvfrom(4096)
                except ConnectionResetError as e:
                    print(f"Connection reset by peer: {e}")
                    continue

                message = ""
                try:
                    message = data.decode('utf-8')
                except Exception:
                    print("dns query received")

                if message.split(' ')[0] == "ZONE_TRANSFER":
                    try:
                        self.handle_zone_transfer(message.split(' ')[1], message.split(' ')[2],
                                                  int(message.split(' ')[3]))
                        print("Zone Transfer successful")
                        self.socket.sendto("SUCCESS".encode(), addr)
                    except Exception:
                        print("Zone Transfer failed")
                        self.socket.sendto("FAILURE".encode(), addr)
                    finally:
                        continue

                # print(request)
                try:
                    request = dns.message.from_wire(data)
                    reply = self.resolve(request)
                except dns.resolver.NXDOMAIN:
                    print("NOT FOUND")
                    continue

                if (dns.rdatatype.to_text(request.question[0].rdtype) == "AXFR" or
                        dns.rdatatype.to_text(request.question[0].rdtype) == "IXFR"):
                    self.socket.sendto(reply.to_wire(), addr)
                    continue

                response = dns.message.make_response(request)

                if reply is not None:
                    if hasattr(reply, 'rrset'):
                        response.answer.append(reply.rrset)
                    else:
                        response.answer.append(reply)
                else:
                    response.set_rcode(dns.rcode.NXRRSET)

                self.socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            pass
        finally:
            self.socket.close()