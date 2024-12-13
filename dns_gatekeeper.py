import dns.message
import dns.resolver
import socket
import time
from concurrent.futures import ThreadPoolExecutor
import uuid
import argparse


class MyDNSGatekeeper:

    def __init__(self, primary_ns_host="127.0.0.1", primary_ns_port=31111,
                 secondary_ns_host="127.0.0.1", secondary_ns_port=31112, listen_address="", port=31110,
                 threshold=100, time_window=5, ban_duration=300):
        super().__init__()
        self.primary_ns_host = primary_ns_host
        self.secondary_ns_host = secondary_ns_host
        self.primary_ns_port = primary_ns_port
        self.secondary_ns_port = secondary_ns_port

        # Dynamic threshold values
        self.THRESHOLD = threshold
        self.TIME_WINDOW = time_window
        self.BAN_DURATION = ban_duration


        print("threshold is, ", self.THRESHOLD)

        # Track request history and blocked IPs
        self.history = {}  # {ip: {"count": int, "start_time": float}}
        self.blocked_ips = {}  # {ip: unblock_time}

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((listen_address, port))


    def validate(self, sender_ip):
        current_time = time.time()

        # Step 1: Check if IP is blocked
        if sender_ip in self.blocked_ips:
            if current_time < self.blocked_ips[sender_ip]:  # Still blocked
                print(f"Blocked request from {sender_ip}")
                return False
            else:
                # Unblock IP after ban duration
                del self.blocked_ips[sender_ip]
                print(f"Unblocked IP: {sender_ip}")

        # Step 2: Update request count and check for rate limiting
        if sender_ip not in self.history:
            self.history[sender_ip] = {"count": 0, "start_time": current_time}

        # Increment request count
        self.history[sender_ip]["count"] += 1
        elapsed_time = current_time - self.history[sender_ip]["start_time"]

        # Check if IP exceeds rate limit
        if self.history[sender_ip]["count"] > self.THRESHOLD and elapsed_time < self.TIME_WINDOW:
            print(f"Blocking {sender_ip} for excessive queries.")
            self.blocked_ips[sender_ip] = current_time + self.BAN_DURATION  # Ban for BAN_DURATION seconds
            del self.history[sender_ip]  # Remove history for blocked IP
            return False

        # Reset count after TIME_WINDOW
        if elapsed_time >= self.TIME_WINDOW:
            self.history[sender_ip] = {"count": 1, "start_time": current_time}

        return True

    def resolve(self, request):
        query_name = str(request.question[0].name)
        query_type = dns.rdatatype.to_text(request.question[0].rdtype)

        key = uuid.uuid4().int

        if hasattr(request, 'update') and len(request.update):
            return self.add_record(request)

        if key % 2 == 0:
            return self.forward_query(query_name, query_type, self.primary_ns_host, self.primary_ns_port)
        else:
            return self.forward_query(query_name, query_type, self.secondary_ns_host, self.secondary_ns_port)

    def forward_query(self, query_name, query_type, host, port):
        resolver = dns.resolver.Resolver()
        resolver.port = port
        resolver.nameservers = [host]
        return resolver.resolve(query_name, dns.rdatatype.from_text(query_type))

    def add_record(self, request):
        update = dns.update.Update(request.zone[0].name)
        address = [rd for rd in request.update[0].items][0].address
        update.add(request.update[0].name, 300, request.update[0].rdtype, address)
        dns.query.udp(update, self.primary_ns_host, port=self.primary_ns_port)
        print("Added record to Primary nameserver")
        return request.update[0]

    def reset_history(self):
        try:
            while True:
                time.sleep(self.TIME_WINDOW)  # Reset history periodically
                self.history = {}
                print("Reset history done")
        except KeyboardInterrupt:
            pass

    def run(self):
        try:
            while True:
                data, addr = self.socket.recvfrom(4096)
                sender_ip = addr[0]

                # Validate sender IP
                if not self.validate(sender_ip):
                    self.socket.sendto("IP banned".encode(), addr)
                    continue

                # Process DNS request
                try:
                    request = dns.message.from_wire(data)
                    reply = self.resolve(request)
                except Exception as e:
                    print(f"DNS ERROR: {e}")
                    continue

                # Create and send response
                response = dns.message.make_response(request)
                if hasattr(reply, 'rrset'):
                    response.answer.append(reply.rrset)
                else:
                    response.answer.append(reply)
                self.socket.sendto(response.to_wire(), addr)
        except KeyboardInterrupt:
            pass
        finally:
            self.socket.close()

    def perform_zone_transfers(self):
        try:
            while True:
                time.sleep(100)
                print("Performing a zone transfer")
                self.zone_transfer(self.secondary_ns_host, self.secondary_ns_port,
                                   self.primary_ns_host, self.primary_ns_port)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=31110, help="Specify DNS Gatekeeper port")
    parser.add_argument("--primary_ns_host", default="127.0.0.1", help="Specify primary DNS host")
    parser.add_argument("--primary_ns_port", type=int, default=31111, help="Specify primary DNS port")
    parser.add_argument("--secondary_ns_host", default="127.0.0.1", help="Specify secondary DNS host")
    parser.add_argument("--secondary_ns_port", type=int, default=31112, help="Specify secondary DNS port")
    parser.add_argument("--threshold", type=int, default=100, help="Max queries allowed in the time window")
    parser.add_argument("--time_window", type=int, default=5, help="Time window in seconds")
    parser.add_argument("--ban_duration", type=int, default=300, help="Duration to block IPs (in seconds)")
    args = parser.parse_args()

    resolver = MyDNSGatekeeper(
        primary_ns_host=args.primary_ns_host,
        primary_ns_port=args.primary_ns_port,
        secondary_ns_host=args.secondary_ns_host,
        secondary_ns_port=args.secondary_ns_port,
        port=args.port,
        threshold=args.threshold,
        time_window=args.time_window,
        ban_duration=args.ban_duration,
    )

    executor = ThreadPoolExecutor(3)
    executor.submit(resolver.run)
    executor.submit(resolver.perform_zone_transfers)
    executor.submit(resolver.reset_history)

