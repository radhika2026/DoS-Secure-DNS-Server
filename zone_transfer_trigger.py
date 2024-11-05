import socket
import argparse

def trigger_zone_transfer(secondary_host, secondary_port, zone_name, primary_host, primary_port):
    # Create the ZONE_TRANSFER message
    message = f"ZONE_TRANSFER {zone_name} {primary_host} {primary_port}"
    
    # Initialize UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        # Send the ZONE_TRANSFER message to the secondary DNS server
        client_socket.sendto(message.encode('utf-8'), (secondary_host, secondary_port))
        print(f"Sent zone transfer request to {secondary_host}:{secondary_port}")

        # Wait for a response from the secondary server
        try:
            response, server_address = client_socket.recvfrom(1024)
            print(f"Response from server {server_address}: {response.decode('utf-8')}")
        except socket.timeout:
            print("No response received, zone transfer may have failed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trigger a zone transfer on the secondary DNS server.")
    parser.add_argument("--secondary_host", default="127.0.0.1", help="Secondary DNS server IP")
    parser.add_argument("--secondary_port", type=int, default=31112, help="Secondary DNS server port")
    parser.add_argument("--zone_name", default="example.com", help="Zone name to transfer")
    parser.add_argument("--primary_host", default="127.0.0.1", help="Primary DNS server IP")
    parser.add_argument("--primary_port", type=int, default=31111, help="Primary DNS server port")
    args = parser.parse_args()

    # Trigger the zone transfer
    trigger_zone_transfer(args.secondary_host, args.secondary_port, args.zone_name, args.primary_host, args.primary_port)
