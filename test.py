import dns.resolver
import dns.update
import dns.query
import dns.zone
import socket
import logging

# Configure logging
logging.basicConfig(
    filename="baseline_experimentation/logs/test_metrics.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def get_record():
    """
    Retrieves DNS records using the local resolver.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.port = 31111
        resolver.nameservers = ["127.0.0.1"]

        logging.info("Performing A record lookup for ns1.example.com")
        answers = resolver.resolve('ns1.example.com', dns.rdatatype.A)
        for rdata in answers:
            logging.info(f"Record retrieved: {rdata}")

        logging.info("Performing A record lookup for www.google.com")
        answers = resolver.resolve('www.google.com', dns.rdatatype.A)
        for rdata in answers:
            logging.info(f"Record retrieved: {rdata}")

    except Exception as e:
        logging.error(f"Failed to retrieve records: {str(e)}")

def add_record():
    """
    Adds a DNS record to the local DNS server.
    """
    try:
        update = dns.update.Update("example.com")
        update.add("ns8", 300, "A", "192.168.2.1")

        logging.info("Adding A record for ns8.example.com with IP 192.168.2.1")
        response = dns.query.udp(update, "127.0.0.1", port=31110)
        logging.info(f"Record addition response: {response}")

    except Exception as e:
        logging.error(f"Failed to add record: {str(e)}")

def perform_axfr_query(zone_name="example.com", master_ip="127.0.0.1"):
    """
    Performs an AXFR query to transfer zone data from the primary server.
    """
    try:
        logging.info(f"Initiating AXFR query for zone {zone_name} from {master_ip}")
        axfr_request = dns.query.xfr(master_ip, zone_name, rdtype=dns.rdatatype.IXFR, port=31111,
                                     use_udp=True, relativize=False)
        zone = dns.zone.from_xfr(axfr_request, relativize=False)
        logging.info(f"Zone transfer successful: {zone.to_text()}")
    except Exception as e:
        logging.error(f"AXFR query failed for zone {zone_name} from {master_ip}: {str(e)}")

def udp_client(host="127.0.0.1", port=31112, message="ZONE_TRANSFER example.com 127.0.0.1 31111"):
    """
    Sends a UDP message to the server and logs the response.
    """
    try:
        # Create a UDP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Send a message to the server
        logging.info(f"Sending UDP message to {host}:{port} - {message}")
        client_socket.sendto(message.encode('utf-8'), (host, port))

        # Receive the response from the server
        response, server_address = client_socket.recvfrom(1024)
        decoded_response = response.decode('utf-8')
        logging.info(f"Response from server {server_address}: {decoded_response}")

    except Exception as e:
        logging.error(f"Failed to send UDP message or receive response: {str(e)}")

    finally:
        # Close the socket
        client_socket.close()

# Run the tests and log their results
if __name__ == "__main__":
    logging.info("Starting DNS test operations")

    get_record()
    add_record()
    perform_axfr_query()
    udp_client()

    logging.info("Completed DNS test operations")

# # OG Code
# import dns.resolver
# import dns.update
# import dns.dnssec
# import socket

# def get_record():
#     resolver = dns.resolver.Resolver()
#     resolver.port = 31111
#     resolver.nameservers = ["127.0.0.1"]
#     answers = resolver.resolve('ns1.example.com', dns.rdatatype.A)

#     for rdata in answers:
#         print(rdata)

#     answers = resolver.resolve('www.google.com', dns.rdatatype.A)

#     for rdata in answers:
#         print(rdata)

# def add_record():
#     update = dns.update.Update("example.com")

#     update.add("ns8", 300, "A", "192.168.2.1")

#     print(dns.query.udp(update, "127.0.0.1", port=31110))

# def perform_axfr_query(zone_name="example.com", master_ip="127.0.0.1"):
#     # Create an AXFR query
#     axfr_request = dns.query.xfr(master_ip, zone_name, rdtype=dns.rdatatype.IXFR, port=31111,
#                                  use_udp=True, relativize=False)

#     # Perform the AXFR query and iterate over response messages
#     # for response in axfr_request:
#     #     if response.rcode() != dns.rcode.NOERROR:
#     #         print(f"AXFR query failed with response code: {dns.rcode.to_text(response.rcode())}")
#     #         break
#     # #
#     # #     # Process the response (you can print or save the data)
#     #     print(response.to_text())

#     zone = dns.zone.from_xfr(axfr_request, relativize=False)
#     print(zone)

# def udp_client(host="127.0.0.1", port=31112, message="ZONE_TRANSFER example.com 127.0.0.1 31111"):
#     # Create a UDP socket
#     client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#     # Send a message to the server
#     client_socket.sendto(message.encode('utf-8'), (host, port))

#     # Receive the response from the server
#     response, server_address = client_socket.recvfrom(1024)

#     # Decode and print the response
#     decoded_response = response.decode('utf-8')
#     print(f"Response from server {server_address}: {decoded_response}")

#     # Close the socket
#     client_socket.close()

# get_record()