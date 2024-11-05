import argparse
from primary_dns.udp_dns_handler import MyUDPDNSHandler
from primary_dns.ssl_dns_handler import MySSLDNSHandler
from primary_dns.https_dns_handler import MyHTTPSDNSHandler

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=31111, help="Specify DNS port")
    parser.add_argument("--zone_file", default="zones/primary.zone", help="Specify zone file")
    parser.add_argument("--private_key_path", default="keys/primary.pem", help="Specify private key file")
    parser.add_argument("--mode", type=str, choices=['udp', 'ssl', 'https'], default='udp', help="Select mode: udp, ssl, or https")

    args = parser.parse_args()
    if args.mode == 'https':
        resolver = MyHTTPSDNSHandler(port=args.port, zone_file_path=args.zone_file, private_key_path=args.private_key_path)
    elif args.mode == 'ssl':
        resolver = MySSLDNSHandler(port=args.port, zone_file_path=args.zone_file, private_key_path=args.private_key_path)
    else:
        resolver = MyUDPDNSHandler(port=args.port, zone_file_path=args.zone_file, private_key_path=args.private_key_path)

    resolver.run()

