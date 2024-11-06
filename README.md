# DoS-Secure-DNS-Server
The project focuses on exploring data replication among multiple DNS servers to boost resilience against localized denial of service (DoS) attacks. The primary objective is to evaluate how data replication within DNS infrastructure can mitigate DoS threats by avoiding single points of failure, thus improving overall service resilience.

## Architecture
![Architecture](./architecture%20diagram/architecture.png)
## Getting Started

### Step 1: Run the Primary DNS Server
To start the primary DNS server, execute the following command:

```bash
python main.py --port 31111 --zone_file zones/primary.zone --private_key_path keys/primary.pem --mode udp 
```

### Step 2: Run the Secondary DNS Server
Open a separate command prompt and start the secondary DNS server with
```bash
python main.py --port 31112 --zone_file zones/secondary.zone --private_key_path keys/secondary.pem --mode udp
```

### Step 3: Start the gatekeeper
To manage the primary and secondary DNS servers, open a separate command prompt and run:
```bash
python dns_gatekeeper.py --primary_ns_host=127.0.0.1 --primary_ns_port=31111 --secondary_ns_host=127.0.0.1 --secondary_ns_port=31112 --port=31110
```
The gatekeeper will now route traffic between the primary and secondary DNS servers.

### Step 4: Test the setup:
To verify the DNS setup, execute the test script:
```bash
python3 test.py
```

### Step 5: Start the DoS Attack
To initiate a DoS attack simulation, run the attack script with the following parameters:
```bash
python3 attack.py --host=127.0.0.1 --port=31110 --timeout=100 --num_threads=10
```
