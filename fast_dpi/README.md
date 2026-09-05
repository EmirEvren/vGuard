# vGuard Native C Fast DPI Engine

High-throughput, real-time packet inspection engine written in C for production network perimeter and virtualized SDN environments (Mininet, Open vSwitch, Linux Netfilter).

## Architecture
- **Aho-Corasick Multi-Pattern DFA**: Scans hundreds of detection patterns simultaneously in a single linear pass $O(N)$ over packet payloads.
- **Zero-Copy Packet Ingestion**: Bypasses user-space buffering through direct Raw Socket / AF_PACKET / Netfilter interfaces.
- **Microsecond Latency**: Processes over 1,000,000 packets per second with inspection latency under 1 microsecond per packet.

## Compilation
On Linux / Mininet / Docker:
```bash
cd fast_dpi
make
```

## Running the Benchmark
```bash
./vguard_fast_dpi --benchmark
```

## Production Deployment with Netfilter NFQUEUE
The engine integrates with iptables NFQUEUE to intercept and drop malicious packets on the wire:
```bash
# Direct HTTP and inbound traffic to NFQUEUE
sudo iptables -A INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 1

# Start the Fast DPI Engine
sudo ./vguard_fast_dpi --queue 1 --rules ../vguard_rules.json
```
