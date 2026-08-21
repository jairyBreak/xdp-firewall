# XDP-firewall

A stateless packet-filtering firewall prototype built on XDP/eBPF, 
designed to explore whether XDP's in-driver packet processing can 
outperform traditional iptables-based filtering

(work in progress)

base on [bpf-developer-tutorial/41-xdp-tcpdump](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/41-xdp-tcpdump)

## Features

### Packet Filtering
- **TCP source/destination port filtering** — exact-match hash map lookup, supports blocking by source port, destination port, or both
- **IP address filtering** — supports both exact-match blocking and CIDR range blocking via LPM trie (`BPF_MAP_TYPE_LPM_TRIE`)
- Multiple rules can be specified at startup (e.g. `-sp 443 8080 -dp 22 -ip 10.0.0.0/24`)
- Per-rule traffic statistics (hit count) tracked for every port/IP rule

### Rate Limiting (Token Bucket)
- Per-source-IP rate limiting using a token bucket algorithm
- Configurable at startup via `-rate` (tokens refilled per millisecond) and `-cap` (bucket capacity)
- Per-IP drop counters track how many packets were rejected due to rate limiting

### Observability
- Ring-buffer-based packet capture for inspecting live traffic (toggleable via `-verbose`)
- End-of-run statistics summary for all rule types (port rules, IP rules, rate-limit buckets)

## Compilation and Execution Instructions
### Building the Program
```bash
cd xdp-firewall
make
```
This command compiles both the kernel eBPF code and the user-space application.

### Running the Program

First, identify your network interfaces:

```bash
ifconfig
```

Sample output:

```
wlp0s20f3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 00:1a:2b:3c:4d:5e  txqueuelen 1000  (Ethernet)
```

Run the user-space program with the desired network interface and blocked IP address, tcp source and destination port:

```bash
sudo ./xdp-firewall wlp0s20f3 [-ip <X.X.X.X/prefixlen>...] [-sp <port>...] [-dp <port>...] [-rate <refill_rate> (packet per ms)] [-cap <max capacity>] [-verbose]
```

Sample Output:

```bash
user@host:~/xdp-firewall$ sudo ./xdp-firewall wlp0s20f3 -sp 443 -dp 47290
Successfully attached XDP program to interface wlp0s20f3
Start polling ring buffer

# if accept the verbose
Captured TCP Header:
  Source Port: 1717
  Destination Port: 12345
  Sequence Number: 1637944930
  Acknowledgment Number: 1335303973
  Data Offset: 5
  Flags: 0x02
  Window Size: 512
```

Sample Output in termination of program: rule execution statistics collected from BPF Maps (flag: 1 indicates dropped rule, count indicates matched packets):
```bash
---map_info---
IP Rule: 10.0.0.2/32, flag: 0, count: 5
Source Port: 1717, flag: 0, count: 1
Source Port: 1715, flag: 0, count: 1
Source Port: 1718, flag: 0, count: 1
Source Port: 1714, flag: 0, count: 1
Source Port: 1716, flag: 0, count: 1
Destination Port: 12345, flag: 1, count: 5
---bucket drop info---
IP 10.0.0.2: token=499, dropped=0
```

# Benchmark: XDP vs iptables — Rule Count Scaling

## Test Setup
- Environment: single machine, two network namespaces (`host` / `client`) connected via a `veth` pair
- Attack: `hping3 -S -p 12345 --flood`, 10-second window
- Metric: number of packets dropped by the target rule (port 12345), read from XDP's rule counter / `iptables -L -v -n`
- Dummy rules (port 20000+) were inserted before the target rule to simulate realistic rule-set sizes — the worst case for iptables' linear scan

### Build Environment

```bash
# build environment
sudo ./setup_veth_env.sh

# xdp-firewall test
sudo ./gen_xdp_ports.sh <rule_number>
# will show sudo ip netns exec host ./xdp-firewall host_DEV -dp ... 12345
sudo ip netns exec host ./xdp-firewall host_DEV -dp ... 12345
# Ctrl + C to see the result

# iptable test
sudo ./add_iptables_rules.sh
# check the counter
sudo ip netns exec host iptables -L -v -n | grep 12345

# clean envirmonment
sudo cleanup_veth_env.sh
```
## Results

| Rule count | XDP (pps) | iptables (pps) |
|---|---|---|
| 1     | 238,391 | 273,800 |
| 100   | 238,237 | 276,500 |
| 500   | 237,800 | 157,300 |
| 1000  | 237,325 |  83,000 |

XDP's throughput stays essentially flat across all rule counts (<1% variation from 1 to 1000 rules), consistent with O(1) hash map lookup. iptables is competitive at low rule counts but degrades sharply as the rule chain grows — down 70% at 1000 rules versus its own 1-rule baseline. At 1000 rules, XDP outperforms iptables by ~2.9x.

This matches the expected architectural difference: iptables scans its rule chain linearly (O(n)), so matching a rule near the end of a long chain gets proportionally slower as more rules are added, while XDP's hash-map lookup stays O(1) regardless of rule count.

## CPU Isolation Check

Since sender (`hping3`) and receiver (packet processing) share the same machine's CPUs in this veth setup, we re-ran the 1000-rule test with the two isolated onto separate cores — RPS steered `host_DEV`'s packet processing to one CPU, while `taskset` pinned `hping3` to another:

```bash
sudo ip netns exec host bash -c 'echo 4 > /sys/class/net/host_DEV/queues/rx-0/rps_cpus'
sudo taskset -c 5 timeout 10 ip netns exec client hping3 -S -p 12345 --flood 10.0.0.1
```

After isolation, iptables' throughput recovered by ~31%, while XDP was unaffected. XDP still held a ~2.9x advantage, confirming the rule-count scaling gap is a real architectural effect — CPU contention only amplified it in this single-machine test setup, it wasn't the root cause.

