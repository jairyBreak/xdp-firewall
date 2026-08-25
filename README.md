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
- Multiple rules can be specified at startup (e.g. `-sp 443 8080 -dp 22 -ip 10.0.0.0/24`) and dynamically now (see [Here](#dynamic-rule-management-xdp-firewall-cli))
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

## Dynamic Rule Management (`xdp-firewall-cli`)

While `xdp-firewall` accepts rules at startup via command-line flags, rules
can also be added or inspected **while the program is running**, without
restarting it. This is done through a separate, independent tool:
`xdp-firewall-cli`.


### Starting the CLI

Make sure `xdp-firewall` is already running (it creates the pinned maps
on startup), then in a separate terminal:

```bash
sudo ./xdp-firewall-cli
```

### Available commands

| Command | Description |
|---|---|
| `block dst-port <port>` | Block a destination port |
| `block src-port <port>` | Block a source port |
| `block ip <cidr>` | Block an IP address or CIDR range (e.g. `10.0.0.0/24`) |
| `status` | Show all current rules and their hit counts |
| `unpin` | Remove all pinned maps (asks for confirmation) |
| `help` | Show the command list |
| `exit` / `quit` | Exit the CLI (does **not** unpin maps) |

### Example session

```bash
xdp-fw> block dst-port 22
Blocked destination port 22
xdp-fw> block ip 192.168.1.0/24
Blocked IP range 192.168.1.0/24
xdp-fw> status
Destination Port: 22, flag: 1, count: 0
IP 10.0.0.2: count: 4213
xdp-fw> exit
```
### Notes

- The rules set here remain active even after the CLI exits — they only
disappear if `xdp-firewall` itself is restart and the pinned maps are
removed (unpinned via the `unpin` command).
- `xdp-firewall-cli` requires `xdp-firewall` to already be running first;
 otherwise it will report that the pinned maps cannot be found.

# Benchmark: XDP vs iptables — Rule Count Scaling

## Test Setup
- Environment: single machine, two network namespaces (`host` / `client`) connected via a `veth` pair
- Attack: `hping3 -S -p 12345 --flood`, 10-second window
- Metric: number of packets dropped by the target rule (port 12345), read from XDP's rule counter / `iptables -L -v -n`
- Dummy rules (port 20000+) were inserted before the target rule to simulate realistic rule-set sizes — the worst case for iptables' linear scan

### Build Environment

```bash
# build environment
sudo ./script/setup_veth_env.sh

# xdp-firewall test
sudo ./script/gen_xdp_ports.sh <rule_number>
# will show sudo ip netns exec host ./xdp-firewall host_DEV -dp ... 12345
sudo ip netns exec host ./xdp-firewall host_DEV -dp ... 12345
# Ctrl + C to see the result

# iptable test
sudo ./script/add_iptables_rules.sh
# check the counter
sudo ip netns exec host iptables -L -v -n | grep 12345

# clean envirmonment
sudo ./script/cleanup_veth_env.sh
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

## Reproducing the Benchmark

The performance benchmark in this project was conducted inside network
namespaces (using `ip netns` + a `veth` pair) to simulate two hosts on a
single machine. This introduces one environmental quirk worth noting:

**bpffs pinning inside a network namespace is isolated from the host's
`/sys/fs/bpf`.** This means `bpf_map__pin()` calls in `xdp-firewall.c`
(used to expose maps to `xdp-firewall-cli`) will attempt to create a
directory in a namespace-local bpffs view, which may behave differently
than a normal deployment on a real interface.

If you're reproducing the benchmark results inside a similar `veth`/netns
setup, and you don't need the CLI tool during benchmarking, **comment out
the `ensure_bpf_fs_dir()` and `bpf_map__pin(...)` calls** in
`xdp-firewall.c` (around [line X]) before building. This avoids the
pinning step entirely — the benchmark itself doesn't rely on pinned maps;
only `xdp-firewall-cli` does.

In a normal deployment on a real network interface (not inside a network
namespace), pinning works as expected and no changes are needed.

