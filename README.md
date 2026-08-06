# XDP-firewall

A stateless packet-filtering firewall prototype built on XDP/eBPF, 
designed to explore whether XDP's in-driver packet processing can 
outperform traditional iptables-based filtering

base on [bpf-developer-tutorial/41-xdp-tcpdump](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/41-xdp-tcpdump)

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

Run the user-space program with the desired network interface and blocked tcp source and destination port:

```bash
sudo ./xdp-tcpdump wlp0s20f3 [-sp <port>...] [-dp <port>...]
```

Sample Output:

```bash
user@host:~/xdp-firewall$ sudo ./xdp-firewall wlp0s20f3 -sp 443 -dp 47290
Successfully attached XDP program to interface wlp0s20f3
Start polling ring buffer
Captured TCP Header:
  Source Port: 80
  Destination Port: 35720
  Sequence Number: 2199134217
  Acknowledgment Number: 1709720450
  Data Offset: 8
  Flags: 0x18
  Window Size: 75
```

Sample Output in termination of program:
```bash
---map_info---
Source Port Map: 80, flag: 0, count: 1
Source Port Map: 443, flag: 1, count: 25
Destination Port Map: 33932, flag: 0, count: 1
Destination Port Map: 50194, flag: 0, count: 8
Destination Port Map: 35720, flag: 0, count: 1
Destination Port Map: 49092, flag: 0, count: 2
Destination Port Map: 47290, flag: 1, count: 14
```

