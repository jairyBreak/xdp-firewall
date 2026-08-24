#!/bin/bash
# usage: ./gen_xdp_ports.sh <rule_number>

N=$1
BASE_PORT=20000

PORTS=""
for i in $(seq 0 $((N-1))); do
    port=$((BASE_PORT + i))
    PORTS="$PORTS $port"
done
PORTS="$PORTS 12345"

echo "sudo ip netns exec host ./xdp-firewall host_DEV -dp$PORTS"