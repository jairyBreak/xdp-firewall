#!/bin/bash
# usage: ./add_iptables_rules.sh <rule_number>

N=$1
BASE_PORT=20000

sudo ip netns exec host iptables -F INPUT   

for i in $(seq 0 $((N-1))); do
    port=$((BASE_PORT + i))
    sudo ip netns exec host iptables -A INPUT -p tcp --dport $port -j DROP
done

sudo ip netns exec host iptables -A INPUT -p tcp --dport 12345 -j DROP

echo "Added $N dummy rules + 1 target rule (port 12345)"
sudo ip netns exec host iptables -L INPUT -v -n | wc -l