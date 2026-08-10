#!/bin/bash
# Set up host/client network namespaces connected via a veth pair.
# Usage: sudo ./setup_veth_env.sh

set -e

HOST_NS="host"
CLIENT_NS="client"
HOST_DEV="host_DEV"
CLIENT_DEV="client_DEV"
HOST_IP="10.0.0.1/24"
CLIENT_IP="10.0.0.2/24"

ip netns del "$HOST_NS" 2>/dev/null || true
ip netns del "$CLIENT_NS" 2>/dev/null || true
ip link del "$HOST_DEV" 2>/dev/null || true

ip netns add "$HOST_NS"
ip netns add "$CLIENT_NS"

ip link add "$HOST_DEV" type veth peer name "$CLIENT_DEV"

ip link set "$HOST_DEV" netns "$HOST_NS"
ip link set "$CLIENT_DEV" netns "$CLIENT_NS"

ip -n "$HOST_NS" link set lo up
ip -n "$HOST_NS" link set "$HOST_DEV" up

ip -n "$CLIENT_NS" link set lo up
ip -n "$CLIENT_NS" link set "$CLIENT_DEV" up

ip -n "$HOST_NS" addr add "$HOST_IP" dev "$HOST_DEV"
ip -n "$CLIENT_NS" addr add "$CLIENT_IP" dev "$CLIENT_DEV"

if ip netns exec "$CLIENT_NS" ping -c 2 -W 1 10.0.0.1 > /dev/null 2>&1; then
    echo "OK: host <-> client reachable"
else
    echo "FAIL: ping did not succeed, please check manually"
    exit 1
fi

echo ""
echo "Host namespace:   $HOST_NS  ($HOST_DEV, $HOST_IP)"
echo "Client namespace: $CLIENT_NS ($CLIENT_DEV, $CLIENT_IP)"