#!/bin/bash
# usage: cleanup_veth_env.sh

sudo pkill -x xdp-firewall 2>/dev/null || true
sudo ip netns del host 2>/dev/null || true
sudo ip netns del client 2>/dev/null || true
echo "Environment cleaned up"