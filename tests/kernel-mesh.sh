#!/usr/bin/env bash
# Run as root on Linux after cargo build --workspace. All links live in netns.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run this test as root'; exit 1; }
bin=$(realpath "${1:-rust/target/debug}")
work=$(mktemp -d)
prefix="wgmesh-$$"
pids=()
cleanup() {
  local status=$?
  if (( status != 0 )); then cat "$work"/*.log >&2 || true; fi
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  for node in hub a b switch; do ip netns del "$prefix-$node" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT
for node in hub a b switch; do ip netns add "$prefix-$node"; done
ip -n "$prefix-switch" link add br0 type bridge
ip -n "$prefix-switch" link set br0 up
index=1
for node in hub a b; do
  ip -n "$prefix-switch" link add "v-$node" type veth peer name "p-$node"
  ip -n "$prefix-switch" link set "p-$node" netns "$prefix-$node"
  ip -n "$prefix-switch" link set "v-$node" master br0
  ip -n "$prefix-switch" link set "v-$node" up
  ip -n "$prefix-$node" link set "p-$node" name eth0
  ip -n "$prefix-$node" addr add "192.0.2.$index/24" dev eth0
  ip -n "$prefix-$node" link set eth0 up
  ip -n "$prefix-$node" link set lo up
  ssh-keygen -q -t ed25519 -N '' -f "$work/$node"
  index=$((index + 1))
done
cat "$work/a.pub" "$work/b.pub" > "$work/signers"
cat > "$work/coord.json" <<JSON
{"listen_addr":"192.0.2.1:8443","mesh_cidr":"10.42.0.0/16",
 "state_path":"$work/state.json","authorized_signers":"$work/signers",
 "wg_ssh_key":"$work/hub"}
JSON
ip netns exec "$prefix-hub" sysctl -qw net.ipv4.ip_forward=1
# Force initial traffic through the relay while direct peers are PROBING.
ip netns exec "$prefix-a" iptables -A OUTPUT -p udp -d 192.0.2.3 --dport 51820 -j DROP
ip netns exec "$prefix-b" iptables -A OUTPUT -p udp -d 192.0.2.2 --dport 51820 -j DROP
ip netns exec "$prefix-hub" "$bin/wgmesh-coord" -c "$work/coord.json" > "$work/hub.log" 2>&1 &
hub_pid=$!; pids+=("$hub_pid")
for node in a b; do
  ip netns exec "$prefix-$node" "$bin/wgmesh-agent" --coordinator http://192.0.2.1:8443 \
    --ssh-key "$work/$node" --poll-secs 1 --include-lan > "$work/$node.log" 2>&1 &
  pids+=("$!")
done
# Use a node's actual assigned address; registration order is nondeterministic.
mesh_ip() { ip -n "$prefix-$1" -o -4 addr show dev wg0 | awk '{split($4,a,"/"); print a[1]}'; }
wait_for() {
  local attempts=$1; shift
  for ((i=0; i<attempts; i++)); do if "$@"; then return 0; fi; sleep 1; done
  echo "Timed out: $*" >&2; return 1
}
registered() { [[ -n $(mesh_ip a 2>/dev/null) && -n $(mesh_ip b 2>/dev/null) ]]; }
wait_for 30 registered
a_ip=$(mesh_ip a); b_ip=$(mesh_ip b)
a_key=$("$bin/ssh-to-wg" < "$work/a.pub")
b_key=$("$bin/ssh-to-wg" < "$work/b.pub")
ping_b() { ip netns exec "$prefix-a" ping -c 1 -W 1 "$b_ip" > /dev/null; }
wait_for 10 ping_b
echo 'Relay forwarding works while direct endpoints are blocked'
ip netns exec "$prefix-a" iptables -F OUTPUT
ip netns exec "$prefix-b" iptables -F OUTPUT
direct() {
  ip netns exec "$prefix-a" wg show wg0 allowed-ips | grep -F "$b_key" | grep -qF "$b_ip/32" &&
  ip netns exec "$prefix-b" wg show wg0 allowed-ips | grep -F "$a_key" | grep -qF "$a_ip/32"
}
wait_for 30 direct
wait_for 10 ping_b
echo 'Direct peer promotion and forwarding work'
# This used to leave A in the relay and B's /peers list for the 600-second TTL.
cat "$work/b.pub" > "$work/signers"
kill -HUP "$hub_pid"
revoked() {
  ! ip netns exec "$prefix-hub" wg show wg0 peers | grep -qF "$a_key" &&
  ! ip netns exec "$prefix-b" wg show wg0 peers | grep -qF "$a_key"
}
wait_for 15 revoked
if ip netns exec "$prefix-b" ping -c 1 -W 1 "$a_ip" > /dev/null; then
  echo 'Revoked node is still reachable' >&2; exit 1
fi
echo 'Revocation removed kernel peers without waiting for TTL'
