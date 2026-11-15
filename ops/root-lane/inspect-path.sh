#!/bin/bash
# Read-only, second step after inspect.sh (operator act 72). The lane's ssh to 127.0.0.1 reached sshd from
# 192.3.84.103 (sshd log 2026-11-15T04:24:31Z "authenticating user root 192.3.84.103 … [preauth]"; no loopback line),
# so the root Match on 127.0.0.1,::1 never applied. This prints what could turn a loopback connect into one from the
# public address: the ssh client config, NAT rules, the gateway's unit and network namespace. Changes nothing.
# Run as root on racknerd, fed over stdin by phasewhip under an operator act bound to this file's sha256.
set -u
export LC_ALL=C
nc() { grep -n -v -E '^[[:space:]]*(#|$)' "$@" 2>/dev/null; }
echo "== host $(hostname) $(date -u +%FT%TZ)"
echo "== ssh client config"
for f in /etc/ssh/ssh_config /etc/ssh/ssh_config.d/* /root/.ssh/config; do [ -e "$f" ] && { echo "-- $f"; nc "$f"; }; done
echo "== ssh -G 127.0.0.1 as root (selected keys)"
ssh -G -l root 127.0.0.1 2>&1 | grep -E '^(hostname|port|bindaddress|bindinterface|proxycommand|proxyjump|addressfamily|hostkeyalias|canonicalizehostname) '
echo "== addresses and routes"
ip -br addr 2>&1
ip route get 127.0.0.1 2>&1
ip route get 192.3.84.103 2>&1
sysctl net.ipv4.conf.all.route_localnet net.ipv4.conf.lo.route_localnet 2>&1
echo "== NAT (iptables-save -t nat, nft nat/redirect lines)"
iptables-save -t nat 2>&1 | grep -v -E '^#' | head -60
command -v nft >/dev/null && nft list ruleset 2>&1 | grep -n -i -E 'table|chain|dnat|snat|masquerade|redirect|dport 22|:22' | head -60
echo "== gateway service"
systemctl list-units --type=service --all --no-pager --plain 2>/dev/null | grep -i -E "dustforge|node|pm2" | head
for u in dustforge.service dustforge-server.service; do
  systemctl cat "$u" >/dev/null 2>&1 || continue
  echo "-- $u"
  systemctl show "$u" -p MainPID -p User -p PrivateNetwork -p NetworkNamespacePath -p RestrictAddressFamilies -p IPAddressDeny -p IPAddressAllow 2>&1
done
P=$(pgrep -o -f 'node .*server\.js' || true)
echo "node pid: ${P:-none}"
if [ -n "$P" ]; then
  echo "netns node=$(readlink /proc/$P/ns/net) init=$(readlink /proc/1/ns/net)"
  ps -o user=,pid=,ppid=,args= -p "$P" | cut -c1-160
fi
echo "== containers"
command -v docker >/dev/null && docker ps --format '{{.Names}} {{.Image}} {{.Ports}}' 2>&1 | head
command -v podman >/dev/null && podman ps --format '{{.Names}} {{.Image}} {{.Ports}}' 2>&1 | head
echo "== done"
