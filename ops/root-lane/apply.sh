#!/bin/bash
# ops/root-lane/apply.sh — racknerd sshd: password login only where a Match allows it; root by password only over
# loopback (the DemiPass root lane, host alias `racknerd-self`). Runs once as root on racknerd, under a phone-approved
# operator act (POST /api/demipass/operator-act, which binds this file's sha256 and the route used).
# (2026-11-14 root-lane adversarial review: option (a) with the gated alias; (a') and (c) rejected.)
#
#   1. diagnose (prints facts, no secret): root's password date, sudo present, Tailscale kernel mode and no Tailscale SSH,
#      who logs in by password today (refuses if anyone but root and dustforge-deploy does: lockout risk);
#   2. back up /etc/ssh/sshd_config.d; write 10-dustforge-hardening.conf (globals, no Match, sorts first) and
#      zz-dustforge-root-lane.conf (the root Match, sorts last); narrow the deploy Match to this box's own addresses when
#      every deploy password login so far came from them;
#   3. `sshd -t` and an `sshd -T -C` matrix (root, deploy, a stranger; loopback, public, tailnet, outside) — any
#      mismatch puts the backup back, nothing reloaded;
#   4. arm a dead-man timer (rollback.sh in 15 min), reload ssh (this session stays), print the confirm step.
# A NEW session runs confirm.sh <stamp> to cancel the dead-man. If it cannot get in, the old session runs rollback.sh
# <stamp>; if both are gone, the timer does it. The RackNerd console is the last resort only.
set -euo pipefail
umask 022
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "apply: run as root" >&2; exit 1; }

D=/etc/ssh/sshd_config.d
HARD=$D/10-dustforge-hardening.conf
LANE=$D/zz-dustforge-root-lane.conf
DEPLOY=$D/dustforge-deploy.conf
SELF_ADDRS="192.3.84.103 127.0.0.1"
TS=$(date -u +%Y%m%dT%H%M%SZ)
BAK=/root/sshd.d.bak-$TS
HERE=$(cd "$(dirname "$0")" && pwd)
UNIT=ssh; systemctl cat ssh.service >/dev/null 2>&1 || UNIT=sshd

fail() { echo "apply: $*" >&2; exit 1; }

echo "== 1. diagnose"
grep -qiE '^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config || fail "sshd_config has no Include of sshd_config.d"
# No pipe here ends early: with pipefail a reader that quits first (head, awk exit) kills the writer with SIGPIPE and
# set -e the script (test run 2026-11-14: rc 141 mid-check).
first=$(awk 'NF && $1 !~ /^#/ {print NR ":" $0; exit}' /etc/ssh/sshd_config)
echo "first directive of sshd_config: $first"
echo "$first" | grep -qiE 'Include\s+/etc/ssh/sshd_config.d' || fail "the Include is not the first directive: main-file values would win over the drop-ins"
echo "root password: $(passwd -S root | awk '{print "status " $2 ", last changed " $3}')"
echo "sudo: $(command -v sudo || echo 'NOT INSTALLED')"
ip link show tailscale0 >/dev/null 2>&1 || fail "no tailscale0: Tailscale may run in userspace mode, where tailnet ssh arrives from 127.0.0.1"
if command -v tailscale >/dev/null && tailscale debug prefs 2>/dev/null | grep -qE '"RunSSH":\s*true'; then fail "Tailscale SSH is on: tailnet port 22 would bypass sshd"; fi
echo "tailscale: kernel interface present, Tailscale SSH off"
echo "password logins in the retained auth logs (user from address: count):"
PW=$(zgrep -h 'Accepted password for' /var/log/auth.log* 2>/dev/null | sed -nE 's/.*Accepted password for ([^ ]+) from ([^ ]+) .*/\1 \2/p' | sort | uniq -c || true)
echo "${PW:-  (none)}"
others=$(echo "$PW" | awk 'NF==3 && $2 != "root" && $2 != "dustforge-deploy" {print $2}' | sort -u)
[ -z "$others" ] || fail "these users log in by password today and would be locked out: $others"
deploy_from=$(echo "$PW" | awk 'NF==3 && $2 == "dustforge-deploy" {print $3}' | sort -u)
NARROW=1
for a in $deploy_from; do case " $SELF_ADDRS " in *" $a "*) ;; *) NARROW=0;; esac; done
[ -n "$deploy_from" ] || NARROW=0
echo "deploy password logins came from: ${deploy_from:-none}; narrow its Match to this box: $([ $NARROW = 1 ] && echo yes || echo no)"

T() { sshd -T -C "user=$1,host=x,addr=$2" 2>/dev/null; }
echo "before: root from 192.3.84.103 -> $(T root 192.3.84.103 | grep -iE '^(permitrootlogin|passwordauthentication) ' | tr '\n' ' ')"

echo "== 2. stage"
[ ! -e "$BAK" ] || fail "$BAK exists"
cp -a "$D" "$BAK"
echo "backup: $BAK"
restore() { rm -rf "$D"; cp -a "$BAK" "$D"; }
# From here, any exit before a successful reload puts the backup back: nothing staged is left for a later reload.
DONE=0
trap 'rc=$?; if [ "$DONE" != 1 ]; then restore; systemctl stop "sshd-deadman-$TS.timer" 2>/dev/null || true; echo "apply: stopped (rc $rc) before the reload finished: backup put back, nothing reloaded" >&2; fi' EXIT
cat > "$HARD" <<'EOF'
# 2026-11 (dustforge ops/root-lane): password login only where a later Match allows it; root by key only, except the
# root lane (zz-dustforge-root-lane.conf). No Match here: this file sorts first, and for global keywords the first
# value read wins.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
EOF
cat > "$LANE" <<'EOF'
# Root lane (dustforge ops/root-lane): the DemiPass gateway on this box, over loopback only, root by password (the vault
# entry is wrapped to the owner's phone: each use is a tap). Sorts last; Match only.
Match User root Address 127.0.0.1,::1
    PermitRootLogin yes
    PasswordAuthentication yes
    KbdInteractiveAuthentication no
    AuthenticationMethods password
    DisableForwarding yes
    PermitTTY no
    PermitUserRC no
    PermitTunnel no
EOF
chmod 0644 "$HARD" "$LANE"
if [ $NARROW = 1 ] && [ -f "$DEPLOY" ] && grep -qxE '\s*Match User dustforge-deploy\s*' "$DEPLOY"; then
  sed -i -E 's/^(\s*)Match User dustforge-deploy\s*$/\1Match User dustforge-deploy Address 192.3.84.103,127.0.0.1/' "$DEPLOY"
  echo "deploy Match narrowed to Address 192.3.84.103,127.0.0.1"
fi

echo "== 3. check"
sshd -t || { restore; fail "sshd -t failed: backup put back, nothing reloaded"; }
bad=0
want() {   # user addr keyword value
  local got; got=$(T "$1" "$2" | awk -v k="$3" 'tolower($1)==k && !f {f=1; sub($1" ",""); print}')
  if [ "$got" = "$4" ]; then echo "  ok   $1@$2 $3=$got"; else echo "  FAIL $1@$2 $3=$got (want $4)"; bad=1; fi
}
for a in 127.0.0.1 ::1; do
  want root $a permitrootlogin yes; want root $a passwordauthentication yes; want root $a authenticationmethods password
  want root $a disableforwarding yes; want root $a permittty no
done
for a in 192.3.84.103 100.83.112.88 100.73.251.12 203.0.113.7; do
  want root $a permitrootlogin without-password; want root $a passwordauthentication no; want root $a pubkeyauthentication yes
done
for a in 192.3.84.103 127.0.0.1; do want dustforge-deploy $a passwordauthentication yes; want dustforge-deploy $a forcecommand /usr/local/libexec/dustforge-deploy-shell; done
want dustforge-deploy 203.0.113.7 passwordauthentication "$([ $NARROW = 1 ] && echo no || echo yes)"
for a in 203.0.113.7 100.83.112.88 127.0.0.1; do want nosuchuser8812 $a passwordauthentication no; want nosuchuser8812 $a kbdinteractiveauthentication no; done
[ $bad = 0 ] || { restore; sshd -t; fail "the effective settings are not the intended ones: backup put back, nothing reloaded"; }

echo "== 4. reload"
systemd-run --quiet --unit="sshd-deadman-$TS" --on-active=15m /bin/bash "$HERE/rollback.sh" "$TS"
echo "dead-man armed: rollback.sh $TS runs in 15 min unless confirm.sh $TS cancels it"
systemctl reload "$UNIT"
DONE=1
# A reload re-executes sshd: for a moment it accepts nothing (test run: "Connection refused" right after). Wait until
# it listens again before saying it is done, so the confirming connection does not race it.
for i in $(seq 1 20); do ss -ltnH 'sport = :22' 2>/dev/null | grep -q . && break; sleep 0.5; done
ss -ltnH 'sport = :22' | grep -q . || echo "apply: sshd is not listening on :22 after the reload — do not log out; the dead-man rolls back" >&2
echo "reloaded $UNIT. Keep this session open. From a NEW session: bash $HERE/confirm.sh $TS"
echo "APPLIED $TS"
