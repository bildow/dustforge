#!/bin/bash
# ops/root-lane/apply.sh — racknerd sshd: password login only where a Match allows it; root by password only over
# loopback (the DemiPass root lane, host alias `racknerd-self`). Runs once as root on racknerd, under a phone-approved
# operator act (POST /api/demipass/operator-act binds this file's sha256, its companions', the commit and the route).
# via-mirror.sh copies the three scripts to a private directory, checks their sha256s there and runs this copy, so the
# dead-man below runs checked bytes too (#119 review M2).
# (2026-11-14 root-lane adversarial review: option (a) with the gated alias; (a') and (c) rejected. #119 review fixes.)
#
#   1. diagnose (prints facts, no secret): sshd_config's Include first, root's password date, Tailscale kernel mode and
#      no Tailscale SSH, no dead-man still armed, who logs in by password or keyboard-interactive today (from auth.log or
#      the journal; refuses if neither can be read, or if anyone but root and dustforge-deploy does: lockout risk);
#   2. back up /etc/ssh/sshd_config.d; write 10-dustforge-hardening.conf (globals, no Match, sorts first: no password
#      or keyboard-interactive login, root by key only, no forwarding), 11-dustforge-deploy-local-only.conf (the deploy
#      account's password only from this box, when every deploy password login so far came from it) and
#      zz-dustforge-root-lane.conf (the root Match, sorts last);
#   3. `sshd -t` and an `sshd -T -C` matrix (root, deploy, a stranger; loopback, public, tailnet, outside) — any
#      mismatch, or any stop before the reload, puts the backup back, nothing reloaded;
#   4. arm a dead-man timer (rollback.sh in 15 min), reload ssh, wait until it listens, print the confirm step.
# A NEW session runs confirm.sh <stamp> to cancel the dead-man. If it cannot get in, the old session runs rollback.sh
# <stamp>; if both are gone, the timer does it. The RackNerd console is the last resort only.
set -euo pipefail
umask 022
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "apply: run as root" >&2; exit 1; }

D=/etc/ssh/sshd_config.d
HARD=$D/10-dustforge-hardening.conf
DLOCAL=$D/11-dustforge-deploy-local-only.conf
LANE=$D/zz-dustforge-root-lane.conf
SELF_ADDRS="192.3.84.103 127.0.0.1"
TS=$(date -u +%Y%m%dT%H%M%SZ)
BAK=/root/sshd.d.bak-$TS
HERE=$(cd "$(dirname "$0")" && pwd)
UNIT=ssh; systemctl cat ssh.service >/dev/null 2>&1 || UNIT=sshd

fail() { echo "apply: $*" >&2; exit 1; }

echo "== 1. diagnose"
# No pipe here ends early: with pipefail a reader that quits first (head, grep -q, awk exit) kills the writer with
# SIGPIPE and set -e the script (test run 2026-11-14: rc 141 mid-check).
first=$(awk 'NF && $1 !~ /^#/ {print NR ":" $0; exit}' /etc/ssh/sshd_config)
echo "first directive of sshd_config: $first"
[[ "$first" =~ Include[[:space:]]+/etc/ssh/sshd_config\.d ]] || fail "the Include of sshd_config.d is not the first directive: main-file values would win over the drop-ins"
armed=$(systemctl list-units 'sshd-deadman-*.timer' --state=active --no-legend --plain 2>/dev/null | awk '{print $1}')
[ -z "$armed" ] || fail "a dead-man timer is still armed ($armed): confirm or roll back that run first (it would undo this one)"
echo "root password: $(passwd -S root | awk '{print "status " $2 ", last changed " $3}')"
echo "sudo: $(command -v sudo || echo 'NOT INSTALLED')"
ip link show tailscale0 >/dev/null 2>&1 || fail "no tailscale0: Tailscale may run in userspace mode, where tailnet ssh arrives from 127.0.0.1"
if command -v tailscale >/dev/null; then
  prefs=$(tailscale debug prefs 2>/dev/null || true)
  [[ "$prefs" =~ \"RunSSH\":[[:space:]]*true ]] && fail "Tailscale SSH is on: tailnet port 22 would bypass sshd"
fi
echo "tailscale: kernel interface present, Tailscale SSH off"
# Who logs in by password today: auth.log, else the journal (Debian 12 / no rsyslog); neither readable → refuse.
LOGS=""
if ls /var/log/auth.log* >/dev/null 2>&1; then LOGS=$(zcat -f /var/log/auth.log* 2>/dev/null || true); SRC=auth.log
elif command -v journalctl >/dev/null; then LOGS=$(journalctl -q --no-pager -o cat _COMM=sshd _COMM=sshd-session 2>/dev/null || true); SRC=journal
fi
[ -n "$LOGS" ] || fail "no sshd log to read (auth.log or journal): cannot tell who logs in by password — refusing (lockout risk)"
PW=$(sed -nE 's/.*Accepted (password|keyboard-interactive\/pam) for ([^ ]+) from ([^ ]+) .*/\2 \3/p' <<<"$LOGS" | sort | uniq -c || true)
echo "password / keyboard-interactive logins in the $SRC (user from address: count):"
echo "${PW:-  (none)}"
others=$(awk 'NF==3 && $2 != "root" && $2 != "dustforge-deploy" {print $2}' <<<"$PW" | sort -u)
[ -z "$others" ] || fail "these users log in by password today and would be locked out: $others"
deploy_from=$(awk 'NF==3 && $2 == "dustforge-deploy" {print $3}' <<<"$PW" | sort -u)
NARROW=1
for a in $deploy_from; do case " $SELF_ADDRS " in *" $a "*) ;; *) NARROW=0;; esac; done
[ -n "$deploy_from" ] || NARROW=0
echo "deploy password logins came from: ${deploy_from:-none}; limit them to this box: $([ $NARROW = 1 ] && echo yes || echo no)"

T() { sshd -T -C "user=$1,host=x,addr=$2" 2>/dev/null; }
echo "before: root from 192.3.84.103 -> $(T root 192.3.84.103 | awk 'tolower($1) ~ /^(permitrootlogin|passwordauthentication)$/' | tr '\n' ' ')"

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
# root lane (zz-dustforge-root-lane.conf); no forwarding (a forward to 127.0.0.1:22 would reach the root lane's Match).
# No Match here: this file sorts first, and for global keywords the first value read wins.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
DisableForwarding yes
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
if [ $NARROW = 1 ]; then
  # Its own file, sorting before dustforge-deploy.conf (first value wins inside Match too): the deploy drop-in itself,
  # with its ForceCommand, stays as setup.sh wrote it for every address (#119 review).
  cat > "$DLOCAL" <<'EOF'
# dustforge ops/root-lane: the deploy account's password only from this box (the gateway's own deploy lane).
Match User dustforge-deploy Address *,!192.3.84.103,!127.0.0.1
    PasswordAuthentication no
EOF
  echo "deploy password login limited to 192.3.84.103 and 127.0.0.1"
fi
chmod 0644 "$HARD" "$LANE"; [ ! -e "$DLOCAL" ] || chmod 0644 "$DLOCAL"

echo "== 3. check"
sshd -t || fail "sshd -t failed"
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
  want root $a disableforwarding yes
done
for a in 192.3.84.103 127.0.0.1; do want dustforge-deploy $a passwordauthentication yes; want dustforge-deploy $a forcecommand /usr/local/libexec/dustforge-deploy-shell; done
want dustforge-deploy 203.0.113.7 passwordauthentication "$([ $NARROW = 1 ] && echo no || echo yes)"
want dustforge-deploy 203.0.113.7 forcecommand /usr/local/libexec/dustforge-deploy-shell
for a in 203.0.113.7 100.83.112.88 127.0.0.1; do
  want nosuchuser8812 $a passwordauthentication no; want nosuchuser8812 $a kbdinteractiveauthentication no; want nosuchuser8812 $a disableforwarding yes
done
[ $bad = 0 ] || fail "the effective settings are not the intended ones"

echo "== 4. reload"
systemd-run --quiet --unit="sshd-deadman-$TS" --on-active=15m /bin/bash "$HERE/rollback.sh" "$TS"
echo "dead-man armed: $HERE/rollback.sh $TS runs in 15 min unless confirm.sh $TS cancels it"
systemctl reload "$UNIT"
DONE=1
# A reload re-executes sshd: for a moment it accepts nothing (test run: "Connection refused" right after). Wait until
# it listens again before saying it is done, so the confirming connection does not race it.
for i in $(seq 1 20); do [ -n "$(ss -ltnH 'sport = :22' 2>/dev/null)" ] && break; sleep 0.5; done
[ -n "$(ss -ltnH 'sport = :22' 2>/dev/null)" ] || echo "apply: sshd is not listening on :22 after the reload — do not log out; the dead-man rolls back" >&2
echo "reloaded $UNIT. Keep this session open. From a NEW session: bash $HERE/confirm.sh $TS"
echo "APPLIED $TS"
