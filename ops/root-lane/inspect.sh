#!/bin/bash
# Read-only. Why sshd refused root by password over loopback after the root-lane change (operator act 65):
# the first lane use (approval 71, 2026-11-15) got "root@127.0.0.1: Permission denied (publickey)", so sshd offered
# no password method to that connection, although apply.sh's `sshd -T` matrix said it would.
# Changes nothing: no writes, no reloads, no service calls beyond status. Prints config, effective settings, sshd log
# lines and file hashes; nothing here holds a secret (sshd logs never carry passwords).
# Run as root on racknerd, fed over stdin by phasewhip (`ssh root@192.3.84.103 bash -s < inspect.sh`) under an
# operator-act approval bound to this file's sha256.
set -u
export LC_ALL=C
SINCE="${INSPECT_SINCE:-2026-11-15 04:00:00 UTC}"
echo "== host $(hostname) $(date -u +%FT%TZ)"
. /etc/os-release 2>/dev/null && echo "os ${PRETTY_NAME:-?}"
dpkg-query -W -f='openssh-server ${Version}\n' openssh-server 2>/dev/null
echo "== units"
for u in ssh.service ssh.socket sshd.service; do printf '%s %s\n' "$u" "$(systemctl is-active "$u" 2>&1)"; done
systemctl show ssh.service -p MainPID -p ExecMainStartTimestamp -p ActiveEnterTimestamp 2>/dev/null
echo "== listeners on :22"
ss -ltnpH 'sport = :22' 2>&1
echo "== /etc/ssh/sshd_config (non-comment lines)"
grep -n -v -E '^[[:space:]]*(#|$)' /etc/ssh/sshd_config
echo "== drop-ins"
for f in /etc/ssh/sshd_config.d/*; do
  [ -e "$f" ] || continue
  echo "-- $f $(stat -c '%y %a %U' "$f") sha256:$(sha256sum < "$f" | cut -c1-16)"
  grep -n -v -E '^[[:space:]]*(#|$)' "$f"
done
echo "== sshd -t"
sshd -t 2>&1; echo "rc=$?"
K='^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|authenticationmethods|usepam|pubkeyauthentication|maxauthtries|disableforwarding|logl[a-z]*) '
for spec in "user=root,host=localhost,addr=127.0.0.1" "user=root,host=127.0.0.1,addr=127.0.0.1" "user=root,host=localhost,addr=::1" \
            "user=root,host=192.3.84.103,addr=192.3.84.103" "user=dustforge-deploy,host=127.0.0.1,addr=127.0.0.1"; do
  echo "== effective: $spec"
  sshd -T -C "$spec" 2>&1 | grep -E "$K"
done
echo "== sshd log since $SINCE (loopback, root, preauth)"
journalctl -u ssh.service -u ssh.socket -u sshd.service --since "$SINCE" -o short-iso --no-pager 2>/dev/null \
  | grep -E '127\.0\.0\.1|::1|for root|root from|preauth|Reload|Received SIGHUP|re-exec|Server listening' | tail -60
echo "== auth.log since the same day (loopback)"
grep -h -E 'sshd.*(127\.0\.0\.1|::1)' /var/log/auth.log 2>/dev/null | tail -20
echo "== root-lane backups and dead-man units"
ls -ld /root/sshd.d.bak-* 2>&1 | tail -5
systemctl list-units --all --no-pager --plain 'sshd-deadman-*' 2>&1 | head -5
echo "== done"
