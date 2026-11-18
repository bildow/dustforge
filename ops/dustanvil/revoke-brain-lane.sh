#!/bin/bash
# Root, once, through the root lane (one phone approval). Revokes Brain's deploy lane on the dustanvil web root and
# enforces it on the host (Aaron 2026-11-18: "carve dustanvil's public record out of Brain's deploy grant"; step 1
# found the lane wrote the site once, 2026-11-05, and nothing since, so it is revoked, not narrowed).
# What changes:
#   1. a new owner for the site tree: system user dustanvil-site (no login, no home), the main-site deploy's OWNER;
#      everything under /var/www/dustanvil except evals/MCI-1 (mci-publish's lane, untouched) becomes
#      dustanvil-site:www-data, dirs 2755, files 0644;
#   2. brain-deploy's key is refused: its authorized_keys files are moved to /root/retired-keys (0600, kept as the
#      record; the fingerprint is printed first), the account is expired (pam account refuses a key login too),
#      locked and given /usr/sbin/nologin; its snapshots dir becomes root-only (kept);
#   3. the result is checked as brain-deploy (runuser -u, no PAM shell): every write test on the public record must be
#      refused, a positive control must succeed (a broken probe can never read as a pass), and nginx's user must still
#      read the tree.
# Before anything changes: no process, cron or unit of brain-deploy may exist, and the git-bundles lane that delivers
# site tarballs must not be brain-deploy's (it is its own account).
# The two site lanes stay exactly as they are: mci-publish inside evals/MCI-1, and the phone-approved main-site deploy.
# Idempotent: a second run changes nothing and prints the same checks. Exit 0 only when every check passes.
set -euo pipefail
export LC_ALL=C
D=/var/www/dustanvil; SNAPS=/var/www/dustanvil-snapshots; LANE_DIR=evals/MCI-1
OLD=brain-deploy; NEW=dustanvil-site; GROUP=www-data
RET=/root/retired-keys; STAMP=$(date -u +%Y%m%dT%H%M%SZ)
[ -d "$D" ] && [ ! -L "$D" ] || { echo "web root $D missing or a symlink"; exit 4; }
id "$OLD" >/dev/null 2>&1 || { echo "no user $OLD: nothing to revoke"; exit 4; }
getent group "$GROUP" >/dev/null || { echo "no group $GROUP"; exit 4; }

AS() { runuser -u "$1" -- /bin/sh -c "$2"; }   # as that user, no PAM shell (runuser -u takes no -s)
echo "== 0. collateral: nothing else runs as $OLD"
[ -z "$(pgrep -u "$OLD" 2>/dev/null)" ] || { echo "STOP: processes run as $OLD:"; ps -u "$OLD" -o pid=,cmd=; exit 4; }
[ -z "$(grep -rl "$OLD" /etc/cron* /var/spool/cron /etc/systemd/system 2>/dev/null)" ] || { echo "STOP: $OLD named in cron/systemd:"; grep -rl "$OLD" /etc/cron* /var/spool/cron /etc/systemd/system 2>/dev/null; exit 4; }
[ "$(stat -c %U /opt/backups/git-bundles 2>/dev/null)" != "$OLD" ] || { echo "STOP: the git-bundles lane is $OLD's"; exit 4; }
AS "$OLD" "test -w /tmp" || { echo "STOP: the probe cannot even write /tmp as $OLD (runuser broken?)"; exit 4; }
echo "ok   no process, cron or unit of $OLD; the tarball lane is $(stat -c %U /opt/backups/git-bundles)'s; the probe works (positive control)"

echo "== 1. $OLD's key refused, account locked (first: a failure later can only leave the host more locked)"
mkdir -p "$RET"; chmod 0700 "$RET"
HOME_OLD=$(getent passwd "$OLD" | cut -d: -f6)
moved=0
for f in "$HOME_OLD/.ssh/authorized_keys" "$HOME_OLD/.ssh/authorized_keys2" /home/$OLD/.ssh/authorized_keys /etc/ssh/authorized_keys/$OLD; do
  [ -f "$f" ] || continue
  echo "info key(s) in $f: $(ssh-keygen -l -f "$f" 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
  mv -f -- "$f" "$RET/$OLD.$(echo "$f" | tr '/' '_').$STAMP"; chmod 0600 "$RET"/*; moved=$((moved+1))
  echo "ok   moved $f → $RET (root-only)"
done
[ "$moved" = 0 ] && echo "ok   no authorized_keys left for $OLD (already moved)"
# Expired (pam_unix account refuses a key login under UsePAM), locked (no password) and no shell (a forced command
# would run under nologin). The key move is what refuses the lane; these are the belt.
usermod -e 1970-01-02 -L -s /usr/sbin/nologin "$OLD"
passwd -S "$OLD" | awk '{print "ok   account", $1, "status", $2, "(L = locked)"}'; echo "ok   expires: $(chage -l "$OLD" | grep -i 'account expires' | cut -d: -f2-)"
[ -d "$SNAPS" ] && [ ! -L "$SNAPS" ] && { chown -R root:root "$SNAPS"; chmod 0700 "$SNAPS"; echo "ok   $SNAPS kept, root-only"; }
# sshd must see no other key source for $OLD (a Match block or an AuthorizedKeysCommand would show here).
sshd -T -C "user=$OLD,host=x,addr=127.0.0.1,laddr=127.0.0.1,lport=22" 2>/dev/null | grep -i -E '^authorizedkeys(file|command)' | sed 's/^/info sshd /' || echo "info sshd -T unavailable (no key-source check)"

echo "== 2. owner of the site tree: $NEW"
id "$NEW" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --user-group "$NEW"
usermod -s /usr/sbin/nologin "$NEW" 2>/dev/null || true
# Everything but the MCI-1 lane: owner, group, modes (no symlink is followed; the live tree holds none).
echo "info files not 0644 before: $(find "$D" -path "$D/$LANE_DIR" -prune -o -type f ! -perm 0644 -print | wc -l); dirs not 2755: $(find "$D" -path "$D/$LANE_DIR" -prune -o -type d ! -perm 2755 -print | wc -l)"
find "$D" -path "$D/$LANE_DIR" -prune -o \( -type d -o -type f \) -print0 | xargs -0 -r chown -h "$NEW:$GROUP"
find "$D" -path "$D/$LANE_DIR" -prune -o -type d -print0 | xargs -0 -r chmod 2755
find "$D" -path "$D/$LANE_DIR" -prune -o -type f -print0 | xargs -0 -r chmod 0644
echo "ok   $(find "$D" -path "$D/$LANE_DIR" -prune -o \( -type d -o -type f \) -user "$NEW" -print | wc -l) entries owned by $NEW; lane dir: $(stat -c '%U:%G %a' "$D/$LANE_DIR" 2>/dev/null || echo absent)"

echo "== 3. checks as $OLD (every write on the public record must be refused)"
fails=0
AS "$OLD" "test -w /tmp" && echo "ok   positive control: $OLD can write /tmp (the probe is alive)" || { echo "FAIL positive control: the probe is broken"; fails=$((fails+1)); }
for p in "$D" "$D/index.html" "$D/index.json" "$D/verify.html" "$D/registry" "$D/registry/index.html" "$D/evals" "$D/evals/index.html" "$D/ledger" "$D/ledger/index.html" "$D/$LANE_DIR"; do
  [ -e "$p" ] || continue
  if AS "$OLD" "test -w '$p'"; then echo "FAIL $OLD can still write $p"; fails=$((fails+1)); else echo "ok   refused: $p"; fi
done
if AS "$OLD" "touch '$D/.brain-lane-probe' 2>/dev/null"; then echo "FAIL $OLD created a file in $D"; rm -f "$D/.brain-lane-probe"; fails=$((fails+1)); else echo "ok   refused: creating a file in $D"; fi
echo "== 4. the site still serves"
AS www-data "test -r '$D/index.html' && test -x '$D/evals' && test -r '$D/registry/index.html'" && echo "ok   www-data reads the tree" || { echo "FAIL www-data cannot read the tree"; fails=$((fails+1)); }
if command -v curl >/dev/null; then
  HC=$(curl -s -k -o /dev/null -w '%{http_code}' -m 10 --resolve dustanvil.com:443:127.0.0.1 https://dustanvil.com/ 2>/dev/null || echo 000)
  [ "$HC" = 200 ] && echo "ok   nginx answers 200 for https://dustanvil.com/" || { echo "FAIL nginx answered $HC"; fails=$((fails+1)); }
else echo "skip nginx check (no curl)"; fi
AS mci-publish "test -w '$D/$LANE_DIR'" && echo "ok   mci-publish still writes $LANE_DIR" || { echo "FAIL mci-publish lost $LANE_DIR"; fails=$((fails+1)); }
for p in "$D" "$D/registry/index.html"; do [ "$(stat -c %U "$p")" = "$NEW" ] || { echo "FAIL $p owned by $(stat -c %U "$p")"; fails=$((fails+1)); }; done
ls "$HOME_OLD/.ssh/authorized_keys" /etc/ssh/authorized_keys/$OLD 2>/dev/null | grep -q . && { echo "FAIL a key file for $OLD remains"; fails=$((fails+1)); }
echo "== done $(date -u +%FT%TZ): $fails failure(s)"
exit $(( fails > 0 ))
