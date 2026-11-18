#!/bin/bash
# Root, once, through the root lane (one phone approval). Revokes Brain's deploy lane on the dustanvil web root and
# enforces it on the host (Aaron 2026-11-18: "carve dustanvil's public record out of Brain's deploy grant"; step 1
# found the lane wrote the site once, 2026-11-05, and nothing since, so it is revoked, not narrowed).
# What changes:
#   1. a new owner for the site tree: system user dustanvil-site (no login, no home), the main-site deploy's OWNER;
#      everything under /var/www/dustanvil except evals/MCI-1 (mci-publish's lane, untouched) becomes
#      dustanvil-site:www-data, dirs 2755, files 0644;
#   2. brain-deploy's key is refused: its authorized_keys files are moved to /root/retired-keys (0600, kept as the
#      record), the account is locked and given /usr/sbin/nologin; its snapshots dir becomes root-only (kept);
#   3. the result is checked as brain-deploy: every write test on the public record must be refused.
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

echo "== 1. owner of the site tree: $NEW"
id "$NEW" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --user-group "$NEW"
usermod -s /usr/sbin/nologin "$NEW" 2>/dev/null || true
# Everything but the MCI-1 lane: owner, group, modes (no symlink is followed; the live tree holds none).
find "$D" -path "$D/$LANE_DIR" -prune -o \( -type d -o -type f \) -print0 | xargs -0 -r chown -h "$NEW:$GROUP"
find "$D" -path "$D/$LANE_DIR" -prune -o -type d -print0 | xargs -0 -r chmod 2755
find "$D" -path "$D/$LANE_DIR" -prune -o -type f -print0 | xargs -0 -r chmod 0644
echo "ok   $(find "$D" -path "$D/$LANE_DIR" -prune -o \( -type d -o -type f \) -user "$NEW" -print | wc -l) entries owned by $NEW; lane dir: $(stat -c '%U:%G %a' "$D/$LANE_DIR" 2>/dev/null || echo absent)"

echo "== 2. $OLD's key refused, account locked"
mkdir -p "$RET"; chmod 0700 "$RET"
HOME_OLD=$(getent passwd "$OLD" | cut -d: -f6)
moved=0
for f in "$HOME_OLD/.ssh/authorized_keys" "$HOME_OLD/.ssh/authorized_keys2" /home/$OLD/.ssh/authorized_keys /etc/ssh/authorized_keys/$OLD; do
  [ -f "$f" ] || continue
  mv -f -- "$f" "$RET/$OLD.$(echo "$f" | tr '/' '_').$STAMP"; chmod 0600 "$RET"/*; moved=$((moved+1))
  echo "ok   moved $f → $RET (root-only)"
done
[ "$moved" = 0 ] && echo "ok   no authorized_keys left for $OLD (already moved)"
usermod -L -s /usr/sbin/nologin "$OLD"
passwd -S "$OLD" | awk '{print "ok   account", $1, "status", $2, "(L = locked)"}'
[ -d "$SNAPS" ] && { chown -R root:root "$SNAPS"; chmod 0700 "$SNAPS"; echo "ok   $SNAPS kept, root-only"; }
# sshd must see no key for $OLD now (a key placed elsewhere would show here).
if sshd -T 2>/dev/null | grep -i '^authorizedkeysfile' | head -1 | grep -q .; then echo "info sshd $(sshd -T 2>/dev/null | grep -i '^authorizedkeysfile' | head -1)"; fi

echo "== 3. checks as $OLD (every write on the public record must be refused)"
fails=0
for p in "$D" "$D/index.html" "$D/index.json" "$D/verify.html" "$D/registry" "$D/registry/index.html" "$D/evals" "$D/evals/index.html" "$D/ledger" "$D/ledger/index.html" "$D/$LANE_DIR"; do
  [ -e "$p" ] || continue
  if runuser -u "$OLD" -s /bin/sh -- -c "test -w '$p'" 2>/dev/null; then echo "FAIL $OLD can still write $p"; fails=$((fails+1)); else echo "ok   refused: $p"; fi
done
if runuser -u "$OLD" -s /bin/sh -- -c "touch '$D/.brain-lane-probe' 2>/dev/null"; then echo "FAIL $OLD created a file in $D"; rm -f "$D/.brain-lane-probe"; fails=$((fails+1)); else echo "ok   refused: creating a file in $D"; fi
for p in "$D" "$D/registry/index.html"; do [ "$(stat -c %U "$p")" = "$NEW" ] || { echo "FAIL $p owned by $(stat -c %U "$p")"; fails=$((fails+1)); }; done
ls "$HOME_OLD/.ssh/authorized_keys" /etc/ssh/authorized_keys/$OLD 2>/dev/null | grep -q . && { echo "FAIL a key file for $OLD remains"; fails=$((fails+1)); }
echo "== done $(date -u +%FT%TZ): $fails failure(s)"
exit $(( fails > 0 ))
