#!/bin/bash
# Root-side deploy of the dustanvil.com main site, run once per release by root on racknerd through the root lane
# (racknerd-self, one phone approval). The approved command names the tarball and its sha256:
#   bash /opt/dustforge/ops/dustanvil/deploy-site.sh <name>.tar <sha256>
# The tarball arrives in /opt/backups/git-bundles/site-deploy/ through the git-bundles rrsync lane. Another account can
# write there, so root only COPIES it (size-capped, no symlink followed, regular file only) into a root-private
# directory, checks its sha256 there, and checks its members. The extraction itself runs WITHOUT root, as the web
# root's owner (dustanvil-site; brain-deploy until the 2026-11-18 revoke), reading the private copy on stdin: the
# kernel then enforces the lane. That user cannot write evals/MCI-1 (mci-publish's) or outside its own trees, whatever
# a member name or a planted symlink says, and it gains nothing it does not already have (it owns the web root).
# Member rules, on the raw names as listed: one strict whole-name pattern (plain characters, no empty, '.' or '..'
# component, no leading '/'); only regular files and directories; nothing under evals/MCI-1. Hardened from the EVAL
# pane's deploy-root.sh (2026-11-16 review; re-review: `.//evals/...` slipped a prefix check, now impossible twice over).
# Extracted files are new inodes owned by the tree's owner (tar unlinks and recreates); directories keep their metadata.
# Exit codes: 2 usage/source/hash, 3 refused member, 4 live tree unsafe, 5 extract failed.
set -euo pipefail
umask 077
export LC_ALL=C
SRC_DIR=/opt/backups/git-bundles/site-deploy
D=/var/www/dustanvil
OWNER=dustanvil-site; GROUP=www-data   # since the Brain-lane revoke (2026-11-18): the site tree's own owner, no key lane
LANE_DIR=evals/MCI-1
MAX_BYTES=$((256*1024*1024))
KEEP_PREV=3
[ $# -eq 2 ] || { echo "usage: deploy-site.sh <name>.tar <sha256>"; exit 2; }
NAME=$1; WANT=$2
[[ "$NAME" =~ ^[A-Za-z0-9._-]{1,100}\.tar$ ]] || { echo "tar name must be a plain file name ending in .tar"; exit 2; }
[[ "$WANT" =~ ^[0-9a-f]{64}$ ]] || { echo "sha256 must be 64 hex"; exit 2; }
[ -d "$D" ] && [ ! -L "$D" ] || { echo "web root $D missing or a symlink"; exit 4; }
[ ! -e /rsyncd-munged ] || { echo "refused: /rsyncd-munged exists, so munged symlinks in the web root would resolve"; exit 4; }
id "$OWNER" >/dev/null 2>&1 || { echo "no user $OWNER"; exit 4; }

# The source: the directory must be a real directory, not a symlink; the file a regular file under the size cap.
[ -d "$SRC_DIR" ] && [ ! -L "$SRC_DIR" ] && [ ! -L "$(dirname "$SRC_DIR")" ] || { echo "$SRC_DIR is not a plain directory"; exit 2; }
SZ=$(stat -c '%s' -- "$SRC_DIR/$NAME" 2>/dev/null || echo -1); TY=$(stat -c '%F' -- "$SRC_DIR/$NAME" 2>/dev/null || echo none)
[ "$TY" = "regular file" ] || { echo "no regular file $SRC_DIR/$NAME"; exit 2; }
[ "$SZ" -gt 0 ] && [ "$SZ" -le "$MAX_BYTES" ] || { echo "tar size $SZ is outside 1..$MAX_BYTES bytes"; exit 2; }
W=$(mktemp -d /root/dustanvil-deploy.XXXXXXXX); trap 'rm -rf "$W"' EXIT
# One open, no symlink followed, never blocking on a FIFO, never more than the cap (+1 to notice growth).
timeout 120 dd if="$SRC_DIR/$NAME" of="$W/site.tar" iflag=nofollow,nonblock bs=1M count=$((MAX_BYTES/1048576 + 1)) status=none \
  || { echo "could not copy the tar"; exit 2; }
[ "$(stat -c '%s' "$W/site.tar")" -le "$MAX_BYTES" ] || { echo "the tar grew past the cap while being copied"; exit 2; }
GOT=$(sha256sum "$W/site.tar" | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || { echo "tar hash mismatch (the approved sha256 does not match the uploaded file)"; exit 2; }
echo "ok   tar $NAME sha256 matches ($(stat -c %s "$W/site.tar") bytes)"

# Member types and names, from the private copy, on the RAW names (nothing stripped before the checks).
tar -tvf "$W/site.tar" > "$W/list.v"
tar -tf "$W/site.tar" > "$W/list.n"
[ "$(wc -l < "$W/list.v")" = "$(wc -l < "$W/list.n")" ] || { echo "refused: member listing inconsistent"; exit 3; }
bad=$(cut -c1 "$W/list.v" | grep -c -v -E '^[-d]$' || true)
[ "$bad" = 0 ] || { echo "refused: $bad member(s) that are not regular files or directories"; exit 3; }
SEG='[A-Za-z0-9_@+-][A-Za-z0-9._@+-]*'   # a component: plain characters, never '.' or '..' (cannot start with '.')
n=0
while IFS= read -r m; do
  [ "$m" = "./" ] && continue                                  # the archive root itself
  [[ "$m" =~ ^(\./)?($SEG/)*$SEG/?$ ]] || { echo "refused: a member name outside the strict pattern"; exit 3; }
  p=${m#./}; p=${p%/}
  case "$p" in "$LANE_DIR"|"$LANE_DIR"/*) echo "refused: the tar carries $LANE_DIR (lane-owned)"; exit 3;; esac
  n=$((n+1))
done < "$W/list.n"
echo "ok   $n members: regular files and directories only, strict names, nothing under $LANE_DIR"

# Defence in depth: the live tree holds no symlink outside the lane (the lanes' rsync munges any they send).
links=$(find "$D" -path "$D/$LANE_DIR" -prune -o -type l -print | wc -l)
[ "$links" = 0 ] || { echo "refused: the live tree holds $links symlink(s); remove them first"; exit 4; }
echo "ok   live tree holds no symlink"

# Previous tree: a root-private copy (0700), the newest $KEEP_PREV kept. A rollback from it must skip $LANE_DIR.
STAMP=$(date -u +%Y%m%dT%H%M%SZ); P=$(mktemp -d "$D.prev-$STAMP-XXXX")
cp -a "$D/." "$P/"; chown root:root "$P"; chmod 0700 "$P"; echo "ok   previous tree copied to $P (root-only)"
# Prune only this script's own copies: root-owned directories with exactly its name shape (never a symlink, never a
# name another account planted; older .prev trees from other tools are left alone).
find "$(dirname "$D")" -mindepth 1 -maxdepth 1 -type d -user root -regextype posix-extended \
  -regex "$D\.prev-[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9]{4}" -printf '%T@ %p\n' | sort -rn | tail -n +$((KEEP_PREV+1)) \
  | cut -d' ' -f2- | while IFS= read -r old; do rm -rf -- "$old"; done

# The extraction, as the web root's owner, reading the private copy on stdin (files 0644, dirs 0755 for the web server).
umask 022
setpriv --reuid="$OWNER" --regid="$GROUP" --clear-groups --no-new-privs --inh-caps=-all \
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
  tar -C "$D" --no-same-owner --no-same-permissions --no-overwrite-dir --delay-directory-restore -xf - < "$W/site.tar" \
  || { echo "extract failed (as $OWNER); the previous tree is at $P"; exit 5; }
echo "ok   extracted over $D as $OWNER"
echo "lane dir: $(stat -c '%U:%G %a' "$D/$LANE_DIR" 2>/dev/null || echo 'absent')"
echo "deployed $WANT; previous tree at $P"
