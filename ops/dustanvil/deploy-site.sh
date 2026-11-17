#!/bin/bash
# Root-side deploy of the dustanvil.com main site, run once per release by root on racknerd through the root lane
# (racknerd-self, one phone approval). The approved command names the tarball and its sha256:
#   bash /opt/dustforge/ops/dustanvil/deploy-site.sh <name>.tar <sha256>
# The tarball arrives in /opt/backups/git-bundles/site-deploy/ through the git-bundles rrsync lane. Another account can
# write there, so nothing is trusted until it is copied into a root-private directory and its sha256 matches the
# approved one. Hardened from the EVAL pane's deploy-root.sh (2026-11-16 review):
#   - only regular files and directories; no symlinks, hardlinks, devices or fifos;
#   - member names: no absolute paths, no `..` component; a leading ./ is normalised before every check;
#   - nothing under evals/MCI-1 (the mci-publish lane's directory), with or without ./;
#   - the live tree must hold no symlink (a symlink could carry the root extraction elsewhere);
#   - extracts OVER the live tree (never moves or deletes it), after copying it to <tree>.prev-<stamp>;
#   - files get root:root or the existing owner kept by --no-same-owner, umask 022; directories keep their metadata.
# Prints counts and paths only. Exit codes: 2 usage/hash, 3 refused member, 4 live tree unsafe, 5 extract failed.
set -euo pipefail
umask 022
export LC_ALL=C
SRC_DIR=/opt/backups/git-bundles/site-deploy
D=${DUSTANVIL_WEB_ROOT:-/var/www/dustanvil}
LANE_DIR=evals/MCI-1
[ $# -eq 2 ] || { echo "usage: deploy-site.sh <name>.tar <sha256>"; exit 2; }
NAME=$1; WANT=$2
[[ "$NAME" =~ ^[A-Za-z0-9._-]{1,100}\.tar$ ]] || { echo "tar name must be a plain file name ending in .tar"; exit 2; }
[[ "$WANT" =~ ^[0-9a-f]{64}$ ]] || { echo "sha256 must be 64 hex"; exit 2; }
[ -f "$SRC_DIR/$NAME" ] && [ ! -L "$SRC_DIR/$NAME" ] || { echo "no regular file $SRC_DIR/$NAME"; exit 2; }
[ -d "$D" ] && [ ! -L "$D" ] || { echo "web root $D missing or a symlink"; exit 4; }

W=$(mktemp -d /root/dustanvil-deploy.XXXXXXXX); trap 'rm -rf "$W"' EXIT
cp --no-preserve=all "$SRC_DIR/$NAME" "$W/site.tar"
GOT=$(sha256sum "$W/site.tar" | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || { echo "tar hash mismatch: got $GOT"; exit 2; }
echo "ok   tar $NAME sha256 matches ($(stat -c %s "$W/site.tar") bytes)"

# Member types and names, from the private copy.
tar -tvf "$W/site.tar" > "$W/list.v"
tar -tf "$W/site.tar" > "$W/list.n"
[ "$(wc -l < "$W/list.v")" = "$(wc -l < "$W/list.n")" ] || { echo "refused: member listing inconsistent"; exit 3; }
bad=$(cut -c1 "$W/list.v" | grep -c -v -E '^[-d]$' || true)
[ "$bad" = 0 ] || { echo "refused: $bad member(s) that are not regular files or directories"; exit 3; }
n=0
while IFS= read -r m; do
  p=${m#./}; p=${p%/}
  case "$m" in /*) echo "refused: absolute member name"; exit 3;; esac
  case "$p" in *//*) echo "refused: an empty component (//) in a member name"; exit 3;; esac   # else evals//MCI-1 dodges the lane check
  case "/$p/" in */../*|*/./*) [ "$p" = "." ] || { echo "refused: '..' or '.' component in a member name"; exit 3; };; esac
  case "$p" in "$LANE_DIR"|"$LANE_DIR"/*) echo "refused: the tar carries $LANE_DIR (lane-owned)"; exit 3;; esac
  [[ "$p" =~ ^[A-Za-z0-9._/@+-]*$ ]] || { echo "refused: a member name outside the plain character set"; exit 3; }
  n=$((n+1))
done < "$W/list.n"
echo "ok   $n members: regular files and directories only, no traversal, nothing under $LANE_DIR"

# The live tree must not hold a symlink (outside the lane's directory, which the tar never touches).
links=$(find "$D" -path "$D/$LANE_DIR" -prune -o -type l -print | wc -l)
[ "$links" = 0 ] || { echo "refused: the live tree holds $links symlink(s); remove them first"; exit 4; }
echo "ok   live tree holds no symlink"

STAMP=$(date -u +%Y%m%dT%H%M%SZ); P=$(mktemp -d "$D.prev-$STAMP-XXXX")
cp -a "$D/." "$P/"; echo "ok   previous tree copied to $P"
tar -C "$D" --no-same-owner --no-same-permissions --no-overwrite-dir --delay-directory-restore -xf "$W/site.tar" || { echo "extract failed; the previous tree is at $P"; exit 5; }
echo "ok   extracted over $D"
echo "lane dir: $(stat -c '%U:%G %a' "$D/$LANE_DIR" 2>/dev/null || echo 'absent')"
echo "deployed $WANT; previous tree at $P"
