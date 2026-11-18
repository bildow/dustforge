#!/bin/bash
# Read-only. The facts the Brain-lane decision rests on (seat relay 2026-11-18, steps 1 and 4): what Brain's deploy
# lane (brain-deploy, key lane /usr/local/libexec/dustanvil-deploy-sync) has EVER written under the dustanvil web root,
# and what else that account can write on this host. Changes nothing; prints no key material.
# The lane snapshots the live tree (cp -al) before each sync into /var/www/dustanvil-snapshots/<UTC stamp> and logs each
# run through logger: both are the record of its writes. Ownership is not: the main-site deploy extracts as
# brain-deploy by design, so every file under the root is brain-deploy's whichever lane wrote it.
set -u
export LC_ALL=C
D=/var/www/dustanvil; SNAPS=/var/www/dustanvil-snapshots; SYNC=/usr/local/libexec/dustanvil-deploy-sync
echo "== now: $(date -u +%FT%TZ)"
echo "== the lane's log tag and what it logs"
TAG=$(grep -o -E "logger -t ['\"]?[A-Za-z0-9._-]+" "$SYNC" 2>/dev/null | head -1 | awk '{print $3}' | tr -d "'\"")
[ -n "$TAG" ] && echo "tag: $TAG" || echo "tag: (none found in $SYNC)"
echo "== every run of the lane in the journal (all time; count, first, last, and the last 40 lines)"
if [ -n "$TAG" ]; then
  journalctl -t "$TAG" --no-pager -o short-iso 2>/dev/null | wc -l
  journalctl -t "$TAG" --no-pager -o short-iso 2>/dev/null | head -1
  journalctl -t "$TAG" --no-pager -o short-iso 2>/dev/null | tail -40
fi
echo "== sshd: sessions of brain-deploy (all time; count, first, last)"
journalctl -u ssh -u sshd --no-pager -o short-iso 2>/dev/null | grep -E "Accepted .* for brain-deploy" | wc -l
journalctl -u ssh -u sshd --no-pager -o short-iso 2>/dev/null | grep -E "Accepted .* for brain-deploy" | head -1
journalctl -u ssh -u sshd --no-pager -o short-iso 2>/dev/null | grep -E "Accepted .* for brain-deploy" | tail -3
echo "== snapshots the lane took (one per sync that reached the live tree)"
if [ -d "$SNAPS" ]; then ls -la --time-style=+%FT%TZ "$SNAPS" 2>&1 | tail -n +2; else echo "(no $SNAPS)"; fi
echo "== what differs between the newest snapshot and the live tree (names only, lane dir excluded): what the LAST sync changed"
NEWEST=$(ls -1 "$SNAPS" 2>/dev/null | sort | tail -1)
if [ -n "$NEWEST" ]; then diff -rq "$SNAPS/$NEWEST" "$D" 2>/dev/null | grep -v "evals/MCI-1" | sed 's#^#   #' | head -60; else echo "(no snapshot)"; fi
echo "== files under the web root newer than the main-site deploy's previous-tree copy (written since; lane dir excluded)"
PREV=$(ls -1d "$D".prev-* 2>/dev/null | sort | tail -1)
if [ -n "$PREV" ]; then echo "reference: $PREV"; find "$D" -path "$D/evals/MCI-1" -prune -o -type f -newer "$PREV" -printf '%TY-%Tm-%TdT%TH:%TM:%TSZ %u %p\n' 2>/dev/null | sort | tail -40; else echo "(no .prev tree)"; fi
echo "== what else brain-deploy can write on this host (directories; / scanned, proc/sys/dev/run/tmp excluded)"
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp -o -path /var/lib/brain-deploy \) -prune -o -type d -writable -user brain-deploy -print 2>/dev/null | head -40
echo "-- group-writable by a group brain-deploy is in ($(id -Gn brain-deploy 2>/dev/null))"
for g in $(id -Gn brain-deploy 2>/dev/null); do find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type d -group "$g" -perm -g+w -print 2>/dev/null | head -20; done
echo "-- world-writable directories without the sticky bit (anyone, brain-deploy included)"
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type d -perm -o+w ! -perm -1000 -print 2>/dev/null | head -20
echo "-- sudo for brain-deploy"; sudo -l -U brain-deploy 2>&1 | tail -5
echo "-- its home and shell"; getent passwd brain-deploy | cut -d: -f1,6,7; ls -la /var/lib/brain-deploy 2>&1 | head -8
echo "== done"
