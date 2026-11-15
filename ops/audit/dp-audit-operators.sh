#!/bin/bash
# Read-only audit (2026-11-14), run once by root on racknerd after a phone approval. Changes nothing.
# 1) every project operator on every fleet, and whether it points at a real, live wallet;
# 2) every HTTP call that added or removed an operator (nginx), since the logs begin;
# 3) evidence of database faults in the gateway's journal since 2026-07-06 (when token revocation shipped): the deployed
#    code let a token through on a failed revocation lookup WITHOUT logging, so only faults logged by other code paths
#    can be counted, never the let-through itself.
# DIDs are shortened; no secret, token or key is read or printed.
set -u
DB=/opt/dustforge/data/dustforge.db
echo "== 1. operators (fleet | owner | project | operator | added_at | wallet | status | silicon of the fleet | member role)"
cd /opt/dustforge && node - "$DB" <<'JS'
const D = require("/opt/dustforge/node_modules/better-sqlite3");
const db = new D(process.argv[2], { readonly: true, fileMustExist: true });
const t = (s) => (s ? String(s).slice(0, 20) + "…" : "-");
const rows = db.prepare(`SELECT f.slug, f.owner_did, (SELECT username FROM identity_wallets WHERE did = f.owner_did) AS owner_user,
    p.project, o.operator_did, o.added_at, w.did AS w, w.status AS ws, w.username AS wu,
    (SELECT 1 FROM fleet_silicons s WHERE s.fleet_id = f.id AND s.member_did = o.operator_did AND s.status = 'active') AS sil,
    (SELECT role FROM fleet_members m WHERE m.fleet_id = f.id AND m.member_did = o.operator_did) AS role
  FROM fleet_project_operators o JOIN fleet_projects p ON p.id = o.project_id JOIN fleets f ON f.id = p.fleet_id
  LEFT JOIN identity_wallets w ON w.did = o.operator_did ORDER BY o.added_at`).all();
for (const r of rows) console.log([r.slug, r.owner_user || t(r.owner_did), r.project, (r.wu ? "@" + r.wu + " " : "") + t(r.operator_did), r.added_at,
  r.w ? "wallet" : "NO WALLET", r.ws || "-", r.sil ? "silicon" : "-", r.role || "-", r.operator_did === r.owner_did ? "(owner)" : ""].join(" | "));
const orphan = db.prepare("SELECT COUNT(*) AS n FROM fleet_project_operators o LEFT JOIN fleet_projects p ON p.id = o.project_id WHERE p.id IS NULL").get().n;
console.log("rows:", rows.length, "| fleets:", db.prepare("SELECT COUNT(*) AS n FROM fleets").get().n,
  "| projects:", db.prepare("SELECT COUNT(*) AS n FROM fleet_projects").get().n, "| operator rows whose project is gone:", orphan,
  "| pointing at no wallet:", rows.filter((r) => !r.w).length);
JS
echo
echo "== 2. operator add/remove calls in the nginx access logs (time | client | method path | status | agent)"
ls -1 /var/log/nginx/ 2>/dev/null | head -20
for f in /var/log/nginx/*access*.log*; do
  case "$f" in *.gz) zcat -f "$f";; *) cat "$f";; esac
done 2>/dev/null | grep -E '"(POST|DELETE) /api/fleet/[^ ]+/board/[^ ]+/operators' | awk -F'"' '{split($1,a," "); print a[4] a[5], "|", a[1], "|", $2, "|", $3, "|", $6}' | sed 's/did%3Akey%3A\([A-Za-z0-9_-]\{12\}\)[A-Za-z0-9_-]*/did:key:\1…/g; s/did:key:\([A-Za-z0-9_-]\{12\}\)[A-Za-z0-9_-]*/did:key:\1…/g'
echo "earliest access-log line:"; for f in $(ls -1tr /var/log/nginx/*access*.log* 2>/dev/null | head -1); do zcat -f "$f" | head -1 | cut -c1-60; done
echo
echo "== 3. database faults in the gateway journal since 2026-07-06"
U=$(systemctl list-units --all --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -i -E '^dustforge(\.service)?$|dustforge' | head -3)
echo "units: $U"
for u in $U; do
  echo "-- $u: journal begins: $(journalctl -u "$u" --no-pager -q -o short-iso 2>/dev/null | head -1 | cut -c1-25)"
  journalctl -u "$u" --since 2026-07-06 --no-pager -q -o short-iso 2>/dev/null \
    | grep -i -E 'SQLITE_(BUSY|LOCKED|IOERR|CORRUPT|FULL|CANTOPEN|READONLY)|database is locked|disk I/O error|database disk image is malformed|no such table: (issued_tokens|token_revocations|fleet_token_cuts)' \
    | awk '{print substr($1,1,10)}' | sort | uniq -c | head -60
  echo "   (count by day; empty = none logged)"
done
echo "== done"
