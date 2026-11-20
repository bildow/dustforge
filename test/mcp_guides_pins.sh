#!/bin/bash
# The three pins inside ops/demipass/publish-mcp-guides.py (what a tapped root-lane approval binds), the manifest and
# the committed public files must all agree (dustforge #140 review round 2).
set -u
W=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd); cd "$W"
python3 - <<'PY'
import ast, hashlib, json, sys
src = open('ops/demipass/publish-mcp-guides.py').read()
tree = ast.parse(src)
pins = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and n.targets[0].id == 'PINS')
manifest = json.load(open('ops/demipass/mcp-guides-manifest.json'))
fails = 0
if pins != manifest: print('FAIL script pins differ from the manifest'); fails += 1
else: print('ok   script pins == manifest (%d files)' % len(pins))
for rel, sha in pins.items():
    got = hashlib.sha256(open(rel, 'rb').read()).hexdigest()
    if got != sha: print('FAIL %s: %s != pinned %s' % (rel, got[:12], sha[:12])); fails += 1
    else: print('ok   %s matches its pin' % rel)
# The pinned SDK archive's defaults must be public HTTPS routes: the guide tells agents to leave CONDUIT_URL unset,
# so the archive's own default is the route. A tailnet name, a private address or plain http in the archive
# contradicts the guide and is a hold, whatever its hash says (ruling 2026-11-19: the tailnet never wires a product).
import io, re, tarfile
PRIVATE = re.compile(r"""['"]http://|\.ts\.net|\b100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|\b10\.\d+\.\d+\.\d+|\b192\.168\.|\b127\.0\.0\.1""")
for rel in pins:
    if not rel.endswith('.tgz'): continue
    with tarfile.open(rel, 'r:gz') as t:
        for m in t.getmembers():
            if not (m.isfile() and m.name.endswith('.js')): continue
            text = t.extractfile(m).read().decode('utf-8', 'replace')
            for ln, line in enumerate(text.splitlines(), 1):
                if ('DEFAULT_URL' in line or '_URL ||' in line or 'LORI_URL' in line) and PRIVATE.search(line):
                    print('FAIL %s: %s:%d has a private default route: %s' % (rel, m.name, ln, line.strip()[:110])); fails += 1
    if not fails:
        print('ok   %s: no private default routes in its JavaScript' % rel)
print('%d failure(s)' % fails); sys.exit(1 if fails else 0)
PY
