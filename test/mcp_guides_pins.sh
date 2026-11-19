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
print('%d failure(s)' % fails); sys.exit(1 if fails else 0)
PY
