#!/usr/bin/env python3
"""Bounded static-site publication. No API checkout, DB, nginx or service changes.

Run through the operator's elevated DemiPass SSH approval, not a raw credential.
Usage: python3 publish-mcp-guides.py SOURCE_COMMIT
The three public assets are pinned below; the existing home page must match the
publicly captured baseline before a link is added. Backups and a receipt persist.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import urllib.request

ROOT = Path('/var/www/demipass')
BASELINE = '3cfaf0bfccd733b2b424bf078e4f614e42fb3e681d7ae6c59b13425c2c95de6e'
FILES = {
    'mcp-agents.html': '9cd303b0a0cd10ed926af59b590dbece5bf170a33283c89043a85f085bb72b6b',
    'mcp-agents.md': '0420a8ec1359c0eef5578a7d78f01462b07ede28a69a6bfadf018ace83ef056a',
    'downloads/demipass-conduit-eaf241e.tgz': 'e003742e3121786358e9fe698386a20eb73faeafee52fe5ed36961730c4f9629',
}
MARKER = 'id="mcp-service-guides"'
ANCHOR = b'<section id="agent">'
LINK = b'''<aside id="mcp-service-guides" class="wrap" style="padding-top:28px;padding-bottom:28px">
<div class="glasscard" style="padding:24px"><h2>Fleetgate &amp; Conduit for agents</h2>
<p>Set up code review and agent messaging with your own DemiPass identity. Includes verified SDK installation, service approvals, session addressing and receipt checks.</p>
<p style="margin-top:14px"><a class="textlink" href="/mcp-agents.html">Read the MCP agent instructions &rarr;</a> &nbsp; <a class="textlink" href="/mcp-agents.md">Plain-text guide</a></p></div></aside>
'''

def digest(data):
    return hashlib.sha256(data).hexdigest()

def read_regular(file):
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError('not a regular file: ' + str(file))
        with os.fdopen(fd, 'rb', closefd=False) as f:
            return f.read(2 * 1024 * 1024 + 1)
    finally:
        os.close(fd)

def replace(file, data, mode=0o644, owner=None):
    fd, name = tempfile.mkstemp(prefix='.mcp-publish-', dir=file.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            os.fchmod(f.fileno(), mode)
            if owner:
                os.fchown(f.fileno(), *owner)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, file)
        d = os.open(file.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def main(commit):
    if os.geteuid() != 0 or not re.fullmatch('[0-9a-f]{40}', commit):
        raise RuntimeError('root operator and exact source SHA required')
    if ROOT.resolve() != ROOT or not ROOT.is_dir():
        raise RuntimeError('unexpected site root; inspect before changing anything')
    index = ROOT / 'index.html'
    original = read_regular(index)
    originals = {}
    payloads = {}
    for name, sha in FILES.items():
        target = ROOT / name
        if target.parent.exists() and (target.parent.resolve() != target.parent or not target.parent.is_dir()):
            raise RuntimeError('unsafe target directory')
        prior = read_regular(target) if target.exists() or target.is_symlink() else None
        if prior is not None and digest(prior) != sha:
            raise RuntimeError('existing asset differs; preserve and reconcile: ' + name)
        originals[name] = prior
        url = 'https://raw.githubusercontent.com/bildow/dustforge/' + commit + '/public/' + name
        with urllib.request.urlopen(url, timeout=30) as r:
            data = r.read(2 * 1024 * 1024 + 1)
        if digest(data) != sha:
            raise RuntimeError('published asset checksum mismatch: ' + name)
        payloads[name] = data
    if MARKER.encode() in original:
        if all(originals[n] == payloads[n] for n in FILES):
            print('already published; no changes')
            return
        raise RuntimeError('partial prior publication; inspect before retry')
    if digest(original) != BASELINE or original.count(ANCHOR) != 1:
        raise RuntimeError('homepage moved or root mismatch; no changes made')
    new_index = original.replace(ANCHOR, LINK + ANCHOR, 1)
    meta = index.stat()
    backup_root = Path('/opt/backups/demipass-site-mcp')
    if backup_root.is_symlink():
        raise RuntimeError('unsafe backup root')
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix='publish-', dir=backup_root))
    (backup / 'index.html').write_bytes(original)
    (backup / 'assets-before.json').write_text(json.dumps({n: d is not None for n, d in originals.items()}))
    receipt = {'source_commit': commit, 'index_before': BASELINE, 'index_after': digest(new_index), 'assets': FILES, 'services_changed': False}
    (backup / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (ROOT / 'downloads').mkdir(mode=0o755, exist_ok=True)
    written = []
    try:
        for name, data in payloads.items():
            if originals[name] is None:
                target = ROOT / name
                if target.exists() or target.is_symlink():
                    raise RuntimeError('asset appeared during publication')
                replace(target, data)
                written.append(name)
        if read_regular(index) != original:
            raise RuntimeError('homepage changed during staging')
        replace(index, new_index, stat.S_IMODE(meta.st_mode), (meta.st_uid, meta.st_gid))
        for name, sha in FILES.items():
            if digest(read_regular(ROOT / name)) != sha:
                raise RuntimeError('installed asset mismatch')
        if read_regular(index) != new_index:
            raise RuntimeError('installed homepage mismatch')
    except Exception:
        if read_regular(index) == new_index:
            replace(index, original, stat.S_IMODE(meta.st_mode), (meta.st_uid, meta.st_gid))
        for name in written:
            if digest(read_regular(ROOT / name)) == FILES[name]:
                (ROOT / name).unlink()
        raise
    print(json.dumps({'published': True, 'backup': str(backup), **receipt}))

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        raise SystemExit('exact source commit required')
    main(sys.argv[1])
