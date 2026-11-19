#!/usr/bin/env python3
"""Link the MCP agent guides from the demipass.com home page. Root, once, through the DemiPass root lane.

The guides themselves need no root: nginx serves every path but `/` from /opt/dustforge/public, so a normal
dustforge-deploy makes /mcp-agents.html, /mcp-agents.md and the SDK archive live. Only the home page
(/var/www/demipass/index.html, a RackNerd-only file in no repo) needs this: one <aside> inserted before the
"agent" section, after the three assets are checked on disk against ops/demipass/mcp-guides-manifest.json.
No network, no argument, no service change. The home page must still be the captured baseline (sha256 of
the origin file, fetched with --resolve past Cloudflare, whose email-protection rewrites a CDN copy per
response); otherwise nothing changes. A backup of index.html and a receipt are written under
/opt/backups/demipass-site-mcp; the receipt only after the installed page verifies.
Run through the lane as `python3 - <stdin` with this file's bytes on stdin, so the approval binds the exact
program (dustforge #140 review M2: root must not execute a file the deploy identity can rewrite).
Idempotent: with the link present and the assets matching, "already published".
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

ROOT = Path('/var/www/demipass')
PUBLIC = Path('/opt/dustforge/public')
MANIFEST = Path('/opt/dustforge/ops/demipass/mcp-guides-manifest.json')
BACKUPS = Path('/opt/backups/demipass-site-mcp')
BASELINE = '4fe3dd2783d9e5e30c3994fab428f01ee7cd508b7b49626210473c6e6b014dd0'   # origin index.html, 2026-11-19, 87209 B
MARKER = b'id="mcp-service-guides"'
ANCHOR = b'<section id="agent">'
LINK = b'''<aside id="mcp-service-guides" class="wrap" style="padding-top:28px;padding-bottom:28px">
<div class="glasscard" style="padding:24px"><h2>Fleetgate &amp; Conduit for agents</h2>
<p>Set up code review and agent messaging with your own DemiPass identity. Includes verified SDK installation, service approvals, session addressing and receipt checks.</p>
<p style="margin-top:14px"><a class="textlink" href="/mcp-agents.html">Read the MCP agent instructions &rarr;</a> &nbsp; <a class="textlink" href="/mcp-agents.md">Plain-text guide</a></p></div></aside>
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(file, limit=2 * 1024 * 1024 + 1):
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError('not a regular file: ' + str(file))
        with os.fdopen(fd, 'rb', closefd=False) as f:
            return f.read(limit)
    finally:
        os.close(fd)


def replace(file, data, mode, owner):
    fd, name = tempfile.mkstemp(prefix='.mcp-publish-', dir=file.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            os.fchmod(f.fileno(), mode)
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


def no_symlink_path(p):
    # Every component root-controlled and not a symlink (the leaf included).
    for q in [p] + list(p.parents):
        if q.is_symlink():
            raise RuntimeError('symlink in path: ' + str(q))


def main():
    if os.geteuid() != 0:
        raise RuntimeError('root operator required (the DemiPass root lane)')
    for p in (ROOT, PUBLIC, MANIFEST.parent):
        no_symlink_path(p)
        if not p.is_dir():
            raise RuntimeError('missing directory: ' + str(p))
    # 1. the three assets are live on disk (a deploy put them there) and are the reviewed bytes
    manifest = json.loads(read_regular(MANIFEST, 64 * 1024).decode('utf-8'))
    if not isinstance(manifest, dict) or len(manifest) != 3 or any(not k.startswith('public/') for k in manifest):
        raise RuntimeError('manifest: three public/ entries expected')
    for rel, sha in manifest.items():
        f = PUBLIC / rel[len('public/'):]
        no_symlink_path(f)
        if digest(read_regular(f)) != sha:
            raise RuntimeError('deployed asset differs from the manifest: ' + rel)
    # 2. the home page
    index = ROOT / 'index.html'
    original = read_regular(index)
    if MARKER in original:
        print(json.dumps({'published': False, 'already': True, 'index_sha256': digest(original)}))
        return
    if digest(original) != BASELINE or original.count(ANCHOR) != 1:
        raise RuntimeError('home page is not the captured baseline (sha256 %s, anchors %d): no changes made'
                           % (digest(original), original.count(ANCHOR)))
    new_index = original.replace(ANCHOR, LINK + ANCHOR, 1)
    meta = index.stat()
    # 3. backup, then the one replace, then verify, then the receipt
    if Path('/opt/backups').is_symlink() or BACKUPS.is_symlink():
        raise RuntimeError('unsafe backup root')
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix='publish-', dir=BACKUPS))
    (backup / 'index.html').write_bytes(original)
    if read_regular(index) != original:
        raise RuntimeError('home page changed during staging; no changes made')
    replace(index, new_index, stat.S_IMODE(meta.st_mode), (meta.st_uid, meta.st_gid))
    try:
        if read_regular(index) != new_index:
            raise RuntimeError('installed home page mismatch')
    except Exception:
        replace(index, original, stat.S_IMODE(meta.st_mode), (meta.st_uid, meta.st_gid))
        raise
    receipt = {'published': True, 'backup': str(backup), 'index_before': BASELINE, 'index_after': digest(new_index),
               'assets': manifest, 'services_changed': False}
    (backup / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
