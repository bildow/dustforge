#!/usr/bin/env python3
"""relay-poller — read unseen mail from a Stalwart inbox and trigger the
owner's Dustforge forwarding rules via POST /api/relay/forward.

Config from /opt/dustforge/scripts/relay-poller.env (KEY=VALUE lines):
  IMAP_HOST, IMAP_PORT, IMAP_USER, IMAP_PASS, API_URL, API_TOKEN

A message is marked \\Seen only after the API accepts it, so transient
failures retry on the next run. A 404 (no active rules) also marks the
message seen — otherwise every run re-bills a forward attempt for mail
nobody asked to forward.
"""
import email
import email.header
import imaplib
import json
import ssl
import sys
import urllib.error
import urllib.request

ENV = '/opt/dustforge/scripts/relay-poller.env'
MAX_BODY = 100000


def load_env(path):
    cfg = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                cfg[k] = v
    return cfg


def decode_hdr(value):
    parts = email.header.decode_header(value or '')
    return ''.join(
        p.decode(enc or 'utf-8', 'replace') if isinstance(p, bytes) else p
        for p, enc in parts
    )


def text_body(msg):
    if msg.is_multipart():
        for want in ('text/plain', 'text/html'):
            for part in msg.walk():
                disp = part.get('Content-Disposition', '') or ''
                if part.get_content_type() == want and not disp.startswith('attachment'):
                    payload = part.get_payload(decode=True)
                    if payload is not None:
                        return payload.decode(part.get_content_charset() or 'utf-8', 'replace')
        return '(no text body)'
    payload = msg.get_payload(decode=True)
    if payload is None:
        return '(empty)'
    return payload.decode(msg.get_content_charset() or 'utf-8', 'replace')


def forward(cfg, subject, body, original_from):
    req = urllib.request.Request(
        cfg['API_URL'] + '/api/relay/forward',
        data=json.dumps({
            'subject': subject,
            'body': body[:MAX_BODY],
            'original_from': original_from,
        }).encode(),
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + cfg['API_TOKEN'],
        },
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def main():
    cfg = load_env(ENV)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Stalwart self-signed; link is tailnet-internal
    M = imaplib.IMAP4_SSL(cfg['IMAP_HOST'], int(cfg.get('IMAP_PORT', 993)), ssl_context=ctx)
    M.login(cfg['IMAP_USER'], cfg['IMAP_PASS'])
    M.select('INBOX')
    _, data = M.search(None, 'UNSEEN')
    uids = data[0].split()
    if uids:
        print(f'{len(uids)} unseen message(s)')
    for uid in uids:
        _, msgdata = M.fetch(uid, '(BODY.PEEK[])')
        msg = email.message_from_bytes(msgdata[0][1])
        subject = decode_hdr(msg.get('Subject')) or '(no subject)'
        sender = decode_hdr(msg.get('From')) or 'unknown'
        try:
            result = forward(cfg, subject, text_body(msg), sender)
            print(f'uid {uid.decode()}: forwarded={result.get("forwarded")}')
            M.store(uid, '+FLAGS', r'\Seen')
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print(f'uid {uid.decode()}: no active rules, marking seen')
                M.store(uid, '+FLAGS', r'\Seen')
            elif e.code == 402:
                print('wallet balance exhausted, aborting run', file=sys.stderr)
                break
            else:
                print(f'uid {uid.decode()}: HTTP {e.code}, will retry: {e.read()[:200]}', file=sys.stderr)
        except Exception as e:
            print(f'uid {uid.decode()}: forward failed, will retry: {e}', file=sys.stderr)
    M.logout()


if __name__ == '__main__':
    main()
