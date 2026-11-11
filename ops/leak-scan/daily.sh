#!/bin/bash
# Daily (systemd user timer): what was appended to transcripts and tome files since the last run (red team item 5).
# --incremental keeps per-file offsets, saved as each file is scanned clean, so a run the daily budget stops resumes
# the next day. Any failure (a hit, the budget, the server) is written to ~/.local/state/demipass/leak-daily-failed,
# which the pane-start hook shows to every new pane until a clean run removes it (#45 review M4).
# Token: ~/.config/demipass-scan/pane-daily.token (0600).
set -u
TOK=${DEMIPASS_DAILY_SCAN_TOKEN_FILE:-$HOME/.config/demipass-scan/pane-daily.token}
ST=$HOME/.local/state/demipass; mkdir -p "$ST"; chmod 700 "$ST"
fail(){ printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" > "$ST/leak-daily-failed"; exit "${2:-2}"; }
SCANNER=${DEMIPASS_LEAK_SCAN:-$HOME/.local/lib/demipass/leak-scan.js}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
# The token is a request the owner approves in the app, never a step anyone runs (Aaron 2026-11-08). Each run first
# claims an approved request; with no usable token it files one (only one waits at a time) and stops until approved.
TOKDIR=$(dirname "$TOK"); LABEL=$(basename "$TOK" .token)
node "$SCANNER" --claim "$TOKDIR" >/dev/null 2>&1
ask_token(){
  local p; p=$(ls "$TOKDIR"/.pending-*.json 2>/dev/null | head -1)
  # The request number is named, so the owner approves this one and not a look-alike someone else filed (#92 review M5).
  if [ -n "$p" ]; then fail "waiting for you to approve the $LABEL scan token — request #$(basename "$p" .json | sed 's/^.pending-//') in the DemiPass app (Settings → Leak scanner)"; fi
  # A denial is respected for 7 days before this asks again (#92 review M4).
  local d="$TOKDIR/.denied-$LABEL"
  if [ -f "$d" ] && [ -z "$(find "$d" -mtime +7 2>/dev/null)" ]; then fail "$1 — you denied the last $LABEL scan token request; this asks again 7 days after that"; fi
  rm -f "$d"
  local out2 r; out2=$(node "$SCANNER" --request --no-wait "$TOKDIR" "$LABEL" 2>&1); r=$?
  [ $r = 0 ] && return 0
  if [ $r = 3 ]; then p=$(ls "$TOKDIR"/.pending-*.json 2>/dev/null | head -1)
    fail "$1 — a new $LABEL scan token was requested (#$(basename "$p" .json | sed 's/^.pending-//')): approve it in the DemiPass app (Settings → Leak scanner); the next run picks it up"; fi
  fail "$1 — asking for a new $LABEL scan token failed: $(echo "$out2" | tail -1)"
}
[ -s "$TOK" ] || ask_token "there was no scan token"
# Transcripts are append-only: only what was added since the last run (--incremental). Tome files are edited in place:
# each one changed in the last 26 h is scanned whole (#45 re-review).
find "$HOME/.claude/projects" -name '*.jsonl' -mmin -1560 -size -60M -print0 2>/dev/null > "$T/jsonl"
find "$HOME/project/tome" -path '*/.git' -prune -o -type f -mmin -1560 -size -20M -print0 2>/dev/null > "$T/tome"
run(){ local list=$1; shift; local targets=(); while IFS= read -r -d '' f; do targets+=("$f"); done < "$list"
  [ ${#targets[@]} -gt 0 ] || return 0
  out=$(DEMIPASS_SCAN_TOKEN_FILE="$TOK" node "$SCANNER" "$@" "${targets[@]}" 2>&1); local rc=$?; echo "$out"; return $rc; }
run "$T/jsonl" --incremental "$ST/leak-offsets.json"; rc=$?
[ $rc = 0 ] && { run "$T/tome"; rc=$?; }
# A token revoked by an earlier hit (its drain window over): set it aside and ask for the next one.
# Only the server's own words for a token spent by a hit (not any line with "revoked" in it: a path, an owner revoke).
if [ $rc = 2 ] && echo "$out" | grep -q 'HTTP 401: this scan token found a leak and was revoked'; then mv -f "$TOK" "$TOK.revoked" 2>/dev/null; ask_token "the scan token was spent by an earlier hit"; fi
case $rc in
  0) rm -f "$ST/leak-daily-failed" ;;
  1) fail "the daily leak scan FOUND a vault value — details in the DemiPass app (Settings → Leak scanner, with your PIN) and mail" ;;
  *) fail "the daily leak scan could not finish: $(echo "$out" | tail -1)" ;;
esac
