#!/bin/bash
# Daily (systemd user timer): transcripts and tome files written in the last day (red team item 5). Exit 1 on a hit.
# (The whole tome is 130+ MB, past a token's 64 MB a day: each file is scanned the day it changes.)
# Token: ~/.config/demipass-scan/pane-daily.token (0600).
set -u
TOK=${DEMIPASS_DAILY_SCAN_TOKEN_FILE:-$HOME/.config/demipass-scan/pane-daily.token}
SCANNER=${DEMIPASS_LEAK_SCAN:-$HOME/.local/lib/demipass/leak-scan.js}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
# Only transcripts touched in the last 26 h (the budget is 64 MB a day), linked, not copied.
{ find "$HOME/.claude/projects" -name '*.jsonl' -mmin -1560 -size -60M -print0 2>/dev/null
  find "$HOME/project/tome" -path '*/.git' -prune -o -type f -mmin -1560 -size -20M -print0 2>/dev/null; } > "$T/list"
targets=()
while IFS= read -r -d '' f; do targets+=("$f"); done < "$T/list"
[ ${#targets[@]} -gt 0 ] || { echo "leak-scan daily: nothing changed in the last day"; exit 0; }
DEMIPASS_SCAN_TOKEN_FILE="$TOK" node "$SCANNER" "${targets[@]}"
