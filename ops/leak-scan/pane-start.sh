#!/bin/bash
# SessionStart hook for agent panes (red team item 5): is any DemiPass vault value in what a pane reads at start —
# its memory directory and the CLAUDE.md files? Prints nothing when clean; a hit is printed (refs and file:lines,
# never a value) so the pane sees it, and the server mails the owner and revokes the token.
# Token: ~/.config/demipass-scan/pane-start.token (0600), from `leak-scan --request ~/.config/demipass-scan pane-start`.
set -u
TOK=${DEMIPASS_PANE_SCAN_TOKEN_FILE:-$HOME/.config/demipass-scan/pane-start.token}
SCANNER=${DEMIPASS_LEAK_SCAN:-$HOME/.local/lib/demipass/leak-scan.js}
[ -f "$TOK" ] && [ -f "$SCANNER" ] || { echo "leak-scan: not set up for this pane (no scan token or scanner) — red team item 5"; exit 0; }
targets=()
for p in "$HOME/.claude/CLAUDE.md" "$HOME/.claude/projects"/*/memory "$PWD/CLAUDE.md"; do [ -e "$p" ] && targets+=("$p"); done
[ ${#targets[@]} -gt 0 ] || exit 0
out=$(DEMIPASS_SCAN_TOKEN_FILE="$TOK" timeout 60 node "$SCANNER" "${targets[@]}" 2>&1); rc=$?
case $rc in
  0) exit 0 ;;
  1) echo "LEAK SCAN: a DemiPass vault value is in a file this pane reads — rotate it and remove the copy (the owner was mailed; this pane's scan token is revoked):"; echo "$out" | grep '^LEAK' ;;
  *) echo "leak-scan could not run at pane start: $(echo "$out" | tail -1)" ;;
esac
exit 0
