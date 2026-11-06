# Sourced by smoke tests (needs their call/J/fail). Two wallets become contacts confirmed in person, through the real
# pairing API (pairing.js): A shows the QR, B scans it, each confirms with its PIN.
#   pair_in_person TOKEN_A PIN_A TOKEN_B PIN_B
pair_in_person(){ local a=$1 pa=$2 b=$3 pb=$4 id tok
  call POST /api/network/pair/start "$a"; tok=$(echo "$BODY" | J token); id=$(echo "$BODY" | J pair_id)
  call POST /api/network/pair/join "$b" '{"token":"'"$tok"'"}'; [ "$CODE" = 200 ] || { fail "pair join: $CODE $BODY"; return 1; }
  call POST /api/identity/gate/verify "$a" '{"gate":"pin","pin":"'"$pa"'","intent":"pair:'"$id"'"}'
  call POST /api/network/pair/$id/confirm "$a" '{}'; [ "$CODE" = 200 ] || { fail "pair confirm A: $CODE $BODY"; return 1; }
  call POST /api/identity/gate/verify "$b" '{"gate":"pin","pin":"'"$pb"'","intent":"pair:'"$id"'"}'
  call POST /api/network/pair/$id/confirm "$b" '{}'
  [ "$CODE" = 200 ] && [ "$(echo "$BODY" | J connected)" = True ] || { fail "pair confirm B: $CODE $BODY"; return 1; }
}
