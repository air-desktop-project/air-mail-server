#!/usr/bin/env bash
#
# check-fuzz — toutes les cibles de fuzz existent-elles, se formatent-elles, et
# compilent-elles ?
#
# # Pourquoi ce script existe
#
# La crate de fuzz vit HORS DU WORKSPACE (voir `fuzz/README.md` : deux
# toolchains, deux LLVM, et un gate de couverture qui ne pourrait plus conclure).
# La conséquence tient en une phrase : `cargo build --workspace` ne la touche
# pas. Une cible qui cesse de compiler ne se voit donc ni au build, ni aux tests,
# ni au clippy — seulement en intégration continue, après un `push`.
#
# **C'est arrivé deux fois**, les deux fois en changeant un trait que les cibles
# implémentent. La première, la cible était en plus absente de la liste du
# smoke-test, et ne compilait plus depuis deux commits sans que rien ne le dise.
#
# # Ce que ce script vérifie
#
#   1. La LISTE des cibles coïncide avec les `[[bin]]` de `fuzz/Cargo.toml`.
#      Une cible ajoutée sans être inscrite ici ne serait jamais lancée, et le
#      gate resterait vert en ne l'ayant pas examinée.
#   2. Elles sont FORMATÉES — `cargo fmt --all` à la racine ne les touche pas.
#   3. TOUTES les cibles compilent.
#   4. Avec `--smoke`, chacune tourne vingt secondes sur ses graines —
#      `AMS_FUZZ_SECONDES` en décide autrement, pour une campagne plus longue.
#
# La liste vit ICI et non dans le workflow : la CI appelle ce script, et l'on
# peut donc lancer en local exactement ce qu'elle lancera. Un contrôle qu'on ne
# peut pas rejouer chez soi est un contrôle qu'on découvre en CI.
#
# # ET LES MÊMES DRAPEAUX QU'EN INTÉGRATION CONTINUE
#
# Le workflow pose `RUSTFLAGS: -D warnings` pour tout le travail. Ce script ne le
# posait pas : un `unused import` dans une cible passait donc en local et
# échouait après le `push`. « On peut lancer en local ce que la CI lancera »
# n'est vrai que si les drapeaux suivent — sans quoi c'est le même script, et
# pas la même épreuve.
#
# Chaque cible a ses graines, qu'aucune convention de nommage ne devine :
# `fuzz_ams_mime_parse` se sème avec `seeds/mime`. D'où la table.

set -euo pipefail

# Les mêmes que le workflow, pour que l'épreuve locale soit celle de la CI.
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"

smoke=0
if [ "${1-}" = "--smoke" ]; then
    smoke=1
fi
secondes="${AMS_FUZZ_SECONDES-20}"

racine=$(cd "$(dirname "$0")/.." && pwd)
cd "$racine/fuzz"

# <cible> <répertoire de graines>
CIBLES=$(cat <<'TABLE'
fuzz_ams_mime_parse mime
fuzz_ams_mime_limits mime
fuzz_ams_mime_compose mime-compose
fuzz_ams_mime_digest mime-digest
fuzz_ams_mime_bounce mime-bounce
fuzz_ams_queue queue
fuzz_ams_dane dane
fuzz_ams_mtasts mtasts
fuzz_ams_http_response http-response
fuzz_ams_mime_envelope mime-envelope
fuzz_ams_mime_structure mime-structure
fuzz_ams_mime_decode mime-decode
fuzz_ams_smtp_command smtp
fuzz_ams_smtp_limits smtp
fuzz_ams_smtp_reply smtp-reply
fuzz_ams_smtp_data smtp-data
fuzz_ams_smtp_client smtp-client
fuzz_ams_session_smtp session
fuzz_ams_pop3 pop3
fuzz_ams_session_pop3 pop3-session
fuzz_ams_imap imap
fuzz_ams_imap_fetch imap-fetch
fuzz_ams_session_imap imap-session
fuzz_ams_http_head http-head
fuzz_ams_h2_frame h2-frame
fuzz_ams_h2_hpack h2-hpack
fuzz_ams_h2_connection h2-connection
fuzz_ams_quic_varint quic-varint
fuzz_ams_quic_packet quic-packet
fuzz_ams_h3_frame h3-frame
fuzz_ams_h3_connection h3-connection
fuzz_ams_h3_driver h3-driver
fuzz_ams_api_route api-route
fuzz_ams_api_token api-token
fuzz_ams_api_json api-json
fuzz_ams_session_http session-http
fuzz_ams_session_render session-render
fuzz_ams_quic_crypto quic-crypto
fuzz_ams_quic_receive quic-receive
fuzz_ams_quic_stream quic-stream
fuzz_ams_quic_streams quic-streams
fuzz_ams_quic_connection quic-connection
fuzz_ams_quic_handshake quic-handshake
fuzz_ams_quic_routing quic-routing
fuzz_ams_quic_emit quic-emit
fuzz_ams_quic_sent quic-sent
fuzz_ams_guard guard
fuzz_ams_index_name index
fuzz_ams_config config
fuzz_ams_tls_kx tls
fuzz_ams_tls_quic tls-quic
fuzz_ams_sasl sasl
fuzz_ams_spf spf
fuzz_ams_spf_eval spf-eval
fuzz_ams_spf_header spf-header
fuzz_ams_dns dns
fuzz_ams_dkim dkim
fuzz_ams_dmarc dmarc
fuzz_ams_dmarc_report dmarc-report
TABLE
)

listees=$(mktemp)
declarees=$(mktemp)
trap 'rm -f "$listees" "$declarees"' EXIT

awk '{print $1}' <<< "$CIBLES" | sort > "$listees"
grep -A1 '^\[\[bin\]\]' Cargo.toml | sed -n 's/^name = "\(.*\)"/\1/p' | sort > "$declarees"

if ! diff -u "$declarees" "$listees"; then
    echo >&2
    echo "ÉCHEC : ce script et \`fuzz/Cargo.toml\` ne nomment pas les mêmes cibles." >&2
    echo "Celles qui manquent ici ne seraient jamais lancées, et le gate resterait" >&2
    echo "vert en ne les ayant pas examinées." >&2
    exit 1
fi

echo "$(wc -l < "$listees") cible(s), et la liste coïncide avec \`Cargo.toml\`."

# LE FORMATAGE AUSSI VIT HORS DU WORKSPACE. `cargo fmt --all` à la racine ne
# touche pas cette crate : un `cargo fmt` lancé là-haut laisse celle-ci non
# formatée, et la CI est alors la première à le voir — après un `push`. C'est
# exactement le genre d'aller-retour que ce script existe pour éviter.
echo "── formatage ────────────────────────────────────────────────────────────"
cargo fmt -- --check

# UN SEUL `cargo fuzz build` LES BÂTIT TOUTES, et c'est le contrôle qui manquait.
echo "── compilation ──────────────────────────────────────────────────────────"
cargo +nightly fuzz build --target x86_64-unknown-linux-gnu

if [ "$smoke" -eq 0 ]; then
    echo
    echo "OK : toutes les cibles compilent. (\`--smoke\` pour les faire tourner.)"
    exit 0
fi

while read -r cible graines; do
    echo "::group::$cible"
    # libFuzzer EXIGE que le premier répertoire de corpus existe : il n'y écrit
    # que s'il peut l'ouvrir, et refuse de démarrer sinon.
    mkdir -p "corpus/$cible"
    cargo +nightly fuzz run --target x86_64-unknown-linux-gnu "$cible" \
        "corpus/$cible" "seeds/$graines" -- "-max_total_time=$secondes"
    echo "::endgroup::"
done <<< "$CIBLES"

echo
echo "OK : les $(wc -l < "$listees") cibles compilent et tournent."
