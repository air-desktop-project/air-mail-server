#!/usr/bin/env bash
#
# check-format — le formatage, aux DEUX endroits où ce dépôt en a.
#
# # POURQUOI CETTE BARRIÈRE EXISTE
#
# `cargo fmt --all -- --check` ne vivait que dans la CI. Rien ne l'empêchait de
# tourner en local — c'est deux secondes — mais il n'était dans aucune des cinq
# barrières qu'on passe avant de committer, et personne ne le lançait.
#
# Six tranches ont donc livré du code que le formateur du dépôt refuse. LA CI EST
# RESTÉE ROUGE SEIZE POUSSÉES DE SUITE, du 2026-09-04 au 2026-09-05, sans que
# personne ne lise son verdict.
#
# **Et ce que cet échec emportait était pire que le formatage.** `cargo fmt` est
# la PREMIÈRE étape du job de vérification : les quatre suivantes — `clippy`,
# `build`, `check-sans-c`, `cargo test` — n'ont jamais tourné pendant ces seize
# poussées. La barrière `check-sans-c`, câblée à la CI la veille, n'y avait donc
# jamais tourné une seule fois. Une étape qui échoue tôt n'échoue pas seule : elle
# emmène tout ce qui la suit, en silence.
#
# # LES DEUX PORTÉES, PARCE QU'IL Y EN A DEUX
#
# `fuzz/` VIT HORS DU WORKSPACE : `cargo fmt --all` ne l'atteint pas, et la CI
# avait donc deux étapes `fmt` dans deux jobs différents. Une barrière locale qui
# n'en aurait couvert qu'une aurait laissé l'autre se découvrir en intégration
# continue — exactement le défaut qu'elle est là pour fermer.
#
# Le pin de `rust-toolchain.toml` s'applique aux deux : rustup remonte
# l'arborescence, donc un seul rustfmt pour tout le dépôt.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-format — le workspace, et `fuzz/` qui n'"'"'en fait pas partie'
echo

violations=0

if cargo fmt --all -- --check; then
    echo "workspace : formaté"
else
    echo "ÉCHEC : le workspace n'est pas formaté (\`cargo fmt --all\` le corrige)."
    violations=$((violations + 1))
fi

if (cd fuzz && cargo fmt -- --check); then
    echo "fuzz/     : formaté"
else
    echo "ÉCHEC : \`fuzz/\` n'est pas formaté (\`cd fuzz && cargo fmt\` le corrige)."
    violations=$((violations + 1))
fi

if [ "$violations" -gt 0 ]; then
    echo
    echo "ÉCHEC : $violations portée(s) mal formatée(s)."
    exit 1
fi

echo
echo "OK : les deux portées passent \`cargo fmt --check\`."
