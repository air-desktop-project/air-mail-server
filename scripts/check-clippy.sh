#!/usr/bin/env bash
#
# check-clippy — les lints du produit, avant la CI et non après elle.
#
# # LE DÉFAUT QUE CETTE BARRIÈRE FERME
#
# Clippy comptait déjà parmi les dix barrières, mais SANS SCRIPT : il fallait
# se souvenir de taper la commande, alors que ses neuf voisines se déroulent en
# lançant `scripts/check-*.sh`. Le 2026-09-06, une tranche est partie avec deux
# erreurs de lint dans un essai neuf — `fin + 1` et `rang as u32` — et la CI l'a
# dit vingt-cinq minutes plus tard.
#
# C'est mot pour mot l'argument que `check-compile.sh` porte déjà : « une erreur
# qu'on ne peut apprendre qu'en payant vingt-cinq minutes finit par se payer
# plusieurs fois ». Une barrière qui n'existe que dans une liste n'est pas une
# barrière, c'est un rappel — et un rappel se saute.
#
# # POURQUOI `check-compile` NE SUFFISAIT PAS
#
# Les deux règles qui ont manqué — `arithmetic_side_effects` et
# `cast_possible_truncation` — sont déclarées `deny` dans le `[lints]` du
# workspace, mais ce sont des lints CLIPPY : `cargo check` ne les voit pas, et
# ne peut pas les voir. La barrière qui compile et celle qui lint regardent deux
# choses différentes, et la seconde n'avait pas d'outil.
#
# # CE QU'ELLE LANCE, ET POURQUOI EXACTEMENT CELA
#
# La MÊME commande que la CI, `--locked` compris. Une barrière locale plus
# indulgente que la CI ne fait que déplacer l'attente ; une plus sévère ferait
# refuser des tranches que la CI accepterait. On copie donc, et le commentaire
# ci-dessous est là pour qu'un changement dans `ci.yml` se répercute ici.
#
#     ci.yml, étape « cargo clippy » :
#         cargo clippy --workspace --all-targets --locked -- -D warnings
#
# `fuzz/` n'y est pas, et c'est délibéré : hors du workspace, il n'hérite pas de
# `[lints]`, et l'y soumettre ferait entrer les règles du produit dans du code
# qui n'est pas livré. Sa compilation, elle, est couverte par `check-compile`.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-clippy — les lints du workspace, comme la CI les passe'
echo

if cargo clippy --workspace --all-targets --locked -- -D warnings; then
    echo
    echo 'OK : `cargo clippy --workspace --all-targets` ne dit rien.'
else
    echo
    echo 'ÉCHEC : clippy refuse. La CI dira la même chose, vingt-cinq minutes plus tard.'
    exit 1
fi
