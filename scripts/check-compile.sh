#!/usr/bin/env bash
#
# check-compile — tout compile-t-il, AUX DEUX ENDROITS où il y a du code ?
#
# # POURQUOI CETTE BARRIÈRE EXISTE
#
# `fuzz/` vit HORS du workspace, et pour une bonne raison : `cargo-fuzz` exige un
# nightly, le workspace est épinglé sur stable, et deux LLVM dans une même
# mesure de couverture ne se relisent pas (voir `fuzz/Cargo.toml`).
#
# **La conséquence est qu'aucune commande ordinaire ne le compile.** Ni
# `cargo build --workspace`, ni `cargo clippy --workspace --all-targets`, ni
# `cargo test --workspace` n'y entrent. Le seul contrôle qui les bâtissait était
# `check-fuzz.sh`, c'est-à-dire le DERNIER de la liste, et celui qui dure
# vingt-cinq minutes.
#
# # CE QUE CE TROU A COÛTÉ, DEUX FOIS DE SUITE
#
# — 2026-09-05, tranche du `405` : la propriété 4 de `fuzz_ams_api_route`
#   affirmait un contrat qu'on venait de changer. Campagne perdue.
# — 2026-09-05, tranche SPECIAL-USE : la signature du trait `Mailboxes::create`
#   et le champ `Listing::special` avaient été portés partout SAUF dans
#   `fuzz_ams_session_imap.rs`. Campagne perdue.
#
# Les deux fois, l'erreur était un défaut de COMPILATION, connu en une seconde
# par `cargo check`. Les deux fois, on l'a appris vingt-cinq minutes plus tard.
#
# **Une erreur qu'on ne peut apprendre qu'en payant vingt-cinq minutes finit par
# se payer plusieurs fois** : on relance, on attend, on recommence. Ce n'est pas
# de la distraction, c'est un trou dans l'outillage — et deux occurrences en un
# jour suffisent à le dire.
#
# # POURQUOI `cargo check` ET NON `clippy`
#
# `fuzz/` n'hérite PAS des lints du workspace : hors du workspace, il n'a pas de
# `[lints] workspace = true`, et l'y ajouter ferait entrer les règles du produit
# dans du code qui n'est pas livré. Ce qui manquait n'était pas du style, c'était
# la COMPILATION — un trait dont la signature a changé. On vérifie donc ce qui
# manquait, et rien de plus.
#
# `cargo check` suffit aussi pour une autre raison : il tourne sur la toolchain
# ÉPINGLÉE. Le nightly de `cargo-fuzz` n'est nécessaire qu'à
# l'instrumentation — ni `libfuzzer-sys` ni `arbitrary` n'exigent autre chose
# pour être TYPÉS. Cette barrière n'a donc rien à installer, et peut vivre dans
# le job de vérification ordinaire.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-compile — le workspace, et `fuzz/` qui n'"'"'en fait pas partie'
echo

violations=0

if cargo check --workspace --all-targets --locked; then
    echo "workspace : compile"
else
    echo "ÉCHEC : le workspace ne compile pas."
    violations=$((violations + 1))
fi

echo

# `--bins` ET NON `--all-targets` : cette crate n'a que des binaires de fuzz, et
# `--all-targets` y chercherait des essais qui n'existent pas.
if (cd fuzz && cargo check --bins --locked); then
    echo "fuzz/     : compile"
else
    echo "ÉCHEC : \`fuzz/\` ne compile pas — la campagne échouerait AVANT de fuzzer."
    violations=$((violations + 1))
fi

if [ "$violations" -gt 0 ]; then
    echo
    echo "ÉCHEC : $violations portée(s) ne compilent pas."
    exit 1
fi

echo
echo "OK : les deux portées compilent."
