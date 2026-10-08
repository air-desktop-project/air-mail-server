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

# ── LES DEUX FICHIERS DE VERROU, AVANT TOUT LE RESTE ────────────────────────
#
# `--locked` REFUSE de mettre un verrou à jour, et c'est ce qu'on veut : un
# paquet doit se construire des versions exactes qu'on a éprouvées. Mais la
# conséquence se découvre mal : un bump de version dans `Cargo.toml` laisse les
# DEUX verrous sur l'ancienne, et rien ne le dit tant qu'un `cargo` sans
# `--locked` ne les a pas régénérés par hasard.
#
# C'est arrivé deux fois. Le `Cargo.lock` du workspace est resté à 0.2.51 après
# le bump en 0.2.52 — découvert par hasard en lisant un `git status`. Et
# `fuzz/Cargo.lock`, lui, a tenu la CI ROUGE du 2026-10-06 au 2026-10-08 :
# `cargo check --locked` y échouait par « cannot update the lock file », et
# comme `check-compile` s'arrête là, aucun contrôle suivant ne tournait. En
# local rien ne se voyait, les verrous étant régénérés par les constructions.
#
# Le contrôle tient en une comparaison, et il vient EN PREMIER parce qu'il
# explique en une ligne ce que `cargo` dit en six.
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
verrous_faux=0
for verrou in Cargo.lock fuzz/Cargo.lock; do
    [ -f "$verrou" ] || { echo "ÉCHEC : \`$verrou\` est absent." >&2; verrous_faux=1; continue; }
    # `ams-config` est dans les deux verrous, et porte la version du workspace.
    pose=$(grep -A1 '^name = "ams-config"$' "$verrou" | sed -n 's/^version = "\(.*\)"/\1/p' | head -1)
    if [ "$pose" != "$version" ]; then
        echo "ÉCHEC : \`$verrou\` dit \`$pose\`, \`Cargo.toml\` dit \`$version\`." >&2
        echo "        \`--locked\` refusera de le corriger. Régénérez-le :" >&2
        case "$verrou" in
            fuzz/*) echo "            (cd fuzz && cargo check --bins)" >&2 ;;
            *)      echo "            cargo check --workspace" >&2 ;;
        esac
        verrous_faux=1
    fi
done
if [ "$verrous_faux" -ne 0 ]; then
    echo >&2
    echo "ÉCHEC : un verrou ne porte pas la version du workspace." >&2
    exit 1
fi
echo "verrous   : Cargo.lock et fuzz/Cargo.lock sont en $version"
echo

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
