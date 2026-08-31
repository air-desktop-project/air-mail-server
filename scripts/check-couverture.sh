#!/usr/bin/env bash
#
# check-couverture — les crates SANS ENTRÉE-SORTIE sont-elles couvertes à 100 % ?
#
# # Le périmètre, et pourquoi il s'arrête là
#
# C2 exige 100 % sur les grammaires (étage 1) et les machines à états (étage 2) —
# ce qui ne fait aucune entrée-sortie. Les crates qui lisent, écrivent et attendent
# (`ams-loop-*`, `ams-store`, les deux binaires) en sont HORS.
#
# Ce n'est pas de l'indulgence. Atteindre 100 % sur une boucle d'entrées-sorties
# exigerait de simuler les pannes du noyau — un `EINTR` ici, un `ENOSPC` là — et
# ce qu'on mesurerait alors serait la fidélité de la simulation, pas la justesse
# du code. C'est précisément pour que ce périmètre reste petit que la logique du
# serveur vit dans des machines à états (C1).
#
# # Ce que ce gate refuse de faire
#
# Rendre un rapport vert qui n'a rien mesuré. Le nombre de RÉGIONS examinées est
# affiché ; à zéro région, le script le dit en toutes lettres au lieu d'annoncer
# « 100 % ». Un pourcentage sur un ensemble vide n'est pas une mesure.
#
# Usage : scripts/check-couverture.sh [--seuil N]   (défaut : 100)

set -euo pipefail

# LOCALE FORCÉE, et ce n'est pas de la coquetterie. En locale française, `printf`
# refuse « 88.88 » — le séparateur décimal y est la virgule — et le script
# s'interrompait au lieu d'appliquer son seuil. Le bug était INVISIBLE en CI, où
# le runner tourne déjà en locale C : il n'aurait mordu qu'en local, c'est-à-dire
# à l'endroit où l'on croit avoir vérifié avant de pousser.
export LC_ALL=C

seuil=100
if [ "${1-}" = "--seuil" ] && [ -n "${2-}" ]; then
    seuil="$2"
fi

# Le périmètre, énuméré à la main et non déduit : une crate qui migrerait d'étage
# doit obliger quelqu'un à modifier CE fichier, et donc à y penser.
CRATES_SANS_IO=(
    ams-mime
    ams-proto-smtp
    ams-sasl
    ams-auth
    ams-proto-pop3
    ams-proto-imap
    ams-field-codec
    ams-proto-http
    ams-proto-h2
    ams-proto-quic
    ams-proto-h3
    ams-quic-crypto
    ams-quic
    ams-session
    ams-guard
    ams-tls
    ams-dkim
    ams-spf
    ams-dns
    ams-dmarc
    ams-config
    ams-index
    ams-api
)

# ── LA SEULE DÉROGATION, ET ELLE EST NOMMÉE ─────────────────────────────────
#
# Le code dérivé des schémas Cap'n Proto (`ams_*_capnp.rs`) est GÉNÉRÉ : il
# porte un accesseur par champ et par sens, dont la plupart ne seront jamais
# appelés. Exiger 100 % dessus reviendrait à écrire des tests qui n'éprouvent
# rien de nos décisions — et un test qui n'éprouve rien affaiblit la mesure au
# lieu de la renforcer.
#
# La dérogation est ÉTROITE : elle nomme les fichiers GÉNÉRÉS, pas une crate. Le
# code écrit à la main d'`ams-config` reste soumis au 100 %. Le motif se termine
# par `_capnp.rs` : un fichier écrit à la main ne portera pas ce suffixe, et un
# schéma de plus n'obligera pas à revenir ici.
#
# Elle est aussi VISIBLE : ce script l'annonce à chaque exécution. Une dérogation
# qu'on ne voit plus est une dérogation qui s'élargit.
IGNORE='/ams_[a-z]+_capnp\.rs$'

args=(--ignore-filename-regex "$IGNORE")
for crate in "${CRATES_SANS_IO[@]}"; do
    args+=(--package "$crate")
done

# ── La mesure, et le cas où il n'y a rien à mesurer ──────────────────────────
#
# Quand aucune crate du périmètre ne contient la moindre fonction, `llvm-cov` ne
# rend pas « 0 région » : il ÉCHOUE, avec « no coverage data found ». C'est le cas
# d'un dépôt dont les crates sont encore des emplacements réservés — un état
# légitime, qu'on ne veut ni maquiller en succès, ni transformer en panne de CI.
#
# On distingue donc les deux échecs : celui-là est un rapport VIDE, et tout autre
# est une panne du gate, qui doit rester une panne.
journal=$(mktemp)
trap 'rm -f "$journal"' EXIT

if ! rapport=$(cargo llvm-cov --json --summary-only --locked "${args[@]}" 2>"$journal"); then
    if grep -q "no coverage data found" "$journal"; then
        echo "périmètre : ${#CRATES_SANS_IO[@]} crates sans entrée-sortie"
        echo
        echo "0 région mesurée — les crates du périmètre ne contiennent AUCUN code."
        echo "Ce gate n'a donc RIEN vérifié ; il ne prétend pas le contraire."
        exit 0
    fi
    echo "ÉCHEC : la mesure de couverture n'a pas abouti." >&2
    cat "$journal" >&2
    exit 1
fi

lecture=$(printf '%s' "$rapport" | python3 "$(dirname "$0")/lire-couverture.py")

echo "périmètre : ${#CRATES_SANS_IO[@]} crates sans entrée-sortie"
echo "seuil     : ${seuil} %"
echo "exclu     : le code GÉNÉRÉ des schémas Cap'n Proto (ams_*_capnp.rs)"
echo

regions_total=0
manquants=0

while read -r cle total couvert pourcent; do
    printf '  %-10s %6s / %-6s  %7s %%\n' "$cle" "$couvert" "$total" "$pourcent"
    if [ "$cle" = "regions" ]; then
        regions_total="$total"
    fi
    # LE SEUIL PORTE SUR LES RÉGIONS ET LES LIGNES, PAS SUR LES BRANCHES.
    #
    # Sur Rust stable, `llvm-cov` n'instrumente pas les branches : le rapport
    # affiche `0 / 0`, et un seuil posé dessus serait vert sans rien mesurer.
    # Les régions font le travail attendu — chaque bras d'un conditionnel en est
    # une — et c'est vérifié : une sonde à deux bras dont un seul était exercé a
    # fait tomber ce gate à 8/9 régions, alors que les lignes affichaient encore
    # 100 %.
    case "$cle" in
        regions | lines)
            # ON COMPARE DES COMPTES, PAS UN POURCENTAGE ARRONDI. Le
            # pourcentage affiché tient sur deux décimales : 23 580 régions sur
            # 23 581 s'y écrivent « 100,00 % », et le seuil de 100 % laissait
            # donc passer une région non couverte. Arrivé une fois, en écrivant
            # `STORE` — le gate a dit OK sur 23580/23581.
            if [ "$total" -gt 0 ] \
                && ! awk "BEGIN { exit !(100 * $couvert / $total + 1e-9 >= $seuil) }"; then
                manquants=$((manquants + 1))
            fi
            ;;
    esac
done <<< "$lecture"

echo

if [ "$regions_total" -eq 0 ]; then
    # UN RAPPORT À 100 % SUR ZÉRO RÉGION N'EST PAS UN SUCCÈS. On le dit.
    echo "0 région mesurée — les crates du périmètre sont VIDES."
    echo "Ce gate n'a donc RIEN vérifié ; il ne prétend pas le contraire."
    exit 0
fi

if [ "$manquants" -gt 0 ]; then
    echo "ÉCHEC : $manquants mesure(s) sous le seuil de ${seuil} % (C2)."
    echo "Détail par fichier : cargo llvm-cov --summary-only ${args[*]}"
    exit 1
fi

echo "OK : le périmètre sans entrée-sortie est couvert à ${seuil} %."
