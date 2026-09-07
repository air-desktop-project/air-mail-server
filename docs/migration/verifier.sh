#!/usr/bin/env bash
#
# verifier.sh — RIEN N'A ÉTÉ PERDU ?
#
# Compare, dossier par dossier et compte par compte, ce que le DISQUE porte et
# ce qu'air-mail-server SERT. Un message dont le nom de fichier ne se lit pas
# n'est ni servi, ni adopté, ni effacé : il reste là, invisible. Ce script est
# le seul endroit d'où on peut le voir.
#
# Il ne modifie rien.
#
# USAGE
#     bash verifier.sh <racine-maildir> [racine-de-comparaison]
#
# Avec un second argument — l'ancien magasin Dovecot — il compare les DEUX,
# compte par compte : c'est ce qu'on veut le jour de la bascule.

set -uo pipefail

racine=${1:?usage : verifier.sh <racine-maildir> [ancienne-racine]}
ancienne=${2-}

# **CE QUE LA GRAMMAIRE ACCEPTE**, et rien de plus.
#
# Un nom Maildir est `<unique>[:2,<drapeaux>]`. Les drapeaux sont des lettres de
# `PRSTDF` et les mots-clefs de ce serveur, DANS L'ORDRE ASCII — c'est ce point
# qui a fait disparaître un message en silence pendant l'étude.
lisible() {
    local nom=$1 info
    case "$nom" in
        */*) return 1 ;;
        *:*) info=${nom#*:} ;;
        *) return 0 ;;                       # sans information : `new/`
    esac
    case "$info" in 2,*) ;; *) return 1 ;; esac
    local lettres=${info#2,}
    # Trié ? On compare la chaîne à sa version triée, caractère par caractère.
    local trie
    trie=$(printf '%s' "$lettres" | grep -o . | LC_ALL=C sort | tr -d '\n')
    [ "$lettres" = "$trie" ]
}

compter() {
    local ou=$1 total=0 douteux=0
    while IFS= read -r -d '' fichier; do
        total=$((total + 1))
        lisible "$(basename "$fichier")" || {
            douteux=$((douteux + 1))
            printf '      ILLISIBLE : %s\n' "${fichier#"$ou"}" >&2
        }
    done < <(find "$ou" \( -path '*/cur/*' -o -path '*/new/*' \) -type f -print0 2>/dev/null)
    printf '%s %s' "$total" "$douteux"
}

echo "verifier — $racine"
[ -n "$ancienne" ] && echo "           comparé à $ancienne"
echo

total_neuf=0
total_ancien=0
ecart=0
# **UN FICHIER ILLISIBLE EST UN ÉCHEC, PAS UNE REMARQUE.**
#
# La première écriture de ce script imprimait « OK : aucun écart » après avoir
# signalé un nom illisible. C'est le défaut que `check-installation.sh` portait
# le matin même : un « OK » inconditionnel sous un message d'alerte. Ici il
# coûterait plus cher — on basculerait en croyant n'avoir rien perdu.
illisibles=0

for boite in "$racine"/*/; do
    [ -d "$boite" ] || continue
    compte=$(basename "$boite")
    read -r n d <<< "$(compter "$boite")"
    total_neuf=$((total_neuf + n))
    illisibles=$((illisibles + d))
    # **LE TOTAL DU COMPTE INCLUT LES SOUS-DOSSIERS**, et le dire évite de les
    # additionner. La première écriture affichait « alice 12 » puis « Sent 3,
    # Trash 1 » : on comptait seize. Un outil dont le métier est de rendre
    # confiant avant une bascule ne peut pas laisser cette ambiguïté.
    ligne=$(printf '  %-24s %6d au total' "$compte" "$n")
    [ "$d" -gt 0 ] && ligne="$ligne — $d ILLISIBLE(S)"

    if [ -n "$ancienne" ] && [ -d "$ancienne/$compte" ]; then
        read -r a _ <<< "$(compter "$ancienne/$compte")"
        total_ancien=$((total_ancien + a))
        if [ "$n" -ne "$a" ]; then
            ligne="$ligne   ≠ ANCIEN : $a"
            ecart=$((ecart + 1))
        else
            ligne="$ligne   = ancien"
        fi
    fi
    echo "$ligne"

    # L'INBOX seule : ce que le compte porte hors de ses sous-dossiers.
    inbox=0
    for d in cur new; do
        [ -d "$boite$d" ] || continue
        inbox=$((inbox + $(find "$boite$d" -maxdepth 1 -type f 2>/dev/null | wc -l)))
    done
    printf '      %-20s %6d\n' "INBOX" "$inbox"

    # Le détail par dossier IMAP, qui est là où un `.Sent` oublié se voit.
    for sous in "$boite".*/; do
        [ -d "$sous" ] || continue
        nom=$(basename "$sous"); nom=${nom#.}
        read -r sn sd <<< "$(compter "$sous")"
        illisibles=$((illisibles + sd))
        printf '      %-20s %6d' "$nom" "$sn"
        [ "$sd" -gt 0 ] && printf ' — %d ILLISIBLE(S)' "$sd"
        if [ -n "$ancienne" ] && [ -d "$ancienne/$compte/.$nom" ]; then
            read -r sa _ <<< "$(compter "$ancienne/$compte/.$nom")"
            [ "$sn" -ne "$sa" ] && { printf '   ≠ ANCIEN : %d' "$sa"; ecart=$((ecart + 1)); }
        fi
        printf '\n'
    done
done

echo
printf 'TOTAL nouveau : %d message(s)\n' "$total_neuf"
[ -n "$ancienne" ] && printf 'TOTAL ancien  : %d message(s)\n' "$total_ancien"

printf 'noms illisibles : %d\n' "$illisibles"

if [ "$ecart" -ne 0 ] || [ "$illisibles" -ne 0 ]; then
    echo
    [ "$ecart" -ne 0 ] && echo "  $ecart écart(s) de décompte."
    [ "$illisibles" -ne 0 ] && echo "  $illisibles nom(s) que le serveur ne servira pas."
    echo "ÉCHEC : NE BASCULEZ PAS."
    exit 1
fi
echo
echo "OK : aucun écart, aucun nom illisible."
