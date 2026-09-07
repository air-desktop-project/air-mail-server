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

# **L'ORDRE EST CELUI DES OCTETS, ET NON CELUI DU DICTIONNAIRE.**
#
# Les drapeaux Maildir se rangent dans l'ordre ASCII. Or `[[ a < b ]]` emploie la
# COLLATION DE LA LOCALE : sous `fr_FR.UTF-8`, « a » précède « B », ce qui est
# l'ordre du dictionnaire et non celui des octets (B vaut 66, a vaut 97). Ce
# script accepterait alors des noms que le serveur refuse, et refuserait des noms
# qu'il accepte — sur la machine de l'exploitant, jamais sur la nôtre.
export LC_ALL=C

racine=${1:?usage : verifier.sh <racine-maildir> [ancienne-racine]}
ancienne=${2-}

# **CE QUE LA GRAMMAIRE ACCEPTE**, et rien de plus.
#
# Un nom Maildir est `<unique>[:2,<drapeaux>]`. Les drapeaux sont des lettres de
# `PRSTDF` et les mots-clefs de ce serveur, DANS L'ORDRE ASCII — c'est ce point
# qui a fait disparaître un message en silence pendant l'étude.
# **AUCUN SOUS-PROCESSUS PAR FICHIER**, et c'est une correction, pas une
# élégance.
#
# La première écriture appelait `basename` une fois par fichier, et
# `grep -o . | sort | tr` trois fois de plus pour vérifier que les drapeaux
# étaient triés. Quatre processus par message. Mesuré le 2026-09-07 :
#
#     50 000 messages → 229 secondes
#
# Or ce script tourne PENDANT LA COUPURE (phase 1, étape 4). Quatre minutes par
# tranche de cinquante mille messages, c'est quarante minutes d'indisponibilité
# sur une boîte d'un demi-million — pour un contrôle que la copie elle-même fait
# en trois secondes.
#
# Tout se fait donc par expansion de paramètres, et le tri se vérifie en un seul
# parcours : une chaîne est triée si chaque caractère est inférieur ou égal au
# suivant. On n'a pas besoin de la trier pour le savoir.
lisible() {
    local nom=$1 info
    case "$nom" in
        */*) return 1 ;;
        *:*) info=${nom#*:} ;;
        *) return 0 ;;                       # sans information : `new/`
    esac
    case "$info" in 2,*) ;; *) return 1 ;; esac
    local lettres=${info#2,} i precedent courant
    precedent=""
    for ((i = 0; i < ${#lettres}; i++)); do
        courant=${lettres:i:1}
        if [ -n "$precedent" ] && [[ "$courant" < "$precedent" ]]; then
            return 1
        fi
        precedent=$courant
    done
    return 0
}

compter() {
    local ou=$1 total=0 douteux=0 fichier nom
    while IFS= read -r -d '' fichier; do
        total=$((total + 1))
        nom=${fichier##*/}
        lisible "$nom" || {
            douteux=$((douteux + 1))
            printf '      ILLISIBLE : %s\n' "${fichier#"$ou"}" >&2
        }
    # **LA BARRE FINALE N'EST PAS UNE COQUETTERIE.** `bascule.md` donne de
    # l'ancien magasin une VUE faite de liens symboliques, et `find` sur un lien
    # SANS barre finale ne le suit pas : il rend le lien lui-même, qui n'est pas
    # un `-type f`, donc RIEN.
    #
    # L'audit annonçait alors « TOTAL ancien : 0 message » et refusait la
    # bascule, en donnant à croire que la copie avait tout perdu. Il refusait
    # dans le bon sens — mais pour une raison fausse, et le jour J on aurait
    # cherché la panne du mauvais côté.
    done < <(find "$ou/" \( -path '*/cur/*' -o -path '*/new/*' \) -type f -print0 2>/dev/null)
    printf '%s %s' "$total" "$douteux"
}

# ── LE BANC ─────────────────────────────────────────────────────────────────
#
# Ce script décide SI L'ON BASCULE. Un « OK » qu'il ne devrait pas donner fait
# basculer sur une copie incomplète, Postfix arrêté ; un « ÉCHEC » qu'il ne
# devrait pas donner fait renoncer pour rien.
#
# Il a déjà eu les deux défauts : il annonçait « OK : aucun écart » après avoir
# signalé un nom illisible, et il ne voyait pas un dossier VIDE perdu.
#
#     bash verifier.sh --essais
#
essais() {
    local banc; banc=$(mktemp -d) || return 1
    trap 'rm -rf "$banc"' RETURN
    local fautes=0

    monter() { # <racine>
        mkdir -p "$1/alice/cur" "$1/alice/new" "$1/alice/.Sent/cur"
        local i
        for i in 1 2 3; do
            printf 'x' > "$1/alice/cur/172500000$i.M1.banc,S=42:2,S"
        done
        printf 'x' > "$1/alice/.Sent/cur/1725000009.M9.banc,S=42:2,S"
    }

    # `attendu <code> <étiquette> [arguments...]`
    attendu() {
        local code=$1 quoi=$2; shift 2
        bash "$0" "$@" > "$banc/sortie.txt" 2>&1
        local vu=$?
        if [ "$vu" -ne "$code" ]; then
            echo "FAUTE : $quoi — code $vu attendu $code" >&2
            sed 's/^/       /' "$banc/sortie.txt" >&2
            fautes=$((fautes + 1))
        fi
    }

    # ── A. DEUX MAGASINS IDENTIQUES ─────────────────────────────────────────
    rm -rf "$banc/neuf" "$banc/ancien"
    monter "$banc/neuf"; monter "$banc/ancien"
    attendu 0 "deux magasins identiques" "$banc/neuf" "$banc/ancien"
    # Et l'audit d'un seul magasin, sans comparaison.
    attendu 0 "un seul magasin, sain" "$banc/neuf"

    # ── B. UN DOSSIER VIDE PERDU ────────────────────────────────────────────
    #
    # LE DÉFAUT QUE CE BANC EXISTE POUR TENIR. Le total du compte ne bouge pas —
    # le dossier est vide — et l'ancienne boucle ne parcourait que le neuf.
    mkdir -p "$banc/ancien/alice/.Archives/cur" "$banc/ancien/alice/.Archives/new"
    attendu 1 "un dossier VIDE perdu" "$banc/neuf" "$banc/ancien"

    # ── C. UN DOSSIER NON VIDE PERDU ────────────────────────────────────────
    printf 'x' > "$banc/ancien/alice/.Archives/cur/1725000011.M1.banc,S=42:2,S"
    attendu 1 "un dossier NON VIDE perdu" "$banc/neuf" "$banc/ancien"

    # ── D. UN MESSAGE MANQUANT DANS UN DOSSIER PARTAGÉ ──────────────────────
    rm -rf "$banc/neuf" "$banc/ancien"
    monter "$banc/neuf"; monter "$banc/ancien"
    printf 'x' > "$banc/ancien/alice/.Sent/cur/1725000012.M1.banc,S=42:2,S"
    attendu 1 "un message manquant dans .Sent" "$banc/neuf" "$banc/ancien"

    # ── E. UN NOM ILLISIBLE ─────────────────────────────────────────────────
    #
    # L'AUTRE DÉFAUT D'ORIGINE : « OK : aucun écart » imprimé sous un
    # avertissement. Un message dont le nom sort de la grammaire n'est ni servi,
    # ni adopté, ni effacé — il reste là, invisible.
    rm -rf "$banc/neuf" "$banc/ancien"
    monter "$banc/neuf"; monter "$banc/ancien"
    # Drapeaux dans le désordre : Maildir les veut en ordre ASCII croissant.
    printf 'x' > "$banc/neuf/alice/cur/1725000013.M1.banc,S=42:2,SR"
    printf 'x' > "$banc/ancien/alice/cur/1725000013.M1.banc,S=42:2,RS"
    attendu 1 "un nom illisible dans le neuf" "$banc/neuf" "$banc/ancien"

    if [ "$fautes" -eq 0 ]; then
        echo "OK : le sain passe, et les cinq écarts font tous ÉCHOUER."
    fi
    return "$fautes"
}

if [ "${1-}" = "--essais" ]; then
    essais
    exit $?
fi

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

    # ── LE DÉTAIL PAR DOSSIER IMAP, SUR L'UNION DES DEUX MAGASINS ───────
    #
    # **L'UNION, ET NON LES DOSSIERS DU NEUF.** Une version antérieure ne
    # parcourait que le nouveau magasin : un dossier VIDE présent dans l'ancien
    # et absent du neuf ne se voyait donc nulle part. Le total du compte ne
    # bougeait pas — il est vide —, et le script annonçait « OK : aucun écart ».
    #
    # Aucun courrier n'est perdu dans ce cas. Mais l'utilisateur perd un dossier
    # qu'il avait créé, et l'outil dont le métier est de RENDRE CONFIANT lui
    # avait dit que tout allait bien. Un dossier non vide, lui, était déjà
    # attrapé par le total du compte.
    # **LA CORRESPONDANCE ENTRE LES DEUX ÉCRITURES D'UN MÊME DOSSIER.**
    #
    # Traduire la LISTE ne suffit pas : il faut ensuite RETROUVER le dossier
    # ancien, qui est toujours sur le disque sous son nom encodé. Sans cette
    # table, la comparaison est simplement sautée — et un dossier dont le compte
    # aurait changé passerait sans un mot.
    declare -A ancien_de=()
    if [ -n "$ancienne" ] && [ -d "$ancienne/$compte" ]; then
        while IFS= read -r reel; do
            [ -n "$reel" ] || continue
            traduit=$(printf '%s\n' "$reel" \
                | python3 "$(dirname "$0")/renommer-dossiers.py" --traduire)
            ancien_de["$traduit"]=$reel
        done < <(
            for sous in "$ancienne/$compte"/.*/; do
                [ -d "$sous" ] && basename "$sous"
            done
        )
    fi

    dossiers=$(
        {
            for sous in "$boite".*/; do
                [ -d "$sous" ] && basename "$sous"
            done
            if [ -n "$ancienne" ] && [ -d "$ancienne/$compte" ]; then
                # **LES NOMS DE L'ANCIEN SE TRADUISENT AVANT D'ÊTRE COMPARÉS.**
                #
                # Dovecot écrit `.&AMk-t&AOk--2025`, air-mail-server `.Été-2025`
                # — c'est le MÊME dossier, que `renommer-dossiers.py` a traduit
                # en 0.4bis. Sans cette traduction, l'audit annonce « CE DOSSIER
                # DISPARAÎT » d'un dossier qui est là, et refuse une bascule
                # parfaitement saine.
                #
                # On passe par le décodeur du renommeur, et non par une copie :
                # deux décodeurs finiraient par ne plus dire la même chose.
                for sous in "$ancienne/$compte"/.*/; do
                    [ -d "$sous" ] && basename "$sous"
                done | python3 "$(dirname "$0")/renommer-dossiers.py" --traduire
            fi
        } 2>/dev/null | grep -vxE '\.|\.\.' | sort -u
    )
    while IFS= read -r nom; do
        [ -n "$nom" ] || continue
        sous="$boite$nom/"
        nom=${nom#.}
        if [ -d "$sous" ]; then
            read -r sn sd <<< "$(compter "$sous")"
        else
            # **LE DOSSIER MANQUE DU NEUF**, et c'est ce qu'on cherchait à voir.
            sn=-1
            sd=0
        fi
        illisibles=$((illisibles + sd))
        if [ "$sn" -lt 0 ]; then
            printf '      %-20s %6s' "$nom" "ABSENT"
            ecart=$((ecart + 1))
        else
            printf '      %-20s %6d' "$nom" "$sn"
        fi
        [ "$sd" -gt 0 ] && printf ' — %d ILLISIBLE(S)' "$sd"
        reel_ancien=${ancien_de[".$nom"]-}
        if [ -n "$ancienne" ] && [ -n "$reel_ancien" ]; then
            read -r sa _ <<< "$(compter "$ancienne/$compte/$reel_ancien")"
            if [ "$sn" -lt 0 ]; then
                printf '   ≠ ANCIEN : %d — CE DOSSIER DISPARAÎT' "$sa"
            elif [ "$sn" -ne "$sa" ]; then
                printf '   ≠ ANCIEN : %d' "$sa"
                ecart=$((ecart + 1))
            fi
        fi
        printf '\n'
    done <<< "$dossiers"
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
