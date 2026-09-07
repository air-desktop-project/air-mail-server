#!/usr/bin/env bash
#
# rapatrier.sh — RAMENER le courrier arrivé depuis la bascule, sans doublon.
#
# # LE DÉFAUT QUE CE SCRIPT EXISTE POUR NE PAS COMMETTRE
#
# `bascule.md` prescrivait, pour le retour en arrière :
#
#     rsync -aH --ignore-existing /var/vmail-ams/ /var/vmail/
#
# En répétant la manœuvre sur un banc, le compte est tombé faux : dix-huit
# messages, plus deux arrivées, moins un effacement, devaient faire vingt. Il y
# en avait VINGT ET UN.
#
# La cause : `--ignore-existing` compare des CHEMINS. Or lire un message change
# son nom ET son dossier — `new/1725…` devient `cur/1725…:2,S`. Le fichier lu
# n'existe donc pas à ce chemin-là dans l'ancien magasin, et il est copié : le
# message s'y trouve alors DEUX FOIS, une fois non lu et une fois lu.
#
#     ancien/alice/cur/1725000007.M7P100.mail.narro.ch,S=73,W=75:2,S
#     ancien/alice/new/1725000007.M7P100.mail.narro.ch,S=73,W=75
#
# Ce n'est pas un drapeau perdu, c'est un DOUBLON que l'utilisateur voit — et il
# le voit pendant un retour en arrière, c'est-à-dire au pire moment.
#
# # CE QUE CE SCRIPT COMPARE À LA PLACE
#
# La PARTIE UNIQUE du nom Maildir : ce qui précède le premier `,` ou le premier
# `:`. Elle ne change ni quand on lit un message, ni quand on l'étiquette, ni
# quand un serveur lui donne un UID. C'est la seule chose qui identifie le
# message, et c'est pour cela que Maildir la réserve.
#
# La comparaison se fait BOÎTE PAR BOÎTE — compte et dossier — et non
# globalement : le même message peut légitimement vivre dans `INBOX` et dans
# `Sent`.
#
# # CE QU'IL NE FAIT PAS, ET QUI SE DIT
#
#   - il ne ressuscite pas ce qu'un utilisateur a EFFACÉ pendant la fenêtre ;
#   - il ne rapporte pas les drapeaux posés pendant la fenêtre sur des messages
#     que l'ancien magasin porte déjà : ceux-là gardent les leurs. L'inverse
#     écraserait des drapeaux justes par ceux d'une fenêtre de deux heures.
#
# USAGE
#     bash rapatrier.sh <source-neuve> <destination-ancienne> [--pour-de-vrai]
#
# SANS `--pour-de-vrai`, il n'écrit RIEN et se contente de dire ce qu'il ferait.

set -uo pipefail

# ── LE BANC, ET POURQUOI IL EST DANS CE SCRIPT ──────────────────────────────
#
# Ce script est le RETOUR EN ARRIÈRE : on le lance quand tout le reste a déjà
# échoué, sous pression, Postfix arrêté et les utilisateurs qui attendent. C'est
# le pire moment pour découvrir qu'il se trompe.
#
# Son défaut d'origine — `rsync --ignore-existing`, qui dupliquait tout message
# lu pendant la fenêtre — a été trouvé sur un banc MONTÉ À LA MAIN. Un banc
# qu'on ne peut pas rejouer n'est pas une garde : c'est un souvenir.
#
#     bash rapatrier.sh --essais
#
essais() {
    local banc; banc=$(mktemp -d) || return 1
    trap 'rm -rf "$banc"' RETURN
    local ancien="$banc/ancien" neuf="$banc/neuf"
    local fautes=0

    # Un message Maildir : `<unique>,S=<taille>` puis, s'il est lu, `:2,S`.
    poser() { # <racine> <compte/dossier> <cur|new> <unique> [drapeaux]
        local chemin="$1/$2/$3"
        mkdir -p "$chemin"
        printf 'message %s\n' "$4" > "$chemin/$4,S=42${5-}"
    }

    for racine in "$ancien" "$neuf"; do
        # ── DIX-HUIT MESSAGES COMMUNS ───────────────────────────────────────
        #
        # Dans l'ANCIEN ils sont tous dans `new`, non lus. Dans le NEUF, les six
        # premiers ont été lus pendant la fenêtre : Maildir les a donc déplacés
        # dans `cur` ET renommés. C'est très exactement ce que
        # `--ignore-existing` ne voyait pas.
        local i
        for i in $(seq 1 18); do
            if [ "$racine" = "$neuf" ] && [ "$i" -le 6 ]; then
                poser "$racine" alice cur "17250000$i.M1.banc" ":2,S"
            else
                poser "$racine" alice new "17250000$i.M1.banc"
            fi
        done
        # ── LE MÊME MESSAGE DANS DEUX BOÎTES, LÉGITIMEMENT ──────────────────
        #
        # Un message envoyé à soi-même vit dans `INBOX` et dans `Sent`. La
        # comparaison se fait BOÎTE PAR BOÎTE : une comparaison globale le
        # croirait déjà rapatrié et le perdrait.
        poser "$racine" alice/.Sent cur "1725000099.M9.banc" ":2,S"
    done

    # ── DEUX ARRIVÉES, QUE LE NEUF SEUL PORTE ───────────────────────────────
    poser "$neuf" alice new "1725000101.M2.banc"
    poser "$neuf" alice/.Sent new "1725000102.M2.banc"

    # ── UN EFFACEMENT PENDANT LA FENÊTRE ────────────────────────────────────
    #
    # Le message 18 a été effacé dans le neuf. Le script NE LE RESSUSCITE PAS —
    # il ne fait que copier du neuf vers l'ancien — mais il ne doit pas non plus
    # l'effacer de l'ancien.
    rm -f "$neuf/alice/new/172500001"8",S=42"

    local avant apres
    avant=$(find "$ancien" -type f | wc -l)

    # ── À BLANC : RIEN NE DOIT BOUGER ───────────────────────────────────────
    bash "$0" "$neuf" "$ancien" > "$banc/blanc.txt" 2>&1
    apres=$(find "$ancien" -type f | wc -l)
    if [ "$avant" -ne "$apres" ]; then
        echo "FAUTE : le passage à blanc a écrit ($avant → $apres)" >&2
        fautes=$((fautes + 1))
    fi
    if ! grep -q "à rapatrier      : 2" "$banc/blanc.txt"; then
        echo "FAUTE : le passage à blanc devait annoncer 2 messages :" >&2
        sed 's/^/       /' "$banc/blanc.txt" >&2
        fautes=$((fautes + 1))
    fi

    # ── POUR DE VRAI ────────────────────────────────────────────────────────
    bash "$0" "$neuf" "$ancien" --pour-de-vrai > "$banc/vrai.txt" 2>&1
    apres=$(find "$ancien" -type f | wc -l)
    if [ "$apres" -ne $((avant + 2)) ]; then
        echo "FAUTE : $((avant + 2)) fichiers attendus, $apres trouvés" >&2
        fautes=$((fautes + 1))
    fi

    # ── ET AUCUN DOUBLON, C'EST LE DÉFAUT D'ORIGINE ─────────────────────────
    #
    # Deux fichiers d'une même boîte qui partagent leur partie unique sont le
    # même message vu deux fois par l'utilisateur — et il le voit pendant un
    # retour en arrière, c'est-à-dire au pire moment.
    local doublons
    doublons=$(find "$ancien" -type f -printf '%h %f\n' \
        | sed -E 's#/(cur|new) # #; s#(,|:)[^ ]*$##' | sort | uniq -d)
    if [ -n "$doublons" ]; then
        echo "FAUTE : doublons dans l'ancien magasin :" >&2
        printf '%s\n' "$doublons" | sed 's/^/       /' >&2
        fautes=$((fautes + 1))
    fi

    # ── L'EFFACÉ N'EST PAS RESSUSCITÉ, ET N'A PAS DISPARU ───────────────────
    if [ ! -e "$ancien/alice/new/1725000018.M1.banc,S=42" ]; then
        echo "FAUTE : le message effacé dans le neuf a disparu de l'ancien" >&2
        fautes=$((fautes + 1))
    fi

    # ── LA BOÎTE `Sent` A REÇU LA SIENNE, ET ELLE SEULE ─────────────────────
    if [ ! -e "$ancien/alice/.Sent/new/1725000102.M2.banc,S=42" ]; then
        echo "FAUTE : l'arrivée de .Sent n'a pas été rapatriée" >&2
        fautes=$((fautes + 1))
    fi

    # ── ET RELANCER NE DOIT RIEN AJOUTER ────────────────────────────────────
    #
    # Le jour J, on relance ce qui a l'air d'avoir échoué. Deux passages doivent
    # donner le même magasin qu'un seul.
    bash "$0" "$neuf" "$ancien" --pour-de-vrai > /dev/null 2>&1
    if [ "$(find "$ancien" -type f | wc -l)" -ne $((avant + 2)) ]; then
        echo "FAUTE : un second passage a ajouté des fichiers" >&2
        fautes=$((fautes + 1))
    fi

    if [ "$fautes" -eq 0 ]; then
        echo "OK : 2 rapatriés sur 21, aucun doublon, rien de perdu, et"
        echo "     un second passage n'ajoute rien."
    fi
    return "$fautes"
}

if [ "${1-}" = "--essais" ]; then
    essais
    exit $?
fi

source=${1:?usage : rapatrier.sh <source> <destination> [--pour-de-vrai]}
destination=${2:?usage : rapatrier.sh <source> <destination> [--pour-de-vrai]}
pour_de_vrai=${3-}

[ -d "$source" ] || { echo "source introuvable : $source" >&2; exit 1; }
[ -d "$destination" ] || { echo "destination introuvable : $destination" >&2; exit 1; }

# La partie unique : jusqu'au premier `,` ou `:`.
unique() {
    local nom=$1
    nom=${nom%%:*}
    nom=${nom%%,*}
    printf '%s' "$nom"
}

copies=0
sautes=0
boites=0

# ── LES DEUX MAGASINS N'ÉCRIVENT PAS LE MÊME DOSSIER PAREIL ─────────────────
#
# Après `renommer-dossiers.py`, le neuf porte `.Été-2025` là où l'ancien garde
# `.&AMk-t&AOk--2025`. C'est le MÊME dossier.
#
# Sans cette table, le rapatriement ne trouve pas la destination, CRÉE un
# `.Été-2025` neuf dans l'ancien magasin, et y recopie des messages qui s'y
# trouvent déjà sous l'autre nom. L'utilisateur voit alors deux dossiers et son
# courrier en double — pendant un RETOUR EN ARRIÈRE, c'est-à-dire au moment où
# il a le moins besoin d'une surprise.
#
# **ON DÉCODE LES DEUX CÔTÉS, ON N'ENCODE PAS.** L'UTF-7 modifié n'a pas de
# forme canonique : deux encodages différents peuvent désigner le même nom, et
# ré-encoder ce que Dovecot a écrit ne redonnerait pas forcément ses octets.
declare -A reel_de=()
decodeur="$(dirname "$0")/renommer-dossiers.py"
while IFS= read -r -d '' cur_destination; do
    boite=$(dirname "$cur_destination")
    chemin=${boite#"$destination"}
    chemin=${chemin#/}
    # `find` sur un lien résolu rend le chemin RÉEL : on remet celui de la vue,
    # qui est le seul que l'appelant connaisse.
    chemin=${chemin#"$(basename "$destination")/"}
    [ -n "$chemin" ] || continue
    decode=$(printf '%s\n' "$chemin" | python3 "$decodeur" --traduire)
    reel_de["$decode"]=$chemin
done < <(
    # **ON DESCEND COMPTE PAR COMPTE, AVEC LA BARRE FINALE.** `bascule.md` donne
    # de l'ancien magasin une VUE faite de liens symboliques, et `find` ne suit
    # pas un lien qu'il rencontre en chemin. Un `find "$destination"` rendait
    # donc RIEN, la table restait vide, et le rapatriement recréait les dossiers
    # au lieu de les retrouver — c'est-à-dire qu'il dupliquait.
    for compte in "$destination"/*; do
        [ -e "$compte" ] || continue
        find "$compte/" -type d -name cur -print0 2>/dev/null
    done
)

# Chaque boîte est un répertoire qui porte `cur` et `new`.
while IFS= read -r -d '' cur_source; do
    boite_source=$(dirname "$cur_source")
    relatif=${boite_source#"$source"}
    relatif=${relatif#/}
    # Le neuf est déjà en UTF-8 ; on le décode tout de même, pour le cas où le
    # renommage n'aurait pas eu lieu — le décodeur laisse l'ASCII intact.
    cherche=$(printf '%s\n' "$relatif" | python3 "$decodeur" --traduire)
    boite_destination="$destination/${reel_de["$cherche"]-$relatif}"
    boites=$((boites + 1))

    # Ce que la destination porte DÉJÀ, quels que soient le dossier et les
    # drapeaux : c'est là tout le point.
    deja=""
    for sous in cur new; do
        [ -d "$boite_destination/$sous" ] || continue
        while IFS= read -r -d '' present; do
            deja="$deja $(unique "$(basename "$present")")"
        done < <(find "$boite_destination/$sous" -maxdepth 1 -type f -print0 2>/dev/null)
    done

    for sous in cur new; do
        [ -d "$boite_source/$sous" ] || continue
        while IFS= read -r -d '' fichier; do
            base=$(unique "$(basename "$fichier")")
            case " $deja " in
                *" $base "*) sautes=$((sautes + 1)); continue ;;
            esac
            copies=$((copies + 1))
            printf '  + %s/%s/%s\n' "$relatif" "$sous" "$(basename "$fichier")"
            if [ "$pour_de_vrai" = "--pour-de-vrai" ]; then
                mkdir -p "$boite_destination/$sous"
                cible="$boite_destination/$sous/$(basename "$fichier")"
                # **ON N'ÉCRASE JAMAIS, ET ON LE DIT SI LE CAS SE PRÉSENTE.**
                # Il ne devrait pas : la partie unique a déjà été cherchée. Un
                # `cp -n` ferait la même garde en silence — et `coreutils`
                # avertit que son comportement peut changer. Un test explicite
                # ne change pas, et se lit.
                if [ -e "$cible" ]; then
                    echo "DÉJÀ LÀ, non écrasé : $cible" >&2
                    continue
                fi
                cp -p "$fichier" "$cible" || {
                    echo "ÉCHEC de copie : $fichier" >&2
                    exit 1
                }
            fi
        done < <(find "$boite_source/$sous" -maxdepth 1 -type f -print0 2>/dev/null)
    done
done < <(find "$source" -type d -name cur -print0 2>/dev/null)

echo
printf 'boîtes examinées : %d\n' "$boites"
printf 'à rapatrier      : %d\n' "$copies"
printf 'déjà présents    : %d\n' "$sautes"
if [ "$pour_de_vrai" != "--pour-de-vrai" ]; then
    echo
    echo "RIEN N'A ÉTÉ ÉCRIT. Relancez avec --pour-de-vrai pour copier."
fi
