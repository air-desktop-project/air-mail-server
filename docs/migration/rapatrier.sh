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

# Chaque boîte est un répertoire qui porte `cur` et `new`.
while IFS= read -r -d '' cur_source; do
    boite_source=$(dirname "$cur_source")
    relatif=${boite_source#"$source"}
    relatif=${relatif#/}
    boite_destination="$destination/$relatif"
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
