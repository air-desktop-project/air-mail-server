#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Pose les six secrets INITIAUX, tous distincts, et écrit de quoi les
# distribuer. À lancer sur la machine, la veille de la bascule.
#
# ── POURQUOI TOUS DISTINCTS, ET POURQUOI ÇA SE VÉRIFIE ──────────────────────
#
# Un secret commun laisserait chacun ouvrir la boîte des cinq autres. Ce n'est
# pas une précaution abstraite : ces comptes sont une famille et une entreprise
# qui se connaissent, et le secret circulera par messages. Le script REFUSE de
# continuer si deux tirages coïncident — plutôt que de supposer que
# `/dev/urandom` ne se répète pas.
#
# ── LA SIXIÈME N'EST PAS UNE PERSONNE ───────────────────────────────────────
#
# `ofrou-sierre` est la passerelle Milesight du chantier OFROU Sierre, créée le
# 2026-09-15 — après la phase 0, ce qui est la raison pour laquelle ce script ne
# la nommait pas. Deux choses la distinguent, et les deux sont dans le code :
#
#   · son secret n'a PAS de tirets — l'interface Milesight n'accepte que des
#     caractères alphanumériques, et un secret refusé au moment de la saisie,
#     sur un appareil joint en 4G, se découvre mal ;
#   · il ne se distribue pas par courrier : il se TAPE dans cette interface, et
#     la sortie le dit, ligne par ligne, pour qu'on ne l'envoie pas à quelqu'un.
#
# ── CE SONT DES SECRETS DE PASSAGE ──────────────────────────────────────────
#
# §0.4ter : chacun pose ensuite le sien, sans passer par l'administrateur.
# Celui-ci ne sert qu'à ouvrir la porte une fois. **SAUF CELUI DE LA
# PASSERELLE** : elle ne sait pas changer de mot de passe, le sien est donc
# définitif — une raison de plus pour qu'il n'ouvre que sa propre boîte.
#
# ── ILS NE S'AFFICHENT JAMAIS SUR LA SORTIE ─────────────────────────────────
#
# Ni à l'écran, ni dans `ps`, ni dans l'historique du shell. Ils vont dans UN
# fichier en 0600, et le chemin est dit. Un secret imprimé sur un terminal vit
# ensuite dans son tampon de défilement, dans la capture de la session, et dans
# tout ce qui la relit.
#
# `air-mail-admin account passwd` les lit sur l'ENTRÉE STANDARD : ce que `ps`
# affiche, tout le monde le lit.
#
# ── L'ALPHABET ÉVITE CE QUI SE CONFOND ──────────────────────────────────────
#
# Ces secrets sont TAPÉS À LA MAIN dans un client de courrier, souvent depuis un
# téléphone. `0`/`O`, `1`/`l`/`I` coûtent un appel de support chacun. On les
# retire, et l'on groupe par quatre pour que l'œil retrouve sa place — SAUF
# pour une machine, dont l'interface refuse le tiret.
set -euo pipefail

comptes=(contact thierry.delhaise vincent.delhaise support kelly.garro ofrou-sierre)
# **CEUX QUI VONT DANS UNE INTERFACE, ET NON DANS UN COURRIER.** Leur secret se
# tire sans tirets. La liste est une liste, et non un `if` sur un nom : la
# prochaine passerelle s'ajoute ici, et nulle part ailleurs.
machines=(ofrou-sierre)
magasin=/var/lib/air-mail/comptes.bin
sortie="${SECRETS_SORTIE:-$HOME/secrets-narro-$(date +%Y%m%d).txt}"
pour_de_vrai=0

while [ $# -gt 0 ]; do
    case "$1" in
        --pour-de-vrai) pour_de_vrai=1; shift ;;
        --magasin) magasin="${2-}"; shift 2 ;;
        --sortie) sortie="${2-}"; shift 2 ;;
        --aide|-h) sed -n '6,50p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "poser-les-secrets : option inconnue : $1" >&2; exit 2 ;;
    esac
done

dit() { printf '  %s\n' "$*"; }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((66 - ${#1}))))"; }

# ── L'ALPHABET, ET LE TIRAGE ────────────────────────────────────────────────
#
# **TRENTE-ET-UN symboles** — vingt-trois lettres (l'alphabet moins `i`, `l` et
# `o`) et huit chiffres (2 à 9). Seize symboles font donc 16 × log₂(31) ≈ **79
# bits**, et non les quatre-vingts qu'un compte rond ferait écrire. C'est très
# au-delà de ce qu'un secret de passage demande, et cela ne coûte rien à qui le
# recopie une fois.
alphabet='abcdefghjkmnpqrstuvwxyz23456789'
est_une_machine() {
    local nom
    for nom in "${machines[@]}"; do [ "$nom" = "$1" ] && return 0; done
    return 1
}
un_secret() {  # $1 = le compte, pour savoir s'il faut grouper par quatre
    local n=${#alphabet} secret='' i groupe=1
    est_une_machine "${1-}" && groupe=0
    for ((i = 0; i < 16; i++)); do
        # `od` plutôt que `$RANDOM` : ce dernier vient d'un générateur du shell,
        # amorcé de façon prévisible, et il ne convient à aucun secret.
        local tirage
        tirage=$(od -An -N1 -tu1 < /dev/urandom | tr -d ' ')
        # **LE MODULO BIAISE**, et l'on rejette plutôt que de biaiser : 256 n'est
        # pas un multiple de 31, donc les premiers symboles sortiraient un peu
        # plus souvent. Sur un secret de passage cela ne se verrait pas — et
        # c'est exactement le genre de raccourci qui se recopie ailleurs.
        while [ "$tirage" -ge $((256 - 256 % n)) ]; do
            tirage=$(od -An -N1 -tu1 < /dev/urandom | tr -d ' ')
        done
        secret="$secret${alphabet:$((tirage % n)):1}"
        # **LES TIRETS SONT POUR L'ŒIL, PAS POUR LA MACHINE.** Ils aident qui
        # recopie seize symboles à retrouver sa place — et ils font refuser le
        # secret par une interface qui n'accepte que l'alphanumérique.
        [ "$groupe" -eq 1 ] && [ $(((i + 1) % 4)) -eq 0 ] && [ "$i" -lt 15 ] \
            && secret="$secret-"
    done
    printf '%s' "$secret"
}

titre "contrôles préalables"
for outil in air-mail-admin od; do
    command -v "$outil" > /dev/null 2>&1 || { echo "manque : $outil" >&2; exit 1; }
done
dit "air-mail-admin et od sont là"

# ── LE MAGASIN SE TESTE AVEC LES DROITS QU'IL FAUT ──────────────────────────
#
# `/var/lib/air-mail` est en 0700 et appartient à `air-mail` : un `[ -f ]` lancé
# par un autre compte rend FAUX sur un fichier parfaitement présent. La première
# écriture de ce script disait donc « magasin introuvable » sur la vraie
# machine, et envoyait chercher un fichier absent là où il ne manquait qu'un
# `sudo`.
#
# C'est le même défaut que celui trouvé dans `verifier.sh` le même soir — sauf
# qu'ici il refuse, là il rendait « OK ». Refuser pour une raison fausse fait
# perdre du temps ; accepter pour une raison fausse fait perdre le courrier.
if ! sudo -u air-mail test -f "$magasin"; then
    echo "poser-les-secrets : $magasin est absent, ou illisible même par \`air-mail\`." >&2
    exit 1
fi
connus=$(sudo -u air-mail air-mail-admin account list "$magasin" | awk '{print $1}')
manquants=0
for compte in "${comptes[@]}"; do
    grep -qx "$compte" <<< "$connus" || { echo "  ABSENT du magasin : $compte" >&2; manquants=1; }
done
[ "$manquants" -eq 0 ] || {
    echo "poser-les-secrets : un compte manque — RIEN n'a été touché." >&2
    echo "  Ce script POSE des secrets, il ne crée pas de compte : c'est \`account add\`" >&2
    echo "  de la §0.4 de \`bascule.md\` qui les écrit. \`ofrou-sierre\` est née le" >&2
    echo "  2026-09-15, après la phase 0 — elle manque encore au magasin de la machine." >&2
    exit 1
}
dit "les ${#comptes[@]} comptes sont dans $magasin"

# **ON REFUSE D'ÉCRASER UN FICHIER DE SECRETS DÉJÀ LÀ.** Deux passages laisseraient
# des secrets posés dans le magasin dont plus personne n'a le texte.
[ -e "$sortie" ] && { echo "poser-les-secrets : $sortie existe déjà — écartez-le d'abord." >&2; exit 1; }
dit "la sortie sera $sortie"

if [ "$pour_de_vrai" -eq 0 ]; then
    titre "à blanc"
    dit "RIEN n'a été posé, et aucun secret n'a été tiré."
    dit "Pour de vrai :  bash $(basename "$0") --pour-de-vrai"
    exit 0
fi

# ── LE TIRAGE, PUIS LA POSE ─────────────────────────────────────────────────
titre "tirage"
declare -A secrets
for compte in "${comptes[@]}"; do
    secrets["$compte"]=$(un_secret "$compte")
done

# **LA DISTINCTION SE VÉRIFIE**, elle ne se suppose pas.
distincts=$(printf '%s\n' "${secrets[@]}" | sort -u | wc -l)
[ "$distincts" -eq "${#comptes[@]}" ] || {
    echo "poser-les-secrets : deux secrets coïncident — RIEN n'a été posé." >&2
    exit 1
}
dit "${#comptes[@]} secrets, ${distincts} distincts, ~79 bits chacun"

titre "pose dans le magasin"
for compte in "${comptes[@]}"; do
    printf %s "${secrets[$compte]}" \
        | sudo -u air-mail air-mail-admin account passwd "$magasin" --login "$compte"
    dit "$compte"
done

titre "de quoi distribuer"
umask 077
{
    printf 'Secrets INITIAUX de narro.ch — posés le %s\n' "$(date -Is)"
    printf 'Ils sont DE PASSAGE : chacun pose le sien ensuite (voir pour-les-utilisateurs.md).\n'
    printf 'À transmettre par un canal distinct de celui qui a annoncé la bascule.\n\n'
    for compte in "${comptes[@]}"; do
        if est_une_machine "$compte"; then
            printf '%-20s %s   <- À TAPER dans l'"'"'interface de la passerelle\n' \
                "$compte" "${secrets[$compte]}"
        else
            printf '%-20s %s\n' "$compte" "${secrets[$compte]}"
        fi
    done
    printf '\n%s\n' "La passerelle Milesight (ofrou-sierre) ne lit pas son courrier :"
    printf '%s\n' "son secret se saisit dans son interface — mail.narro.ch, port 587"
    printf '%s\n' "STARTTLS, identifiant = l'adresse complète, From: obligatoirement"
    printf '%s\n' "ofrou-sierre@narro.ch. Tant qu'il n'y est pas, ses alertes s'arrêtent"
    printf '%s\n' "SANS QUE RIEN NE LE DISE."
} > "$sortie"
chmod 600 "$sortie"
dit "$sortie (0600) — $(wc -l < "$sortie") lignes"

printf '\nOK : les %d secrets sont posés, tous distincts.\n' "${#comptes[@]}"
printf '     Ils ne sont PAS dans cette sortie : ils sont dans %s\n' "$sortie"
printf '     Effacez-le une fois les %d transmis — et celui de la passerelle SAISI\n' \
    "$((${#comptes[@]} - ${#machines[@]}))"
printf '     dans son interface, ce qui ne se fait pas depuis cette machine.\n'
