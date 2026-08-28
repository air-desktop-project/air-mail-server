#!/usr/bin/env bash
#
# check-dco — les commits de cette branche portent-ils leur `Signed-off-by`,
# et sont-ils exempts de toute revendication de paternité par un outil ?
#
# # Ce que le gate vérifie
#
#   VIOLATION  aucun `Signed-off-by:` dans le message      → DCO non certifié
#   VIOLATION  une attribution à Claude / Anthropic        → règle de paternité
#   SIGNALEMENT le `Signed-off-by` ne nomme pas l'auteur    → patch relayé ?
#   SIGNALEMENT commit sans aucune signature cryptographique
#
# Une VIOLATION fait échouer ; un SIGNALEMENT s'affiche et laisse passer.
#
# # Ce que le gate NE PEUT PAS vérifier, et pourquoi c'est dit ici
#
# La VALIDITÉ d'une signature GPG. `git` distingue « non signé » (`N`) de « signé
# mais invérifiable ici » (`E`, clé absente du trousseau) — et un runner de CI n'a
# le trousseau de personne. Il constate donc qu'une signature EXISTE, jamais
# qu'elle est bonne. La vérification effective relève de la protection de branche
# GitHub (`required_signatures`), pas de ce script. Prétendre le contraire serait
# précisément le travers que ce gate existe pour empêcher.
#
# # Le périmètre : la branche, pas l'historique
#
# On examine `base..HEAD`, les commits que cette branche AJOUTE. Rejouer tout
# l'historique ferait échouer chaque PR sur des commits anciens que plus personne
# ne peut corriger.
#
# Usage : scripts/check-dco.sh [base]
#         base par défaut : origin/main, sinon main, sinon HEAD~1.

set -euo pipefail

# ── Résolution de la base ────────────────────────────────────────────────────
#
# Une base absente n'est pas une erreur du gate : c'est un dépôt fraîchement
# cloné, ou un dépôt qui n'a qu'un seul commit.
resoudre_base() {
    if [ $# -ge 1 ] && [ -n "$1" ]; then
        printf '%s\n' "$1"
        return 0
    fi
    for candidat in origin/main main HEAD~1; do
        if git rev-parse --verify --quiet "$candidat" >/dev/null 2>&1; then
            printf '%s\n' "$candidat"
            return 0
        fi
    done
    return 1
}

if base=$(resoudre_base "${1-}"); then
    plage="${base}..HEAD"
else
    # Dépôt à un seul commit : il n'y a pas de base, donc on examine tout.
    base="(aucune — dépôt à commit unique)"
    plage="HEAD"
fi

# `--no-merges` N'EST PAS UNE COMMODITÉ, C'EST LA RÈGLE.
#
# Un commit de fusion n'introduit aucun contenu écrit par quiconque : il déclare
# une jonction entre deux histoires déjà attestées par les commits qu'il réunit.
# Il n'y a donc rien à y certifier, et le DCO l'exempte partout où il s'applique.
#
# Sans cette exemption, le gate échoue sur un commit que PERSONNE n'a écrit : sur
# une pull request, `actions/checkout` positionne `HEAD` sur `refs/pull/N/merge`,
# une fusion que GitHub fabrique à la volée pour prévisualiser l'intégration.
mapfile -t commits < <(git rev-list --no-merges "$plage")

echo "base              : $base"
echo "commits vérifiés  : ${#commits[@]}"
echo

if [ "${#commits[@]}" -eq 0 ]; then
    # UN RAPPORT VERT QUI N'A RIEN EXAMINÉ EST UN MENSONGE POLI. On le dit.
    echo "Aucun commit dans \`$plage\` — RIEN n'a été vérifié."
    echo "(la branche est-elle à jour avec $base ?)"
    exit 0
fi

violations=0
signalements=0

for sha in "${commits[@]}"; do
    court=$(git log -1 --format=%h "$sha")
    sujet=$(git log -1 --format=%s "$sha")
    courriel=$(git log -1 --format=%ae "$sha")
    signature=$(git log -1 --format='%G?' "$sha")
    corps=$(git log -1 --format=%B "$sha")
    etiquette="$court « $sujet »"

    # ── Règle 1 : présence du Signed-off-by ──────────────────────────────────
    sign_offs=$(printf '%s\n' "$corps" | sed -n 's/^[[:space:]]*Signed-off-by:[[:space:]]*//p')

    if [ -z "$sign_offs" ]; then
        echo "VIOLATION  $etiquette"
        echo "           aucun \`Signed-off-by\` — DCO non certifié (\`git commit -s\`)"
        violations=$((violations + 1))
    elif [[ "$courriel" == *"@users.noreply.github.com" ]]; then
        # L'identité a été REMPLACÉE PAR LA FORGE. GitHub réécrit l'auteur d'un
        # squash-merge en `…@users.noreply.github.com` : le sign-off garde le
        # courriel réel, l'auteur porte celui de la forge, et les deux ne
        # coïncideront jamais. Un gate qui les accuserait aurait toujours tort.
        :
    elif ! printf '%s\n' "$sign_offs" | grep -qF "<$courriel>"; then
        echo "SIGNALEMENT $etiquette"
        echo "           le \`Signed-off-by\` ne mentionne pas l'auteur ($courriel)"
        echo "           — légitime pour un patch relayé, à confirmer sinon"
        signalements=$((signalements + 1))
    fi

    # ── Règle 2 : aucune revendication de paternité par un outil ─────────────
    #
    # La règle est DE PATERNITÉ, pas de style : un outil ne co-signe pas, pas plus
    # qu'un compilateur. Seule la signature de l'auteur humain fait foi.
    #
    # Les motifs visent les artefacts RÉELS que les clients savent introduire — un
    # trailer, une ligne « Generated with », une URL de session — et non le mot
    # « claude » où qu'il apparaisse : une phrase de prose qui parlerait de l'outil
    # n'est pas une revendication d'autorat, et la confondre avec une violation
    # rendrait ce gate impossible à respecter honnêtement.
    #
    # L'URL est exigée AVEC SON SCHÉMA `https://`. Le motif l'ignorait d'abord, et
    # a rejeté le commit qui l'introduisait : ce message-là DÉCRIVAIT les URL au
    # lieu de les revendiquer. Tout artefact réel porte son schéma (le lien
    # « Generated with », la ligne `Claude-Session:`), donc l'exiger ne laisse rien
    # passer — et rend le gate compatible avec sa propre documentation.
    attribution=$(printf '%s\n' "$corps" | grep -inE \
        -e '^[[:space:]]*co-authored-by:.*(claude|anthropic)' \
        -e '^[[:space:]]*(claude|anthropic)[a-z-]*:[[:space:]]*[^[:space:]]' \
        -e 'generated with.*(claude|anthropic)' \
        -e 'https?://(claude\.ai/code|claude\.com/claude-code)' || true)

    if [ -n "$attribution" ]; then
        echo "VIOLATION  $etiquette"
        echo "           attribution à un outil — un outil n'est pas co-auteur :"
        printf '%s\n' "$attribution" | sed 's/^/             /'
        violations=$((violations + 1))
    fi

    # ── Règle 3 : une signature a-t-elle été apposée ? ───────────────────────
    #
    # `N` = aucune signature. C'est le SEUL verdict qu'un runner sans trousseau
    # puisse rendre avec certitude (cf. l'en-tête de ce fichier).
    if [ "$signature" = "N" ]; then
        echo "SIGNALEMENT $etiquette"
        echo "           commit NON signé (aucune signature GPG/SSH apposée)"
        signalements=$((signalements + 1))
    fi
done

echo
echo "violations : $violations    signalements : $signalements"

if [ "$violations" -gt 0 ]; then
    exit 1
fi
