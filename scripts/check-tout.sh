#!/usr/bin/env bash
#
# check-tout — les dix barrières, dans l'ordre, sans en oublier une.
#
# # LE DÉFAUT QUE CETTE BARRIÈRE FERME
#
# Les barrières se déroulaient à la main, une commande après l'autre. Le
# 2026-09-06, la tranche `9e48e31c` est partie sans que clippy ait tourné — la
# seule des dix qui n'avait pas encore de script — et la CI l'a dit vingt-cinq
# minutes plus tard. Le script de clippy a été écrit dans la foulée ; il ne
# corrigeait que la moitié du problème.
#
# **L'AUTRE MOITIÉ : RIEN NE VÉRIFIAIT QUE LES DIX AVAIENT TOURNÉ.** Un geste
# manuel de dix pas en oublie un, et rien ne le dit. C'est ce trou-là que ce
# script comble, et il a été consigné dans `docs/contraintes.md` avant d'être
# comblé — parce qu'un trou reconnu vaut mieux qu'un trou tenu pour comblé.
#
# # LA LISTE NE SE RECOPIE PAS, ELLE SE DÉRIVE
#
# `check-fuzz` et `check-paquet` s'étaient ajoutées au dépôt sans que la ligne
# qui les compte bouge dans `docs/v1.md`. Une liste écrite ici aurait le même
# sort : elle vieillirait en silence, et ce script dirait « les dix » en en
# lançant huit.
#
# Il lit donc le RÉPERTOIRE, et confronte ce qu'il y trouve à trois choses :
#
#   1. l'ORDRE ci-dessous, qui est un choix — le plus rapide d'abord, pour qu'un
#      échec se sache en une seconde plutôt qu'en quarante minutes ;
#   2. ce que `ci.yml` LANCE, car une barrière que la CI ignore ne protège que
#      la machine de qui la lance ;
#   3. réciproquement, ce que `ci.yml` lance et qui n'existerait pas ici.
#
# **ET LES ARGUMENTS VIENNENT DE LÀ AUSSI.** La première écriture de ce script
# lançait `check-fuzz.sh` nu, alors que la CI lui passe `--smoke` : sans cette
# option, la barrière COMPILE les cibles sans les faire tourner. Le runner aurait
# annoncé « les dix passent » en en passant une plus faible que la CI — le genre
# de mensonge exact qu'il existe pour empêcher. Il lit donc la ligne `run:` de
# `ci.yml` et reprend ce qu'elle passe.
#
# Les expressions `${{ … }}` en sont retirées : elles n'ont de sens que chez
# GitHub. `check-dco` en porte une — la base de comparaison — et son absence lui
# fait prendre son défaut, `origin/main`, qui est ce qu'on veut en local.
#
# Un écart dans n'importe lequel des trois sens ARRÊTE ce script. Il ne s'agit
# pas de style : c'est la seule façon qu'une onzième barrière ne puisse pas
# naître sans que ce runner l'apprenne.
#
# # POURQUOI AUCUNE OPTION POUR EN SAUTER UNE
#
# Un `--sans-fuzz` serait la première chose qu'on taperait un soir de hâte, et le
# geste manuel qu'on remplace ici avait exactement cette forme. Ce qui est long
# l'est ; on le lance et on fait autre chose.
#
# # CE QUE CE SCRIPT NE PEUT PAS DIRE
#
# `check-dco` examine `base..HEAD`, c'est-à-dire les commits qui EXISTENT DÉJÀ.
# Lancé avant de commiter, il ne voit pas le commit qu'on s'apprête à écrire. Il
# tourne quand même — il coûte une seconde et rattrape un commit précédent mal
# formé — mais son verdict ne porte pas sur la tranche en cours, et ce script le
# dit plutôt que de le laisser croire.

set -uo pipefail

cd "$(dirname "$0")/.."

# ── L'ORDRE : un choix, et le seul de ce fichier ─────────────────────────────
#
# Du plus rapide au plus lent. `check-etages` ne compile rien et dure une
# seconde ; `check-fuzz` compile soixante-six cibles et les fait tourner.
ORDRE=(
    check-format
    check-etages
    check-dco
    check-compile
    check-clippy
    check-sans-c
    check-couverture
    check-installation
    check-paquet
    check-fuzz
)

# ── Ce que le répertoire porte ───────────────────────────────────────────────
mapfile -t PRESENTES < <(
    find scripts -maxdepth 1 -name 'check-*.sh' -printf '%f\n' |
        sed 's/\.sh$//' | grep -vx 'check-tout' | sort
)

ecart_de_liste=0
dire_ecart() {
    echo "ÉCHEC DE COHÉRENCE : $1"
    ecart_de_liste=1
}

# 1. L'ordre couvre-t-il exactement ce qui existe ?
for barriere in "${PRESENTES[@]}"; do
    trouve=0
    for prevue in "${ORDRE[@]}"; do
        [ "$prevue" = "$barriere" ] && trouve=1
    done
    [ "$trouve" = 1 ] || dire_ecart "\`scripts/$barriere.sh\` existe mais n'est pas dans l'ORDRE de ce script"
done
for prevue in "${ORDRE[@]}"; do
    [ -x "scripts/$prevue.sh" ] || dire_ecart "l'ORDRE cite \`$prevue\`, que \`scripts/\` ne porte pas (ou pas exécutable)"
done

# 2 et 3. La CI lance-t-elle les mêmes ?
CI=.github/workflows/ci.yml
for barriere in "${PRESENTES[@]}"; do
    grep -q "scripts/$barriere.sh" "$CI" ||
        dire_ecart "\`$barriere\` tourne ici et JAMAIS dans la CI — elle ne protège que cette machine"
done
mapfile -t LANCEES_PAR_LA_CI < <(
    grep -oE '\.?/?scripts/check-[a-z-]+\.sh' "$CI" | sed 's|.*scripts/||; s|\.sh$||' | sort -u
)
for barriere in "${LANCEES_PAR_LA_CI[@]}"; do
    [ -x "scripts/$barriere.sh" ] ||
        dire_ecart "la CI lance \`$barriere\`, que \`scripts/\` ne porte pas"
done

if [ "$ecart_de_liste" != 0 ]; then
    echo
    echo 'ARRÊT : la liste des barrières ne coïncide pas. Rien n'"'"'a été lancé.'
    exit 1
fi

# ── LES ARGUMENTS, TELS QUE `ci.yml` LES PASSE ───────────────────────────────
#
# On prend ce qui suit `scripts/<barrière>.sh` sur sa ligne `run:`, moins les
# expressions `${{ … }}` qui n'ont de sens que chez GitHub.
# **SUR LES LIGNES `run:` SEULEMENT.** La première écriture prenait la première
# occurrence n'importe où dans le fichier, et attrapait un COMMENTAIRE qui cite
# `scripts/check-fuzz.sh` — d'où un argument fantôme, « ` fait ». Un fichier qui
# s'explique abondamment est une chance ; le lire comme s'il ne contenait que des
# commandes est une faute.
arguments_de() {
    grep -oE "run: *\.?/?scripts/$1\.sh[^\n]*" "$CI" |
        head -1 |
        sed "s|^run: *\.\?/\?scripts/$1\.sh||; s|\\\${{[^}]*}}||g; s|\"||g" |
        xargs 2>/dev/null || true
}

echo "check-tout — ${#ORDRE[@]} barrières, plus \`cargo build\` et \`cargo test\`"
echo "             (la CI les lance toutes ; voir \`$CI\`)"
echo

# ── LES DEUX ÉTAPES DE LA CI QUI N'ONT PAS DE SCRIPT ─────────────────────────
#
# `cargo build` et `cargo test` sont des étapes de `ci.yml` à part entière. Leur
# donner un script n'apporterait rien — elles n'ont ni argument ni raison à
# expliquer — mais les OUBLIER ici ferait de ce runner un menteur.
declare -A DIRECTES=(
    [cargo-build]="cargo build --workspace --locked"
    [cargo-test]="cargo test --workspace --locked"
)
# Après `check-sans-c`, comme dans la CI.
APRES=check-sans-c

resultats=()
rate=0

lancer() {
    local nom=$1 commande=$2
    local debut fin
    debut=$SECONDS
    printf '── %s ' "$nom"
    printf '%.0s─' $(seq 1 $((60 - ${#nom}))) 
    printf '\n'
    if eval "$commande"; then
        fin=$((SECONDS - debut))
        resultats+=("OK     $nom (${fin} s)")
    else
        fin=$((SECONDS - debut))
        resultats+=("ÉCHEC  $nom (${fin} s)")
        rate=1
    fi
    echo
}

for barriere in "${ORDRE[@]}"; do
    passe=$(arguments_de "$barriere")
    if [ -n "$passe" ]; then
        lancer "$barriere $passe" "./scripts/$barriere.sh $passe"
    else
        lancer "$barriere" "./scripts/$barriere.sh"
    fi
    if [ "$barriere" = "$APRES" ]; then
        lancer cargo-build "${DIRECTES[cargo-build]}"
        lancer cargo-test "${DIRECTES[cargo-test]}"
    fi
done

echo '════════════════════════════════════════════════════════════'
for ligne in "${resultats[@]}"; do
    echo "  $ligne"
done
echo '════════════════════════════════════════════════════════════'
echo
echo 'RAPPEL : `check-dco` a examiné `base..HEAD`, donc les commits DÉJÀ écrits.'
echo '         Il ne dit rien de la tranche qu'"'"'on s'"'"'apprête à commiter.'

if [ "$rate" != 0 ]; then
    echo
    echo 'ÉCHEC : au moins une barrière refuse.'
    exit 1
fi

echo
echo "OK : les ${#ORDRE[@]} barrières passent, et les deux commandes de la CI aussi."
