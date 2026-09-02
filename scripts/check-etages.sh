#!/usr/bin/env bash
#
# check-etages — C1 est-elle tenue, ou seulement affirmée ?
#
# # Ce que C1 dit, et ce que rien ne vérifiait
#
# Les crates de protocole et les machines à états ne connaissent ni socket, ni
# fichier, ni horloge. Ce sont les boucles (`ams-loop-*`) qui lisent, écrivent
# et attendent.
#
# Le registre l'écrivait, et écrivait aussi que **rien ne le vérifiait** :
# « Aucun gate ne vérifie qu'une crate `ams-proto-*` ou `ams-session` n'importe
# pas `std::net` ou `std::fs`. C'est faisable (un `grep` sur les `use`) et ce
# n'est pas fait. » Le voici.
#
# # Pourquoi cela vaut un gate, et pas une revue
#
# C1 est la contrainte dont TOUT le reste dépend. C'est elle qui rend C2
# atteignable : une machine à états se pilote pas à pas depuis un test, une
# boucle `async` ne se pilote pas — on l'attend. Un seul `std::fs` glissé dans un
# codec, et le 100 % de couverture cesse d'être une mesure pour devenir une
# fiction qu'on entretient.
#
# Une revue attrape cela **quand elle regarde**. Un `use` ajouté dans un fichier
# de trois cents lignes, un jour de correction pressée, ne se regarde pas.
#
# # LA LISTE DES CRATES N'EST PAS ICI
#
# Elle vit dans `check-couverture.sh`, qui en a besoin pour la même raison : le
# périmètre de C2 EST le périmètre de C1. Deux listes auraient fini par différer,
# et une crate serait sortie de l'une sans sortir de l'autre — couverte à 100 %
# et libre de faire des entrées-sorties, ou l'inverse.
#
# Ce script la LIT donc là-bas. Si l'extraction ne rend rien, il ÉCHOUE plutôt
# que de conclure : un contrôle qui n'a rien examiné n'est pas un contrôle qui
# passe.

set -euo pipefail

racine=$(cd "$(dirname "$0")/.." && pwd)
cd "$racine"

# ── Le périmètre, lu là où il vit ───────────────────────────────────────────
crates=$(sed -n '/^CRATES_SANS_IO=(/,/^)/p' scripts/check-couverture.sh \
    | grep -oE 'ams-[a-z0-9-]+' || true)

if [ -z "$crates" ]; then
    echo "ÉCHEC : impossible de lire le périmètre dans scripts/check-couverture.sh."
    echo "Ce contrôle n'a RIEN examiné ; il ne prétend pas le contraire."
    exit 1
fi

combien=$(wc -l <<< "$crates")
echo "périmètre : $combien crates sans entrée-sortie (lu de check-couverture.sh)"

# ── ET LE DÉCOUPAGE EST CELUI QUE LE README ANNONCE ─────────────────────────
#
# Les trois tableaux du README sont la seule description des étages qu'un
# lecteur rencontre avant le code. Une crate qui n'y figure pas n'existe pas
# pour lui : il la découvre en trébuchant dessus, sans savoir de quel étage elle
# est ni ce qu'elle a le droit de faire.
#
# C'est arrivé, et largement : le tableau en décrivait vingt-quatre sur
# trente-quatre. Toute la pile QUIC, HTTP/2 et HTTP/3 y manquait, ainsi que
# l'API REST — c'est-à-dire dix crates dont rien ne disait l'étage. Un tableau
# tenu à la main dérive à chaque tranche ; celui-ci est confronté.
sur_disque=$(find crates -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
au_tableau=$(grep -oE '^\| `ams-[a-z0-9-]+`' README.md | tr -d '|` ' | sort)

if [ "$sur_disque" != "$au_tableau" ]; then
    echo >&2
    echo "ÉCHEC : les tableaux du README et le contenu de \`crates/\` diffèrent." >&2
    diff -u <(echo "$au_tableau") <(echo "$sur_disque") >&2 || true
    echo >&2
    echo "Une crate absente des tableaux n'existe pas pour qui lit le README :" >&2
    echo "il ignore son étage, donc ce qu'elle a le droit de faire." >&2
    exit 1
fi

echo "découpage  : les tableaux du README nomment les $(wc -l <<< "$sur_disque") crates de \`crates/\`"
echo

# ── Ce qui est interdit, et pourquoi chaque entrée y est ────────────────────
#
# `std::time::Duration` n'y est PAS : c'est un type, pas une horloge. `Instant`
# et `SystemTime`, eux, LISENT l'heure — c'est-à-dire qu'ils rendent deux
# réponses différentes au même appel, ce qu'une machine à états ne doit pas
# faire. C'est la distinction qui compte, et non le nom du module.
#
# `tokio` est nommé pour la même raison qu'il l'est dans C1 : une crate d'étage 2
# qui en dépendrait aurait choisi un modèle d'exécution pour ses appelants.
INTERDITS='std::net|std::fs|std::io|std::process|std::thread|std::time::Instant|std::time::SystemTime|(^|[^-a-z])tokio::|use tokio'

violations=0

for crate in $crates; do
    src="crates/$crate/src"
    [ -d "$src" ] || continue

    # **LES FICHIERS D'ESSAIS SONT HORS PÉRIMÈTRE** : `src/**/tests.rs` est la
    # convention de ce dépôt, et un essai a le droit de lire un fichier de
    # vecteurs. Ce qui est jugé, c'est ce qu'on LIVRE.
    fichiers=$(find "$src" -name '*.rs' ! -name 'tests.rs')
    for fichier in $fichiers; do
        # Les commentaires ne comptent pas : `ams-loop-tokio` se cite en prose
        # dans la moitié des en-têtes, et une citation n'est pas une dépendance.
        trouve=$(sed 's://.*::' "$fichier" | grep -nE "$INTERDITS" || true)
        if [ -n "$trouve" ]; then
            echo "$fichier"
            sed 's/^/    /' <<< "$trouve"
            violations=$((violations + 1))
        fi
    done

    # ── ET LA DÉPENDANCE, PAS SEULEMENT L'USAGE ─────────────────────────────
    #
    # Une crate peut déclarer `tokio` sans encore l'employer. Le jour où elle
    # l'emploiera, la revue arrivera trop tard : la dépendance était déjà là, et
    # personne ne l'aura vue entrer.
    manifeste="crates/$crate/Cargo.toml"
    if [ -f "$manifeste" ] && sed -n '/^\[dependencies\]/,/^\[/p' "$manifeste" \
        | grep -qE '^\s*tokio\s*='; then
        echo "$manifeste"
        echo "    dépend de tokio, alors qu'elle est d'étage 2 (C1)"
        violations=$((violations + 1))
    fi
done

echo
if [ "$violations" -gt 0 ]; then
    echo "ÉCHEC : $violations fichier(s) touchent à une entrée-sortie ou à une horloge (C1)."
    echo "Ce qui lit, écrit ou attend appartient aux boucles (\`ams-loop-*\`)."
    exit 1
fi

echo "OK : les $combien crates du périmètre ne touchent ni socket, ni fichier, ni horloge."
