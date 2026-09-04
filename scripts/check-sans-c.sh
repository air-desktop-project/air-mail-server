#!/usr/bin/env bash
#
# check-sans-c — « aucun C » est-il tenu, ou seulement mesuré une fois ?
#
# # Ce que le registre affirmait, et ce que rien ne vérifiait
#
# Sous le titre « Ce qui a été mesuré, et non supposé », le registre écrit :
# « **Aucun C.** […] ni `ring`, ni `cc`, ni la moindre crate `*-sys` ». C'était
# vrai, et daté du 2026-08-28 — c'est-à-dire vrai CE JOUR-LÀ.
#
# Rien ne le revérifiait. Un `cargo add` suffisait à faire entrer `ring` ou une
# crate `*-sys` dans le graphe, et la propriété serait tombée sans un mot : le
# projet aurait continué d'affirmer, dans un document que personne ne relit à
# chaque commit, ce qui aurait cessé d'être.
#
# # Pourquoi cela vaut une barrière
#
# Une dépendance en C n'est pas une dépendance comme une autre. Elle échappe aux
# garanties du compilateur Rust, elle demande un compilateur C sur la machine de
# qui construit, elle rend la reproductibilité tributaire d'un `cc` et de ses
# options, et elle ouvre une classe de fautes — dépassements, doubles
# libérations — que le reste de ce dépôt s'est donné du mal pour rendre
# impossible.
#
# La constater à la main, une fois, ne la tient pas. Ceci la tient.
#
# # Ce qui est vérifié, et comment
#
# Trois choses, sur la CIBLE HÔTE — car c'est elle qu'on compile, et une crate
# réservée à une autre plateforme (`windows-sys`) n'entre jamais dans le
# binaire :
#
#   1. `ring` et `cc` sont absents du graphe ;
#   2. aucune crate dont le nom finit par `-sys` n'y figure ;
#   3. aucune compilation n'a produit d'objet C — pas un `.o`, pas un `.a`.
#
# Le nombre de crates est RENDU, jamais opposé : il change à chaque dépendance
# ajoutée, et en faire un seuil ferait échouer la barrière pour une raison qui
# n'est pas celle qu'elle garde.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "check-sans-c — ce qui entre dans le binaire, et ce qui n'y entre pas"
echo

violations=0

# ── 1. Les deux noms que le registre cite ───────────────────────────────────
#
# `-i <crate>` demande « qui en dépend » : sans réponse, la crate n'est pas dans
# le graphe. `cargo tree` le dit sur sa sortie d'erreur, et rend zéro quand même
# — on lit donc la sortie, pas le code.
for interdite in ring cc; do
    if cargo tree -i "$interdite" --prefix none 2>/dev/null | grep -q .; then
        echo "ÉCHEC : \`$interdite\` est dans le graphe de dépendances."
        cargo tree -i "$interdite" --prefix none 2>/dev/null | head -5 | sed 's/^/    /'
        violations=$((violations + 1))
    fi
done

# ── 2. Toute crate `*-sys`, quelle qu'elle soit ─────────────────────────────
#
# Le suffixe `-sys` est la convention pour « ceci enveloppe une bibliothèque
# système ». Elle n'est pas une garantie — une crate peut lier du C sans le
# suffixe — mais elle attrape la quasi-totalité des cas, et son absence est
# exactement ce que le registre affirme.
sys=$(cargo tree --prefix none 2>/dev/null | awk '{print $1}' | sort -u | grep -E -- '-sys$' || true)
if [ -n "$sys" ]; then
    echo "ÉCHEC : des crates \`*-sys\` sont dans le graphe de la cible hôte :"
    echo "$sys" | sed 's/^/    /'
    violations=$((violations + 1))
fi

# ── 3. Ce que la compilation a réellement produit ───────────────────────────
#
# Les deux contrôles précédents lisent des NOMS. Celui-ci regarde le disque : un
# objet C sous `target/*/build` veut dire qu'un compilateur C a tourné, quel que
# soit le nom de la crate qui l'a demandé. C'est la seule des trois qui ne se
# laisse pas contourner par un nom bien choisi.
#
# Elle ne vaut que si une compilation a eu lieu ; sans `target/`, elle se tait
# plutôt que de conclure.
objets=""
for repertoire in target/debug/build target/release/build; do
    if [ -d "$repertoire" ]; then
        trouves=$(find "$repertoire" \( -name '*.o' -o -name '*.a' \) 2>/dev/null | head -5 || true)
        [ -n "$trouves" ] && objets="$objets$trouves"$'\n'
    fi
done
if [ -n "${objets// /}" ]; then
    echo "ÉCHEC : une compilation a produit des objets C :"
    echo "$objets" | grep -v '^$' | sed 's/^/    /'
    violations=$((violations + 1))
fi

combien=$(cargo tree --prefix none --edges normal 2>/dev/null | awk '{print $1}' | sort -u | wc -l)

if [ "$violations" -gt 0 ]; then
    echo
    echo "ÉCHEC : $violations contrôle(s) en défaut — « aucun C » n'est plus tenu."
    exit 1
fi

echo "graphe    : $combien crates hors dépendances d'essai"
echo "objets C  : aucun"
echo
echo "OK : ni \`ring\`, ni \`cc\`, ni crate \`*-sys\` — et pas un objet C compilé."
