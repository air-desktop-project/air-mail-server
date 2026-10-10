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
# Les deux contrôles précédents lisent des NOMS. Celui-ci regarde le disque.
#
# **IL MESURE LA PROVENANCE, IL NE LA DÉDUIT PLUS DU CHEMIN.** Il balayait
# `target/*/build` et concluait « objet C » sur tout `.o`/`.a` trouvé là. La
# prémisse — ce chemin n'appartient qu'aux scripts de construction — **ne tient
# pas** : cargo y range aussi des artefacts de rustc (cible `staticlib`, unités de
# codegen). Constaté le 2026-10-09 dans le dépôt `air-service-locator-client`, où
# le même critère a accusé une archive produite par rustc dans une crate SANS
# `build.rs`.
#
# Un contrôle qui accuse le compilateur du langage qu'il protège est pire
# qu'absent : on apprend à ignorer son verdict.
#
# On lit donc la section `.comment` de chaque objet, que le compilateur producteur
# y écrit lui-même. Le détail, l'exemption des objets `compiler-rt` livrés par la
# toolchain, et la posture fermée-par-défaut sont dans
# `scripts/provenance-objets.py` — fichier PARTAGÉ avec les dépôts
# `air-service-locator-{client,server}` : toute correction ici est due là-bas.
#
# Elle ne vaut que si une compilation a eu lieu ; sans `target/`, elle se tait
# plutôt que de conclure.
# **CE QUE `main` AVAIT CORRIGÉ AUTREMENT, ET QUI EST REPRIS ICI.** Le 2026-09-22,
# ce même critère rendait un ÉCHEC sur le poste de développement : il prenait pour
# des objets C les `*.rcgu.o`, qui sont les unités de génération de code de `rustc`
# lui-même, que le Mac laisse traîner sous `build/`. Le correctif d'alors les
# excluait PAR LEUR NOM (`! -name '*.rcgu.o'`). Il tuait bien le faux positif, mais
# il s'ouvrait du même geste : un objet C nommé `faux.rcgu.o` n'était plus regardé.
# Éprouvé le 2026-10-10 — un objet produit par GCC 15.2.0 et nommé ainsi passait
# le filtre par nom sans un mot, et la mesure de provenance le refuse en nommant
# son producteur. Un nom est une convention ; une section `.comment` est une trace.
if ! python3 scripts/provenance-objets.py; then
    violations=$((violations + 1))
fi

combien=$(cargo tree --prefix none --edges normal 2>/dev/null | awk '{print $1}' | sort -u | wc -l)

if [ "$violations" -gt 0 ]; then
    echo
    echo "ÉCHEC : $violations contrôle(s) en défaut — « aucun C » n'est plus tenu."
    exit 1
fi

echo "graphe    : $combien crates hors dépendances d'essai"
echo
echo "OK : ni \`ring\`, ni \`cc\`, ni crate \`*-sys\` — et aucun objet refusé"
echo "     par le critère 3, dont la ligne ci-dessus dit CE QU'IL A EXAMINÉ."
