#!/usr/bin/env bash
#
# check-openapi — le document commité est-il celui que le code engendre ?
#
# # LE DÉFAUT QUE CETTE BARRIÈRE FERME
#
# Un document d'API écrit à la main est faux le jour où une route bouge, et
# personne ne s'en aperçoit : rien ne le relit. C'est la panne ordinaire de
# toutes les API documentées, et elle est pire que l'absence de document — un
# client code contre ce qui est écrit, pas contre ce qui est servi.
#
# `docs/openapi.json` n'est donc pas écrit : il est ENGENDRÉ, par
# `air-mail-admin openapi`, depuis la table de routage elle-même. Cette barrière
# régénère le document et exige qu'il soit identique à celui qui est commité.
#
# **POURQUOI LE COMMITER, PUISQU'IL S'ENGENDRE ?** Parce qu'un `diff` lisible est
# ce qui fait voir qu'une route a changé. Un ajout de chemin, une méthode de
# plus, une portée qui bouge : cela se lit dans la revue, et c'est exactement ce
# qu'on veut qu'un relecteur voie.
#
# # CE QU'ELLE VÉRIFIE, DANS CET ORDRE
#
#   1. Le document se régénère et il est IDENTIQUE au commité ;
#   2. c'est du JSON que `python3` relit — l'écrivain tient la structure par
#      construction, mais une barrière qui ne vérifie que son propre travail ne
#      vérifie rien ;
#   3. ses invariants tiennent : la version d'OpenAPI, une opération par méthode
#      servie, des `operationId` distincts, et toutes les références internes
#      qui aboutissent.
#
# **ELLE N'APPELLE AUCUN VALIDEUR EXTERNE.** `npx @redocly/cli lint` dit « valid »
# sur ce document, et c'est ainsi qu'il a été éprouvé — mais une barrière qui
# tire un paquet du réseau à chaque exécution échoue le jour où le réseau est
# absent, et ce n'est pas une faute du code.
set -uo pipefail
export LC_ALL=C

depot=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$depot"

COMMITE="docs/openapi.json"
TEMPORAIRE=$(mktemp -t openapi.XXXXXX)
trap 'rm -f "$TEMPORAIRE"' EXIT

dire() { printf '  %s\n' "$*"; }

echo
echo "── le document engendré ───────────────────────────────────────────────"

if ! cargo build --quiet -p ams-admin 2>&1 | tail -5; then
    echo "ÉCHEC : \`ams-admin\` ne compile pas." >&2
    exit 1
fi

binaire="target/debug/air-mail-admin"
[ -x "$binaire" ] || binaire="target/release/air-mail-admin"
if [ ! -x "$binaire" ]; then
    echo "ÉCHEC : \`air-mail-admin\` est introuvable." >&2
    exit 1
fi

if ! "$binaire" openapi > "$TEMPORAIRE"; then
    echo "ÉCHEC : \`air-mail-admin openapi\` a refusé d'écrire." >&2
    exit 1
fi
dire "engendré : $(wc -l < "$TEMPORAIRE" | tr -d ' ') lignes, $(wc -c < "$TEMPORAIRE" | tr -d ' ') octets"

if [ ! -f "$COMMITE" ]; then
    echo
    echo "ÉCHEC : \`$COMMITE\` n'existe pas. Posez-le :" >&2
    echo "    $binaire openapi > $COMMITE" >&2
    exit 1
fi

if ! diff -u "$COMMITE" "$TEMPORAIRE" > /dev/null; then
    echo
    echo "ÉCHEC : \`$COMMITE\` n'est plus celui que le code engendre."
    echo
    diff -u "$COMMITE" "$TEMPORAIRE" | head -60 | sed 's/^/    /'
    echo
    echo "    Une route, une méthode ou une portée a changé. Si c'est voulu :"
    echo "        $binaire openapi > $COMMITE"
    echo "    puis relisez le \`diff\` : c'est le contrat de l'API qui bouge."
    exit 1
fi
dire "identique au commité"

echo
echo "── ce que le document dit ─────────────────────────────────────────────"

python3 -I - "$COMMITE" <<'PY'
import json
import sys

chemin = sys.argv[1]
with open(chemin, encoding="utf-8") as fichier:
    document = json.load(fichier)

fautes = []


def exiger(condition, message):
    if not condition:
        fautes.append(message)


exiger(document.get("openapi") == "3.1.0", "la version d'OpenAPI n'est pas 3.1.0")
exiger(bool(document.get("info", {}).get("version")), "la version du serveur n'est pas dite")
exiger(bool(document.get("paths")), "aucun chemin n'est décrit")

VERBES = {"get", "head", "post", "put", "delete", "patch", "options"}

identifiants = {}
operations = 0
for chemin_api, bloc in document["paths"].items():
    exiger(chemin_api.startswith("/v1/"), f"{chemin_api} ne commence pas par /v1/")
    declares = {
        parametre["name"]
        for parametre in bloc.get("parameters", [])
        if "name" in parametre
    }
    attendus = {
        morceau.split("}")[0]
        for morceau in chemin_api.split("{")[1:]
    }
    exiger(
        declares == attendus,
        f"{chemin_api} : paramètres déclarés {sorted(declares)} ≠ {sorted(attendus)}",
    )
    verbes = {cle for cle in bloc if cle in VERBES}
    exiger(bool(verbes), f"{chemin_api} ne sert aucune méthode")
    exiger("options" in verbes, f"{chemin_api} ne décrit pas OPTIONS")
    for verbe in verbes:
        operations += 1
        operation = bloc[verbe]
        identifiant = operation.get("operationId")
        exiger(bool(identifiant), f"{chemin_api} {verbe} : pas d'operationId")
        if identifiant in identifiants:
            fautes.append(
                f"l'operationId {identifiant} sert deux fois : {identifiants[identifiant]} et {chemin_api} {verbe}"
            )
        identifiants[identifiant] = f"{chemin_api} {verbe}"
        exiger(bool(operation.get("summary")), f"{chemin_api} {verbe} : pas de résumé")
        exiger(bool(operation.get("responses")), f"{chemin_api} {verbe} : pas de réponse")
        exiger(
            "default" in operation.get("responses", {}),
            f"{chemin_api} {verbe} : pas de réponse par défaut",
        )


# Toute référence interne aboutit-elle ?
def references(noeud):
    if isinstance(noeud, dict):
        for cle, valeur in noeud.items():
            if cle == "$ref" and isinstance(valeur, str):
                yield valeur
            else:
                yield from references(valeur)
    elif isinstance(noeud, list):
        for element in noeud:
            yield from references(element)


for reference in set(references(document)):
    exiger(reference.startswith("#/"), f"{reference} n'est pas une référence interne")
    noeud = document
    for morceau in reference.removeprefix("#/").split("/"):
        noeud = noeud.get(morceau) if isinstance(noeud, dict) else None
        if noeud is None:
            fautes.append(f"{reference} ne mène à rien")
            break

# Un composant déclaré sans être référencé est du document mort.
utilisees = set(references(document))
for famille in ("parameters", "schemas", "responses"):
    for nom in document.get("components", {}).get(famille, {}):
        exiger(
            f"#/components/{famille}/{nom}" in utilisees,
            f"le composant {famille}/{nom} n'est référencé par personne",
        )

if fautes:
    print()
    print(f"ÉCHEC : {len(fautes)} faute(s) dans le document :")
    for faute in fautes:
        print(f"    {faute}")
    raise SystemExit(1)

print(f"  JSON relu par python3 : {len(document['paths'])} chemins, {operations} opérations")
print(f"  {len(identifiants)} operationId, tous distincts")
print("  toutes les références internes aboutissent")
print("  aucun composant orphelin")
PY

verdict=$?
echo
if [ "$verdict" -ne 0 ]; then
    echo "ÉCHEC : le document ne tient pas ses invariants."
    exit 1
fi

echo "OK : \`$COMMITE\` est celui que le code engendre, et il tient."
