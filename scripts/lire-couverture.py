"""Réduit le rapport JSON de `cargo llvm-cov` à quatre lignes lisibles.

Vit dans son propre fichier plutôt qu'embarqué dans `check-couverture.sh` : la
version embarquée était enfermée dans une chaîne shell entre guillemets simples,
et ne pouvait donc pas en contenir un seul. Un f-string a suffi à la casser.

Sortie, une ligne par mesure :  <mesure> <total> <couvert> <pourcentage>
"""

import json
import sys

MESURES = ("regions", "lines", "branches", "functions")


def main() -> None:
    rapport = json.load(sys.stdin)
    totaux = rapport["data"][0]["totals"]
    for cle in MESURES:
        mesure = totaux.get(cle, {})
        total = mesure.get("count", 0)
        couvert = mesure.get("covered", 0)
        # Le pourcentage est arrondi ICI, et non par `printf`, dont le format
        # flottant dépend de la locale de qui lance le script.
        pourcent = mesure.get("percent", 0.0)
        # Une mesure VIDE ne vaut pas « 0,00 % » : un pourcentage sur un ensemble
        # vide n'est pas une mesure, et l'afficher comme telle ferait croire à un
        # échec là où il n'y a rien.
        affiche = "{:.2f}".format(pourcent) if total else "-"
        print(cle, total, couvert, affiche)


if __name__ == "__main__":
    main()
