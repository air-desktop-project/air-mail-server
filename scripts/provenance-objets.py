#!/usr/bin/env python3
"""Critère 3 de C4 — la provenance d'un objet se MESURE, elle ne se déduit pas du chemin.

# Ce que ce fichier remplace, et pourquoi

Le critère 3 cherchait des `.o`/`.a` sous ``target/<profil>/build/<paquet>/<empreinte>/out/``
et concluait « compilé par un script de construction ». La prémisse était qu'un tel chemin
n'appartenait qu'aux scripts de construction. **Elle ne tient plus** : le cargo du
``nightly-2026-08-15`` y range aussi des artefacts de rustc. Relevé le 2026-10-09 sur
``asl-client-ffi`` — dont la cible ``staticlib`` y atterrit sans qu'aucun ``build.rs``
n'existe dans la crate —, le gate accusait une archive produite par rustc.

L'en-tête de ``check-sans-c.sh`` disait déjà la leçon, apprise une première fois quand le
contrôle balayait tout ``target/`` et dénonçait l'incrémental de rustc : *« Un contrôle qui
accuse le compilateur du langage qu'il protège est pire qu'absent : on apprend à ignorer son
verdict. »* Le même défaut était revenu par la porte de côté, parce que le critère reposait
encore sur un **emplacement**.

On lit donc la section ``.comment`` de chaque objet, que le compilateur producteur y écrit
lui-même : ``rustc version …``, ``GCC: …``, ``clang version …``. C'est une mesure sur
l'artefact, pas une présomption sur son rangement.

# Ce que la mesure a révélé, et qui change ce que C4 peut affirmer

Sur les **887** membres de ``libasl_client_ffi.a`` : **852 portent ``rustc version``**, et
**35 portent ``clang version 23.1.0git``**. Ces 35 sont les intrinsèques de ``compiler-rt``
(``absvdi2``, ``muldc3``, ``popcountdi2``…) que **la toolchain elle-même livre** dans
``libcompiler_builtins-*.rlib`` du sysroot — mêmes noms de membres, même préfixe de hachage.

**Aucune crate tierce ne les introduit, et aucune `staticlib` Rust n'en est exempte.** C4
interdit qu'une crate tierce compile ou lie du C ; il ne peut pas interdire le socle que
rustc pose sous tout programme Rust. Ces objets sont donc **exemptés par ORIGINE, au sens
strict** : on relève les membres du ``compiler_builtins`` du sysroot et on compare les
**empreintes SHA-256**. Un objet n'est accepté que s'il est *octet pour octet* celui que la
toolchain livre.

Écrit d'abord en comparant les NOMS, ce critère acceptait un objet GCC renommé
``45c91108d938afe8-popcountdi2.o`` — éprouvé, trouvé faux, corrigé. Un contrôle dont
l'exemption se laisse obtenir en renommant un fichier n'est pas une barrière.

# Fermé par défaut

Un objet dont la provenance ne peut pas être établie — pas de section ``.comment``, ou
``readelf`` indisponible — est une **VIOLATION**, pas un doute accordé au prévenu. Une
barrière de doctrine qui ne sait pas conclure doit refuser, sinon elle laisse passer
précisément ce qu'elle existe pour arrêter.
"""

# Fichier PARTAGÉ par trois dépôts — ``air-service-locator-client``,
# ``air-service-locator-server`` et ``air-mail-server``. Les trois portaient le même
# critère fautif, et leurs copies de ``check-sans-c.sh`` avaient déjà divergé une fois.
# **Toute correction faite ici est due dans les deux autres**, le jour où elle est faite.

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

# Ce que `.comment` écrit quand le producteur est rustc.
MARQUE_RUSTC = re.compile(r"rustc version")
# Les producteurs que l'on sait nommer dans un message d'échec.
MARQUE_C = re.compile(r"GCC:|clang version")


def sortie(commande: list[str]) -> str | None:
    """Rend la sortie standard de `commande`, ou `None` si elle a échoué."""
    try:
        acheve = subprocess.run(commande, capture_output=True, text=True, check=False)
    except OSError:
        return None
    if acheve.returncode != 0:
        return None
    return acheve.stdout


def objets_de_la_toolchain() -> set[str]:
    """Empreintes SHA-256 des membres des `libcompiler_builtins*.rlib` du sysroot.

    C'est l'exemption par ORIGINE au sens strict : on accepte un objet parce qu'il est
    **octet pour octet** celui que la toolchain livre, pas parce qu'il en porte le nom.
    Une première version comparait les NOMS — un objet GCC renommé
    `45c91108d938afe8-popcountdi2.o` passait alors la barrière. Mesuré, et refusé depuis.
    """
    sysroot = sortie(["rustc", "--print", "sysroot"])
    if sysroot is None:
        return set()
    empreintes: set[str] = set()
    for rlib in pathlib.Path(sysroot.strip()).rglob("libcompiler_builtins*.rlib"):
        liste = sortie(["ar", "t", str(rlib)])
        if liste is None:
            continue
        noms = [l.strip() for l in liste.splitlines() if l.strip().endswith(".o")]
        if not noms:
            continue
        with tempfile.TemporaryDirectory() as temporaire:
            extrait = subprocess.run(
                ["ar", "x", "--output", temporaire, str(rlib.resolve())],
                capture_output=True,
                text=True,
                check=False,
            )
            if extrait.returncode != 0:
                continue
            for nom in noms:
                membre = pathlib.Path(temporaire) / nom
                if membre.is_file():
                    empreintes.add(empreinte(membre))
    return empreintes


def empreinte(chemin: pathlib.Path) -> str:
    """SHA-256 du fichier, en hexadécimal."""
    return hashlib.sha256(chemin.read_bytes()).hexdigest()


def producteur(chemin: pathlib.Path) -> str | None:
    """Rend la ligne `.comment` de l'objet, ou `None` si elle est absente/illisible."""
    brut = sortie(["readelf", "-p", ".comment", str(chemin)])
    if brut is None:
        return None
    for ligne in brut.splitlines():
        if MARQUE_RUSTC.search(ligne) or MARQUE_C.search(ligne):
            return ligne.strip().split("]", 1)[-1].strip()
    return None


def juger(nom: str, chemin: pathlib.Path, exemptes: set[str]) -> str | None:
    """Rend `None` si l'objet est acceptable, sinon la raison du refus."""
    marque = producteur(chemin)
    if marque is not None and MARQUE_RUSTC.search(marque):
        return None
    if empreinte(chemin) in exemptes:
        # Octet pour octet un objet `compiler-rt` livré par la toolchain : hors de portée
        # de C4, qui vise les crates TIERCES. Le nom ne joue aucun rôle.
        return None
    if marque is None:
        return f"{nom} — provenance indéterminable (aucune section `.comment` lisible)"
    return f"{nom} — compilé par {marque}"


def membres_archive(archive: pathlib.Path, exemptes: set[str]) -> list[str]:
    """Juge chaque membre d'une archive, dans un répertoire temporaire."""
    liste = sortie(["ar", "t", str(archive)])
    if liste is None:
        return [f"{archive} — archive illisible par `ar`"]
    noms = [ligne.strip() for ligne in liste.splitlines() if ligne.strip().endswith(".o")]
    if not noms:
        return []
    refus: list[str] = []
    with tempfile.TemporaryDirectory() as temporaire:
        extrait = subprocess.run(
            ["ar", "x", "--output", temporaire, str(archive.resolve())],
            capture_output=True,
            text=True,
            check=False,
        )
        if extrait.returncode != 0:
            return [f"{archive} — extraction impossible : {extrait.stderr.strip()}"]
        for nom in noms:
            sous = pathlib.Path(temporaire) / nom
            if not sous.is_file():
                refus.append(f"{archive}({nom}) — membre absent après extraction")
                continue
            raison = juger(nom, sous, exemptes)
            if raison is not None:
                refus.append(f"{archive}({raison})")
    return refus


def candidats_sous_out() -> list[pathlib.Path]:
    """Les `.o`/`.a` situés sous un `out/` lui-même sous un `build/`.

    Reprend la sémantique du `find -path '*/build/*/out/*'` qu'on remplace — dont le `*`
    franchit les séparateurs, et attrape donc aussi bien `build/<pkg>/out/` que
    `build/<pkg>/<empreinte>/out/`. Un motif `glob` naïf manque la seconde forme, qui est
    précisément celle que cargo emploie : écrit d'abord ainsi, ce contrôle ne trouvait
    RIEN et rendait vert.
    """
    trouves: list[pathlib.Path] = []
    for racine, _, fichiers in os.walk("target"):
        parties = pathlib.Path(racine).parts
        if "build" not in parties:
            continue
        indice = parties.index("build")
        if "out" not in parties[indice + 1 :]:
            continue
        for fichier in fichiers:
            if fichier.endswith((".o", ".a")):
                trouves.append(pathlib.Path(racine) / fichier)
    return trouves


def main() -> int:
    if shutil.which("readelf") is None or shutil.which("ar") is None:
        print("VIOLATION  `readelf` ou `ar` indisponible — la provenance ne peut pas être")
        print("           mesurée, et un critère qui ne mesure pas ne conclut pas.")
        return 1

    exemptes = objets_de_la_toolchain()
    if not exemptes:
        print("VIOLATION  aucun `libcompiler_builtins*.rlib` trouvé dans le sysroot —")
        print("           l'exemption par origine ne peut pas être établie.")
        return 1

    candidats = sorted(candidats_sous_out())

    refus: list[str] = []
    archives = objets = 0
    for candidat in candidats:
        if candidat.suffix == ".a":
            archives += 1
            refus.extend(membres_archive(candidat, exemptes))
        else:
            objets += 1
            raison = juger(candidat.name, candidat, exemptes)
            if raison is not None:
                refus.append(f"{candidat.parent}/{raison}")

    if refus:
        print("VIOLATION  des objets que rustc n'a pas produits :")
        for raison in refus[:20]:
            print(f"           {raison}")
        if len(refus) > 20:
            print(f"           … et {len(refus) - 20} autre(s)")
        return 1

    if archives == 0 and objets == 0:
        print("aucun objet sous la sortie d'un script de construction")
        return 0

    print(
        f"provenance mesurée : {archives} archive(s) et {objets} objet(s) examinés, "
        "tous produits par rustc"
    )
    print(
        f"           (exemption par origine : {len(exemptes)} empreintes `compiler-rt` "
        "livrées par la toolchain)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
