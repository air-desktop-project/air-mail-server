#!/usr/bin/env python3
"""renommer-dossiers.py — traduire les noms de dossiers de Dovecot vers ceux
d'air-mail-server.

# LE DÉFAUT QUE CE SCRIPT EXISTE POUR NE PAS COMMETTRE

Les deux serveurs rangent les dossiers en Maildir++ — un répertoire par dossier,
préfixé d'un point, la hiérarchie marquée par d'autres points. Mais ils
n'encodent PAS le nom de la même façon :

    Dovecot          .&AMk-t&AOk--2025       (UTF-7 modifié, RFC 3501 §5.1.3)
    air-mail-server  .Été-2025               (UTF-8)

Copié tel quel, un dossier accentué ressort chez le client sous son nom ENCODÉ :
« Été-2025 » devient « &AMk-t&AOk--2025 ». Le courrier est là, le dossier est là,
mais il porte un nom illisible — et l'utilisateur ne retrouve plus ses affaires.

Pour un domaine francophone — « Éléments envoyés », « Reçus », « Archivé » — ce
n'est pas un cas limite, c'est le cas courant.

Mesuré le 2026-09-07 : `air-mail-server` a écrit `.Été-2025bis` sur le disque
quand un client lui a demandé de créer `&AMk-t&AOk--2025bis`. Son IMAP est
juste ; c'est la convention DE STOCKAGE qui diffère.

# ET LES ABONNEMENTS, QUI SE PERDENT AUSSI

Dovecot les écrit dans `subscriptions`, air-mail-server dans `ams-abonnements`.
Le format est le même — un nom par ligne — mais la convention diffère de la même
façon, et sur un point de plus :

    Dovecot          Sent.2024        &AMk-t&AOk--2025    (séparateur `.`)
    air-mail-server  Sent/2024        Été-2025            (séparateur `/`)

Sans conversion, `LSUB` ne rend rien. Les clients qui n'affichent QUE les
dossiers abonnés — c'est le réglage par défaut de plusieurs — les montreraient
tous disparus, alors que le courrier est là.

# CE QU'IL FAIT

Il parcourt la racine des boîtes, renomme chaque répertoire `.<nom>` dont le nom
porte de l'UTF-7 modifié, et traduit `subscriptions` en `ams-abonnements`. Les
noms purement ASCII ne sont pas touchés.

Sans `--pour-de-vrai`, il n'écrit RIEN et dit ce qu'il ferait.

USAGE
    python3 renommer-dossiers.py <racine-maildir> [--pour-de-vrai]
"""

import base64
import os
import sys


def depuis_utf7_modifie(nom: str) -> str:
    """Décode l'UTF-7 modifié de RFC 3501 §5.1.3.

    Il diffère de l'UTF-7 ordinaire sur deux points : le caractère d'échappement
    est `&` au lieu de `+`, et l'alphabet base64 emploie `,` au lieu de `/`.
    `&-` désigne un `&` littéral.
    """
    if "&" not in nom:
        return nom
    sortie = []
    i = 0
    while i < len(nom):
        if nom[i] != "&":
            sortie.append(nom[i])
            i += 1
            continue
        fin = nom.find("-", i + 1)
        if fin == -1:
            # Une séquence non terminée n'est pas de l'UTF-7 modifié valide.
            # On rend le nom TEL QUEL plutôt que d'inventer : renommer sur une
            # supposition ferait perdre le dossier.
            return nom
        morceau = nom[i + 1 : fin]
        if morceau == "":
            sortie.append("&")  # `&-` est un `&` littéral
        else:
            try:
                sortie.append((("+" + morceau.replace(",", "/") + "-")).encode(
                    "ascii"
                ).decode("utf-7"))
            except (UnicodeDecodeError, UnicodeEncodeError):
                return nom
        i = fin + 1
    return "".join(sortie)


def _encoder_utf7_modifie(nom: str) -> str:
    """L'encodage de RFC 3501 §5.1.3 — POUR LES ESSAIS SEULEMENT.

    Écrit INDÉPENDAMMENT de `depuis_utf7_modifie`, et ne partageant aucune ligne
    avec lui. C'est ce qui donne sa valeur à l'aller-retour : deux
    implémentations qui se tromperaient de la même façon passeraient quand même
    si l'une dérivait de l'autre.
    """
    sortie: list[str] = []
    tampon: list[str] = []

    def vider() -> None:
        if tampon:
            octets = "".join(tampon).encode("utf-16-be")
            b64 = base64.b64encode(octets).decode("ascii").rstrip("=")
            sortie.append("&" + b64.replace("/", ",") + "-")
            tampon.clear()

    for caractere in nom:
        if caractere == "&":
            vider()
            sortie.append("&-")
        elif 0x20 <= ord(caractere) <= 0x7E:
            vider()
            sortie.append(caractere)
        else:
            tampon.append(caractere)
    vider()
    return "".join(sortie)


def est_un_entete_dovecot(ligne: str) -> bool:
    """La ligne est-elle l'en-tête de version d'un `subscriptions` Dovecot ?

    Le format est `V`, une TABULATION, un entier. On exige les trois : une boîte
    qui s'appellerait vraiment `V` — improbable mais permis — ne doit pas
    disparaître parce qu'elle est en première ligne.
    """
    if not ligne.startswith("V\t"):
        return False
    return ligne[2:].strip().isdigit()


def essais() -> int:
    """Éprouve le décodeur, et rend le nombre de fautes.

    # POURQUOI CES ESSAIS EXISTENT

    `depuis_utf7_modifie` est écrit à la main, sur un encodage tordu, et il
    décide du NOM QUE L'UTILISATEUR VERRA. Une faute n'y produit pas une erreur :
    elle produit un dossier qui s'appelle « &AMk-l&AOk-ments envoy&AOk-s » chez
    le client, et personne ne saura d'où ça vient.

    # ET LA PREMIÈRE ÉCRITURE DE CES ESSAIS ÉTAIT FAUSSE

    Elle attendait `Re&AME-us` pour « Reçus », encodage inventé à la main plutôt
    que calculé. `&AME-` vaut `Á` (U+00C1) ; « Reçus » s'écrit `Re&AOc-us`. Le
    décodeur avait raison, l'essai avait tort — d'où l'aller-retour contre un
    encodeur, qui ne laisse rien à inventer.
    """
    fautes = 0

    # ── L'aller-retour, sur ce qu'un domaine francophone porte réellement ───
    noms = [
        "INBOX", "Sent", "Drafts.2025",
        "Été-2025", "Éléments envoyés", "Reçus", "Archivé", "Brouillons",
        "Œuvres", "Année 2024", "Ça marche", "À trier", "Noël",
        "Recherche & développement", "&", "&&", "a&b",
        "台北", "日本語", "Ελληνικά", "Привет",
        "Facturé — 2025", "Résumé…", "naïve",
    ]
    for nom in noms:
        revenu = depuis_utf7_modifie(_encoder_utf7_modifie(nom))
        if revenu != nom:
            print(f"FAUTE aller-retour : {nom!r} → {revenu!r}", file=sys.stderr)
            fautes += 1

    # ── Les deux exemples qu'on n'a pas inventés ────────────────────────────
    litteraux = [
        # RFC 3501 §5.1.3, l'exemple de la RFC elle-même.
        ("~peter/mail/&U,BTFw-/&ZeVnLIqe-", "~peter/mail/台北/日本語"),
        # Ce que Dovecot écrit RÉELLEMENT sur `mail.narro.ch`.
        ("&AMk-t&AOk--2025", "Été-2025"),
    ]
    for brut, attendu in litteraux:
        vu = depuis_utf7_modifie(brut)
        if vu != attendu:
            print(f"FAUTE littérale : {brut!r} → {vu!r} au lieu de {attendu!r}",
                  file=sys.stderr)
            fautes += 1

    # ── ET CE QU'ON REFUSE DE DEVINER ──────────────────────────────────────
    #
    # Une séquence non terminée, ou du base64 illisible, n'est pas de l'UTF-7
    # modifié valide. Le décodeur rend alors le nom TEL QUEL : renommer sur une
    # supposition ferait PERDRE le dossier, et un nom laissé tel quel se voit.
    for abime in ["&AMk", "&", "&AMk-t&AOk", "&!!!-", "&&&-"]:
        if depuis_utf7_modifie(abime) != abime:
            print(f"FAUTE : {abime!r} aurait dû être rendu tel quel", file=sys.stderr)
            fautes += 1

    # ── L'EN-TÊTE DE DOVECOT N'EST PAS UN DOSSIER ───────────────────────────
    #
    # Trouvé sur la machine de narro.ch le 2026-09-08 : `subscriptions` commence
    # par `V<TAB>2`, que le script prenait pour une boîte. L'abonnement fantôme
    # ne fait rien tomber — il désigne une boîte qui n'existe pas — mais il est
    # faux, et ce qui est faux sans bruit est ce qu'on ne corrige jamais.
    entetes = [("V\t2\n", True), ("V\t1\n", True), ("V\t12\n", True)]
    pas_des_entetes = [
        ("Sent\n", False),
        ("V\n", False),              # un `V` seul est une boîte nommée `V`
        ("V\tdeux\n", False),        # pas un entier : on ne devine pas
        ("Ventes\n", False),
        ("\tV\t2\n", False),         # décalé : ce n'est plus l'en-tête
    ]
    for ligne, attendu in entetes + pas_des_entetes:
        vu = est_un_entete_dovecot(ligne)
        if vu != attendu:
            print(f"FAUTE : est_un_entete_dovecot({ligne!r}) = {vu}, attendu {attendu}",
                  file=sys.stderr)
            fautes += 1

    # ── DE BOUT EN BOUT : LE FICHIER ÉCRIT EST-IL UTILISABLE ? ──────────────
    #
    # Le décodeur peut être juste et le résultat inexploitable. Les deux défauts
    # trouvés sur la machine de narro.ch le 2026-09-08 ne se voyaient QUE par un
    # essai qui écrit vraiment : l'en-tête `V<TAB>2` pris pour une boîte, et le
    # fichier écrit à `root` donc illisible par le compte de service. Un banc
    # qui n'éprouve que la traduction laisse passer les deux.
    import subprocess, tempfile
    with tempfile.TemporaryDirectory() as banc:
        boite = os.path.join(banc, "essai")
        os.makedirs(os.path.join(boite, ".Sent", "cur"))
        # **LA BOÎTE PREND UN GROUPE QUI N'EST PAS LE NÔTRE PAR DÉFAUT**, sans
        # quoi l'essai ne prouve rien : un fichier créé par ce processus hérite
        # déjà du bon propriétaire, et l'assertion passerait même si le script
        # ne posait aucune appartenance. C'est ce qu'une mutation a montré.
        autre_groupe = next(
            (g for g in os.getgroups() if g != os.getgid()), None
        )
        if autre_groupe is not None:
            os.chown(boite, os.getuid(), autre_groupe)
        with open(os.path.join(boite, "subscriptions"), "w", encoding="utf-8") as f:
            f.write("V\t2\n\nSent\nDrafts\n&AMk-t&AOk--2025\n")
        subprocess.run(
            [sys.executable, __file__, banc, "--pour-de-vrai"],
            check=True, capture_output=True,
        )
        ecrit = os.path.join(boite, "ams-abonnements")
        lignes = open(ecrit, encoding="utf-8").read().splitlines()
        if lignes != ["Sent", "Drafts", "Été-2025"]:
            print(f"FAUTE : abonnements écrits = {lignes!r}", file=sys.stderr)
            fautes += 1
        st, parent = os.stat(ecrit), os.stat(boite)
        if (st.st_uid, st.st_gid) != (parent.st_uid, parent.st_gid):
            print("FAUTE : le fichier n'a pas l'appartenance de la boîte "
                  f"({st.st_uid}:{st.st_gid} au lieu de "
                  f"{parent.st_uid}:{parent.st_gid})", file=sys.stderr)
            fautes += 1
        elif autre_groupe is None:
            print("NOTE : un seul groupe pour cet utilisateur — l'appartenance "
                  "n'a pas pu être éprouvée de façon discriminante.",
                  file=sys.stderr)
        if st.st_mode & 0o777 != 0o600:
            print(f"FAUTE : mode {st.st_mode & 0o777:o}, attendu 600", file=sys.stderr)
            fautes += 1

    if fautes == 0:
        print(f"OK : {len(noms)} allers-retours, {len(litteraux)} littéraux, "
              "et ce qu'on refuse de deviner.")
    return fautes


def main() -> int:
    if "--essais" in sys.argv[1:]:
        return 1 if essais() else 0

    # ── LE MODE FILTRE ──────────────────────────────────────────────────────
    #
    # **UNE SEULE DÉFINITION DE « LE MÊME DOSSIER ».** Après le renommage, les
    # deux magasins nomment le même dossier différemment : `.&AMk-t&AOk--2025`
    # d'un côté, `.Été-2025` de l'autre. `verifier.sh` et `rapatrier.sh` les
    # comparent — et sans traduction, l'un croit qu'un dossier a DISPARU et
    # l'autre recopie son contenu dans un dossier neuf, ce qui le duplique aux
    # yeux de l'utilisateur.
    #
    # Ils passent donc leurs noms par ici. Deux décodeurs finiraient par ne plus
    # dire la même chose, et la divergence serait invisible.
    if "--traduire" in sys.argv[1:]:
        for ligne in sys.stdin:
            print(depuis_utf7_modifie(ligne.rstrip("\n")))
        return 0
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    racine = sys.argv[1]
    pour_de_vrai = "--pour-de-vrai" in sys.argv[2:]
    if not os.path.isdir(racine):
        print(f"racine introuvable : {racine}", file=sys.stderr)
        return 1

    a_renommer = []
    for compte in sorted(os.listdir(racine)):
        boite = os.path.join(racine, compte)
        if not os.path.isdir(boite):
            continue
        for entree in sorted(os.listdir(boite)):
            if not entree.startswith(".") or entree in (".", ".."):
                continue
            chemin = os.path.join(boite, entree)
            if not os.path.isdir(chemin):
                continue
            # Le point de tête est le préfixe Maildir++, pas une partie du nom.
            traduit = "." + depuis_utf7_modifie(entree[1:])
            if traduit != entree:
                a_renommer.append((compte, chemin, os.path.join(boite, traduit)))

    # ── Les abonnements ─────────────────────────────────────────────────────
    abonnements = []
    for compte in sorted(os.listdir(racine)):
        boite = os.path.join(racine, compte)
        source = os.path.join(boite, "subscriptions")
        cible = os.path.join(boite, "ams-abonnements")
        if not os.path.isfile(source):
            continue
        if os.path.exists(cible):
            print(
                f"  {compte} : `ams-abonnements` existe déjà — laissé tel quel",
                file=sys.stderr,
            )
            continue
        lignes = []
        with open(source, encoding="utf-8", errors="replace") as fichier:
            for rang, ligne in enumerate(fichier):
                nom = ligne.strip()
                if not nom:
                    continue
                # **LA PREMIÈRE LIGNE PEUT ÊTRE UN EN-TÊTE, PAS UN DOSSIER.**
                # Dovecot 2.x écrit `V<TAB>2` en tête de `subscriptions` ; les
                # versions plus anciennes n'écrivent rien. Pris pour un nom de
                # boîte, cet en-tête donnait un abonnement fantôme à une boîte
                # qui n'existe pas — trouvé sur la machine de narro.ch le
                # 2026-09-08, pendant la phase 0.
                if rang == 0 and est_un_entete_dovecot(ligne):
                    continue
                # Le séparateur de Maildir++ est le point ; celui de ce
                # serveur, la barre. L'alphabet de l'UTF-7 modifié ne porte
                # aucun point, la substitution est donc sans ambiguïté.
                lignes.append(depuis_utf7_modifie(nom).replace(".", "/"))
        if lignes:
            abonnements.append((compte, cible, lignes))

    if not a_renommer and not abonnements:
        print("Rien à faire : les noms sont lisibles et les abonnements sont là.")
        return 0

    for compte, cible, lignes in abonnements:
        print(f"  {compte} : {len(lignes)} abonnement(s) → {os.path.basename(cible)}")
        for nom in lignes:
            print(f"       {nom}")

    for compte, avant, apres in a_renommer:
        print(f"  {compte} : {os.path.basename(avant)}")
        print(f"       → {os.path.basename(apres)}")
        if os.path.exists(apres):
            print(
                f"ARRÊT : `{apres}` existe déjà. Renommer écraserait un dossier.",
                file=sys.stderr,
            )
            return 1

    print(
        f"\n{len(a_renommer)} dossier(s) à renommer, "
        f"{len(abonnements)} fichier(s) d'abonnements à traduire."
    )
    if not pour_de_vrai:
        print("\nRIEN N'A ÉTÉ ÉCRIT. Relancez avec --pour-de-vrai.")
        return 0

    for _, avant, apres in a_renommer:
        os.rename(avant, apres)
    for _, cible, lignes in abonnements:
        with open(cible, "w", encoding="utf-8") as fichier:
            for nom in lignes:
                fichier.write(nom + "\n")
        os.chmod(cible, 0o600)
        # **LE FICHIER PREND LE PROPRIÉTAIRE DE LA BOÎTE, ET NON CELUI QUI LANCE.**
        # Ce script tourne sous `sudo` : sans cela le fichier naît à `root` en
        # 0600, donc ILLISIBLE par le compte de service — et les abonnements
        # restent invisibles, ce qui est exactement le défaut qu'on répare ici.
        # On copie l'appartenance du répertoire du compte plutôt que de nommer
        # un utilisateur : le script n'a pas à savoir comment il s'appelle.
        parent = os.stat(os.path.dirname(cible))
        try:
            os.chown(cible, parent.st_uid, parent.st_gid)
        except PermissionError:
            print(
                f"AVERTISSEMENT : `{cible}` reste à l'utilisateur courant — "
                "le compte de service ne le lira pas. Relancez sous `sudo`.",
                file=sys.stderr,
            )
    print("Fait.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
