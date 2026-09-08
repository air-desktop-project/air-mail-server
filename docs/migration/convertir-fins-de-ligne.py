#!/usr/bin/env python3
"""LF → CRLF dans une copie de Maildir, avant qu'air-mail-server n'y touche.

# POURQUOI CE SCRIPT EXISTE

**Les deux serveurs ne stockent pas les messages de la même façon.** Dovecot
écrit des fins de ligne `LF` nues — c'est son défaut, `mail_save_crlf = no` —
tandis qu'air-mail-server écrit du `CRLF`, comme le veut la RFC 5322 sur le fil.

`ams-mime` refuse un `LF` isolé, et c'est délibéré : sur le fil, un message qui
en porte n'est pas « réparé », il ne part pas. Mais **un fichier Maildir n'est
pas du fil**, et le décodeur ne trouve alors pas la ligne vide qui sépare les
en-têtes du corps.

Mesuré le 2026-09-08 sur la machine de narro.ch, en phase 0, sur les 573
messages réels :

    FETCH 1 (ENVELOPE)   → ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)
    FETCH 1 (BODY[TEXT]) → {0}
    FETCH 1 (BODY[HEADER]) → 101864 octets, soit le message ENTIER

Autrement dit : **ni expéditeur, ni sujet, ni date, ni corps**. Les cinq boîtes
se seraient ouvertes sur des lignes blanches, et `verifier.sh` aurait dit « OK,
aucun écart » — il compte des fichiers, il ne les lit pas.

Le même serveur, au même instant, sur un message écrit en CRLF, rend une
enveloppe complète et son corps. La seule différence est la fin de ligne.

# L'ORACLE EST DANS LE NOM DU FICHIER, ET IL VIENT DE DOVECOT

Dovecot nomme ses messages ainsi :

    1788338183.M777963P781764.vps-9d275e3a,S=101864,W=103463:2,S
                                             │         │
                       taille du fichier ────┘         └──── taille RFC822,
                              (LF nu)                        c'est-à-dire AVEC CRLF

**`W=` est exactement la taille que le fichier aura après conversion.** On ne se
contente donc pas de convertir : on VÉRIFIE, message par message, contre un
nombre calculé par l'autre serveur. Un écart d'un seul octet arrête tout.

# CE SCRIPT PASSE AVANT LA PREMIÈRE ADOPTION, ET CE N'EST PAS UN DÉTAIL

air-mail-server réécrit les noms quand il adopte une boîte venue d'ailleurs : il
lit la taille par `stat`, l'inscrit dans son propre `,S=`, et **c'est ce nom qui
fait foi ensuite** — la taille servie ne vient pas d'un `stat` par message.
Convertir APRÈS l'adoption laisserait donc un `S=` qui ment de la longueur d'un
message. L'ordre est : `rsync`, puis CE script, puis le premier démarrage.

# USAGE

    python3 convertir-fins-de-ligne.py --essais
    python3 convertir-fins-de-ligne.py /var/vmail-ams              # à blanc
    python3 convertir-fins-de-ligne.py /var/vmail-ams --pour-de-vrai

Il est IDEMPOTENT : un message déjà en CRLF n'est pas touché, et le relancer ne
double rien.
"""

import os
import re
import sys
import tempfile

# `,W=<nombre>` dans la partie unique du nom, tel que Dovecot l'écrit.
W = re.compile(rb",W=(\d+)")


def convertir(octets: bytes) -> bytes:
    """Rend le contenu avec des CRLF, sans toucher aux CRLF déjà présents.

    **On ne fait pas `replace(b"\\n", b"\\r\\n")`** : cela doublerait les CR d'un
    message déjà converti, et le script cesserait d'être idempotent — or il sera
    relancé, ne serait-ce que par prudence le jour de la bascule.
    """
    sortie = bytearray()
    precedent = 0
    for octet in octets:
        if octet == 0x0A and precedent != 0x0D:
            sortie += b"\r\n"
        else:
            sortie.append(octet)
        precedent = octet
    return bytes(sortie)


def taille_annoncee(nom: str):
    """La taille RFC822 que Dovecot a inscrite dans le nom, ou `None`."""
    trouve = W.search(nom.encode("utf-8", "surrogateescape"))
    return int(trouve.group(1)) if trouve else None


def messages(racine: str):
    """Chaque fichier de message sous une racine de comptes.

    Les répertoires `tmp/` sont écartés : Maildir y dépose ce qui n'est pas
    encore livré, et un message qu'on convertirait pendant sa livraison serait
    un message qu'on abîme.
    """
    for compte in sorted(os.listdir(racine)):
        boite = os.path.join(racine, compte)
        if not os.path.isdir(boite):
            continue
        for dossier, _, fichiers in os.walk(boite):
            base = os.path.basename(dossier)
            if base not in ("cur", "new"):
                continue
            for nom in sorted(fichiers):
                yield compte, os.path.join(dossier, nom), nom


def main() -> int:
    arguments = [a for a in sys.argv[1:]]
    if "--essais" in arguments:
        return essais()
    pour_de_vrai = "--pour-de-vrai" in arguments
    positionnels = [a for a in arguments if not a.startswith("--")]
    if len(positionnels) != 1:
        print(__doc__.split("# USAGE")[1].strip(), file=sys.stderr)
        return 2
    racine = positionnels[0]
    if not os.path.isdir(racine):
        print(f"ÉCHEC : `{racine}` n'est pas un répertoire.", file=sys.stderr)
        return 1

    a_convertir, deja, sans_oracle, ecarts = [], 0, 0, []
    for compte, chemin, nom in messages(racine):
        with open(chemin, "rb") as fichier:
            octets = fichier.read()
        converti = convertir(octets)
        if converti == octets:
            deja += 1
            continue
        attendu = taille_annoncee(nom)
        if attendu is None:
            sans_oracle += 1
        elif len(converti) != attendu:
            ecarts.append((compte, nom, len(converti), attendu))
        a_convertir.append((chemin, converti))

    print(f"  déjà en CRLF        : {deja}")
    print(f"  à convertir         : {len(a_convertir)}")
    print(f"  sans `W=` pour vérifier : {sans_oracle}")

    if ecarts:
        print(file=sys.stderr)
        print(f"ARRÊT : {len(ecarts)} message(s) dont la taille convertie ne vaut "
              "PAS le `W=` que Dovecot annonce.", file=sys.stderr)
        for compte, nom, vu, attendu in ecarts[:5]:
            print(f"  {compte} : {nom[:50]}… → {vu} octets, `W=` dit {attendu}",
                  file=sys.stderr)
        print("Rien n'a été écrit. Ces messages ne sont pas ce que l'on croit.",
              file=sys.stderr)
        return 1

    if not a_convertir:
        print("\nRien à faire : tout est déjà en CRLF.")
        return 0

    if not pour_de_vrai:
        print("\nRIEN N'A ÉTÉ ÉCRIT. Relancez avec --pour-de-vrai.")
        return 0

    for chemin, converti in a_convertir:
        avant = os.stat(chemin)
        dossier = os.path.dirname(chemin)
        # **ÉCRITURE ATOMIQUE.** Un `open(w)` sur place laisserait, si la machine
        # s'arrête au milieu, un message tronqué que rien ne signalerait — et le
        # `W=` ne le rattraperait pas, puisqu'on ne le relit qu'ici.
        with tempfile.NamedTemporaryFile(dir=dossier, delete=False) as neuf:
            neuf.write(converti)
            provisoire = neuf.name
        os.chmod(provisoire, avant.st_mode & 0o7777)
        os.chown(provisoire, avant.st_uid, avant.st_gid)
        # **LA DATE DE MODIFICATION EST CONSERVÉE** : c'est elle qui fait
        # l'`INTERNALDATE` d'IMAP. La perdre ferait apparaître tout le courrier
        # comme arrivé le jour de la bascule, et les tris par date mentiraient.
        os.utime(provisoire, (avant.st_atime, avant.st_mtime))
        os.replace(provisoire, chemin)

    print(f"\nFait : {len(a_convertir)} message(s) convertis, "
          f"{deja} déjà en CRLF, aucun écart de taille.")
    return 0


def essais() -> int:
    """Éprouve la conversion, son idempotence, et l'oracle `W=`."""
    fautes = 0

    # ── La conversion elle-même ─────────────────────────────────────────────
    cas = [
        (b"a\nb\n", b"a\r\nb\r\n", "LF nu"),
        (b"a\r\nb\r\n", b"a\r\nb\r\n", "déjà CRLF — inchangé"),
        (b"a\r\nb\nc\r\n", b"a\r\nb\r\nc\r\n", "mélangé"),
        (b"", b"", "vide"),
        (b"sans fin de ligne", b"sans fin de ligne", "sans fin de ligne"),
        (b"\n", b"\r\n", "une seule ligne vide"),
        (b"a\r\rb", b"a\r\rb", "CR isolés — on n'invente pas de LF"),
    ]
    for entree, attendu, quoi in cas:
        vu = convertir(entree)
        if vu != attendu:
            print(f"FAUTE : {quoi} — {entree!r} → {vu!r}, attendu {attendu!r}",
                  file=sys.stderr)
            fautes += 1

    # ── L'IDEMPOTENCE, et ce n'est pas du zèle ──────────────────────────────
    #
    # Ce script sera relancé — par prudence, ou parce qu'on ne se souviendra plus
    # s'il a tourné. Un `replace(b"\n", b"\r\n")` naïf doublerait les CR au second
    # passage et abîmerait TOUS les messages, sans erreur.
    for entree, _, quoi in cas:
        une = convertir(entree)
        deux = convertir(une)
        if une != deux:
            print(f"FAUTE : non idempotent sur {quoi} — {une!r} puis {deux!r}",
                  file=sys.stderr)
            fautes += 1

    # ── L'oracle du nom de fichier ──────────────────────────────────────────
    noms = [
        ("1788338183.M777963P781764.hote,S=101864,W=103463:2,S", 103463),
        ("1788429958.M848015P795027.hote,W=140830,U=21,S=137962:2,S", 140830),
        ("1725000000.M1P2.hote,S=999:2,S", None),
        ("1725000000.M1P2.hote", None),
    ]
    for nom, attendu in noms:
        vu = taille_annoncee(nom)
        if vu != attendu:
            print(f"FAUTE : `W=` de {nom} lu {vu}, attendu {attendu}", file=sys.stderr)
            fautes += 1

    # ── DE BOUT EN BOUT, SUR UN VRAI ARBRE ──────────────────────────────────
    #
    # Le cas qui compte : un message dont le `W=` NE CORRESPOND PAS doit tout
    # arrêter, et RIEN ne doit être écrit. Un script qui convertirait quand même
    # laisserait un magasin à moitié juste, ce qui est pire qu'un magasin faux.
    import subprocess
    with tempfile.TemporaryDirectory() as banc:
        cur = os.path.join(banc, "jean", "cur")
        os.makedirs(cur)
        corps = b"From: a@b.c\nSubject: x\n\ncorps\n"          # 29 octets en LF
        converti_attendu = len(convertir(corps))               # 33 en CRLF
        bon = os.path.join(cur, f"1.M1P1.hote,S={len(corps)},W={converti_attendu}:2,S")
        with open(bon, "wb") as f:
            f.write(corps)
        # Et un menteur : son `W=` annonce n'importe quoi.
        faux = os.path.join(cur, "2.M2P2.hote,S=29,W=9999:2,S")
        with open(faux, "wb") as f:
            f.write(corps)

        r = subprocess.run([sys.executable, __file__, banc, "--pour-de-vrai"],
                           capture_output=True)
        if r.returncode == 0:
            print("FAUTE : un `W=` faux aurait dû tout arrêter", file=sys.stderr)
            fautes += 1
        if open(bon, "rb").read() != corps:
            print("FAUTE : un message a été écrit malgré l'arrêt", file=sys.stderr)
            fautes += 1

        # Le menteur retiré, la conversion passe et le contenu est juste.
        os.remove(faux)

        # **UNE DATE FRANCHEMENT ANCIENNE, ET C'EST UNE CORRECTION.** La première
        # écriture de cet essai comparait le `mtime` d'avant et d'après sans le
        # forcer : le fichier temporaire naissant dans la même seconde, l'égalité
        # était vraie MÊME SANS `utime`, et une mutation l'a montré. Une assertion
        # que l'environnement rend vraie d'office ne vérifie rien.
        jadis = 1_600_000_000  # 13 septembre 2020
        os.utime(bon, (jadis, jadis))

        # **ET UN GROUPE QUI N'EST PAS LE NÔTRE PAR DÉFAUT**, pour la même
        # raison : un fichier créé par ce processus hérite déjà du bon
        # propriétaire, si bien que l'assertion passerait même sans `chown`.
        # Le jour de la bascule le script tourne sous `sudo`, et un message
        # rendu à `root` serait ILLISIBLE par le compte de service.
        autre_groupe = next((g for g in os.getgroups() if g != os.getgid()), None)
        if autre_groupe is not None:
            os.chown(bon, os.getuid(), autre_groupe)

        # Un message dans `tmp/` : Maildir y dépose ce qui n'est pas encore livré.
        # Le convertir serait abîmer un message en cours d'écriture.
        tmp = os.path.join(banc, "jean", "tmp")
        os.makedirs(tmp)
        en_cours = os.path.join(tmp, "3.M3P3.hote")
        with open(en_cours, "wb") as f:
            f.write(corps)

        rapport = subprocess.run([sys.executable, __file__, banc, "--pour-de-vrai"],
                                 check=True, capture_output=True)
        sortie = rapport.stdout.decode()
        apres = open(bon, "rb").read()
        if apres != convertir(corps):
            print(f"FAUTE : contenu converti = {apres!r}", file=sys.stderr)
            fautes += 1
        if len(apres) != converti_attendu:
            print(f"FAUTE : {len(apres)} octets, `W=` disait {converti_attendu}",
                  file=sys.stderr)
            fautes += 1
        if os.stat(bon).st_mtime != jadis:
            print("FAUTE : la date de modification n'a pas été conservée — "
                  "l'INTERNALDATE d'IMAP en dépend", file=sys.stderr)
            fautes += 1
        if open(en_cours, "rb").read() != corps:
            print("FAUTE : un message de `tmp/` a été converti", file=sys.stderr)
            fautes += 1
        if autre_groupe is not None and os.stat(bon).st_gid != autre_groupe:
            print("FAUTE : le propriétaire du message n'a pas été conservé — "
                  "sous `sudo`, il reviendrait à `root` et le compte de service "
                  "ne le lirait plus", file=sys.stderr)
            fautes += 1
        if "à convertir         : 1" not in sortie:
            print(f"FAUTE : le rapport devrait annoncer 1 à convertir :\n{sortie}",
                  file=sys.stderr)
            fautes += 1

        # Et un second passage ne touche à rien : il doit voir 1 déjà en CRLF et
        # 0 à convertir. Le contenu seul ne suffirait pas à le dire — réécrire un
        # fichier à l'identique se voit dans le compte, pas dans les octets.
        second = subprocess.run([sys.executable, __file__, banc, "--pour-de-vrai"],
                                check=True, capture_output=True).stdout.decode()
        if open(bon, "rb").read() != apres:
            print("FAUTE : un second passage a modifié le message", file=sys.stderr)
            fautes += 1
        if "déjà en CRLF        : 1" not in second or "à convertir         : 0" not in second:
            print(f"FAUTE : le second passage devrait ne rien avoir à faire :\n{second}",
                  file=sys.stderr)
            fautes += 1

    if fautes == 0:
        print(f"OK : {len(cas)} conversions, leur idempotence, l'oracle `W=`, "
              "et un arrêt sur écart.")
    return fautes


if __name__ == "__main__":
    sys.exit(main())
