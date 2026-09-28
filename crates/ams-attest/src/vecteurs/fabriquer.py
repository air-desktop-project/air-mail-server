#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Fabrique les chaînes d'attestation SYNTHÉTIQUES des essais d'`ams-attest`.

Les chaînes réelles (`google/`) viennent d'appareils de test : déverrouillés,
d'une application système, sous un défi `abc`. Elles éprouvent la lecture et
la cryptographie, jamais une acceptation. Celles-ci sont fabriquées sous une
racine d'essai, avec ce qu'on choisit — défi, paquet, empreinte, état de
démarrage — pour éprouver chaque règle de la politique, une par une.

LES CLEFS SONT DÉTERMINISTES ET PUBLIQUES : elles ne protègent rien. La clef
d'appareil est la graine [7]*32, la même que l'épreuve de production.

Relancer ce script réécrit les fichiers `synthese/` ; les signatures ECDSA
changent (elles sont aléatoires), pas ce qu'elles couvrent. Usage :

    python3 fabriquer.py
"""
import datetime
import hashlib
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

ICI = os.path.dirname(os.path.abspath(__file__))
SORTIE = os.path.join(ICI, "synthese")

# ── Un encodeur DER minimal, pour la KeyDescription ─────────────────────────


def longueur(n):
    if n < 0x80:
        return bytes([n])
    octets = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


def tlv(etiquette, contenu):
    return etiquette + longueur(len(contenu)) + contenu


def entier(n):
    octets = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True)
    return tlv(b"\x02", octets)


def enumere(n):
    return tlv(b"\x0a", bytes([n]))


def octets(o):
    return tlv(b"\x04", o)


def booleen(b):
    return tlv(b"\x01", b"\xff" if b else b"\x00")


def sequence(*parts):
    return tlv(b"\x30", b"".join(parts))


def ensemble(*parts):
    return tlv(b"\x31", b"".join(sorted(parts)))


def contexte(numero, contenu):
    """Une étiquette de contexte CONSTRUITE et explicite, en forme haute au-delà
    de 30 — c'est ce qu'écrit Keymaster pour ses champs à numéro élevé."""
    if numero < 31:
        return tlv(bytes([0xA0 | numero]), contenu)
    groupes = []
    while True:
        groupes.insert(0, numero & 0x7F)
        numero >>= 7
        if numero == 0:
            break
    for i in range(len(groupes) - 1):
        groupes[i] |= 0x80
    return tlv(bytes([0xBF] + groupes), contenu)


def description(
    defi,
    paquet=b"org.airdesktop.mail",
    empreintes=None,
    niveau=1,
    verrouille=True,
    etat=0,
    origine=0,
    applications=True,
    racine_de_confiance=True,
    application_brute=None,
):
    """Une KeyDescription (version 200, KeyMint) : le défi, la liste logicielle
    qui porte l'identité de l'application, et la liste matérielle qui porte la
    racine de confiance et l'origine de la clef."""
    if empreintes is None:
        empreintes = [EMPREINTE]
    logiciel = []
    if application_brute is not None:
        logiciel.append(contexte(709, octets(application_brute)))
    elif applications:
        appli = sequence(
            ensemble(sequence(octets(paquet), entier(7))),
            ensemble(*[octets(e) for e in empreintes]),
        )
        logiciel.append(contexte(709, octets(appli)))
    materiel = [
        contexte(1, ensemble(entier(2))),
        contexte(2, entier(3)),
        contexte(3, entier(256)),
        contexte(10, entier(1)),
        contexte(702, entier(origine)),
    ]
    if racine_de_confiance:
        materiel.append(contexte(
            704,
            sequence(
                octets(bytes(32)),
                booleen(verrouille),
                enumere(etat),
                octets(bytes(32)),
            ),
        ))
    materiel += [
        contexte(705, entier(140000)),
        contexte(706, entier(202609)),
    ]
    return sequence(
        entier(200),
        enumere(niveau),
        entier(200),
        enumere(niveau),
        octets(defi),
        octets(b""),
        sequence(*logiciel),
        sequence(*materiel),
    )


# ── Les clefs, toutes déterministes ─────────────────────────────────────────


def cle_ec(graine, courbe=ec.SECP256R1()):
    return ec.derive_private_key(int.from_bytes(bytes([graine]) * 32, "big"), courbe)


APPAREIL = cle_ec(7)
RACINE = cle_ec(21, ec.SECP384R1())
INTERMEDIAIRE = cle_ec(22)
AUTRE_RACINE = cle_ec(23, ec.SECP384R1())
# Le certificat de signature de l'application : son empreinte est ce que la
# configuration nomme. Une chaîne quelconque d'octets suffit à l'essai.
EMPREINTE = hashlib.sha256(b"certificat de signature air-desktop.org").digest()
DEFI = hashlib.sha256(b"invitation d'essai").digest()

DEBUT = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
FIN = datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc)
OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")


def nom(texte):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, texte)])


def certificat(sujet, publique, emetteur, cle_emetteur, ca, extension=None,
               debut=DEBUT, fin=FIN, empreinte=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(nom(sujet))
        .issuer_name(nom(emetteur))
        .public_key(publique)
        .serial_number(x509.random_serial_number())
        .not_valid_before(debut)
        .not_valid_after(fin)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if extension is not None:
        b = b.add_extension(x509.UnrecognizedExtension(OID, extension), critical=False)
    algo = empreinte or hashes.SHA256()
    return b.sign(cle_emetteur, algo).public_bytes(serialization.Encoding.DER)


def chaine(desc, racine=RACINE, feuille_publique=None, debut=DEBUT):
    r = certificat("Racine d'essai", racine.public_key(), "Racine d'essai", racine, True,
                   empreinte=hashes.SHA384())
    i = certificat("Intermédiaire d'essai", INTERMEDIAIRE.public_key(), "Racine d'essai",
                   racine, True, empreinte=hashes.SHA384())
    f = certificat("Android Keystore Key", feuille_publique or APPAREIL.public_key(),
                   "Intermédiaire d'essai", INTERMEDIAIRE, False, desc, debut=debut)
    return f + i + r


def ecrire(nom_fichier, octets_):
    with open(os.path.join(SORTIE, nom_fichier), "wb") as f:
        f.write(octets_)


def principal():
    os.makedirs(SORTIE, exist_ok=True)
    racine = RACINE.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ecrire("racine.spki", racine)
    ecrire("appareil.sec1", APPAREIL.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    ecrire("empreinte.bin", EMPREINTE)
    ecrire("defi.bin", DEFI)

    ecrire("tee.der", chaine(description(DEFI)))
    ecrire("strongbox.der", chaine(description(DEFI, niveau=2)))
    ecrire("logiciel.der", chaine(description(DEFI, niveau=0)))
    ecrire("deverrouille.der", chaine(description(DEFI, verrouille=False)))
    ecrire("non-verifie.der", chaine(description(DEFI, etat=2)))
    ecrire("importee.der", chaine(description(DEFI, origine=2)))
    ecrire("autre-paquet.der", chaine(description(DEFI, paquet=b"com.exemple.autre")))
    ecrire("autre-signataire.der", chaine(description(
        DEFI, empreintes=[hashlib.sha256(b"un autre signataire").digest()])))
    ecrire("deux-signataires.der", chaine(description(
        DEFI, empreintes=[EMPREINTE, hashlib.sha256(b"un autre signataire").digest()])))
    ecrire("sans-application.der", chaine(description(DEFI, applications=False)))
    ecrire("sans-racine-de-confiance.der", chaine(description(DEFI, racine_de_confiance=False)))
    ecrire("extension-illisible.der", chaine(sequence()))
    ecrire("application-illisible.der", chaine(description(DEFI, application_brute=b"\x30\x01")))
    ecrire("autre-racine.der", chaine(description(DEFI), racine=AUTRE_RACINE))
    ecrire("autre-cle.der", chaine(description(DEFI), feuille_publique=cle_ec(8).public_key()))
    ecrire("future.der", chaine(description(DEFI),
                                debut=datetime.datetime(2034, 1, 1, tzinfo=datetime.timezone.utc)))
    # Une feuille sans extension d'attestation : un certificat ordinaire.
    r = certificat("Racine d'essai", RACINE.public_key(), "Racine d'essai", RACINE, True,
                   empreinte=hashes.SHA384())
    i = certificat("Intermédiaire d'essai", INTERMEDIAIRE.public_key(), "Racine d'essai",
                   RACINE, True, empreinte=hashes.SHA384())
    f = certificat("Android Keystore Key", APPAREIL.public_key(), "Intermédiaire d'essai",
                   INTERMEDIAIRE, False)
    ecrire("sans-extension.der", f + i + r)
    # Une racine RSA, pour la signature PKCS#1 d'un intermédiaire.
    racine_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ecrire("racine-rsa.spki", racine_rsa.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    ecrire("rsa.der", chaine(description(DEFI), racine=racine_rsa))


if __name__ == "__main__":
    principal()
