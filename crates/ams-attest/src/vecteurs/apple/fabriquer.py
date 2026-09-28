#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Fabrique les objets d'attestation App Attest SYNTHÉTIQUES des essais.

L'exemple d'Apple (`exemple-apple.cbor`) éprouve la cryptographie et la
lecture ; mais toute retouche de son `authData` change le nonce, et s'arrête
là. Ceux-ci sont signés sous une racine d'essai, avec le nonce qui va, pour
éprouver chaque règle qui suit : compteur, environnement, identifiant de clef.

LES CLEFS SONT DÉTERMINISTES ET PUBLIQUES. Usage : python3 fabriquer.py
"""
import datetime
import hashlib
import os
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ICI = os.path.dirname(os.path.abspath(__file__))
SORTIE = os.path.join(ICI, "synthese")
APPLICATION = b"TEAM123456.org.airdesktop.mail"
# Le `clientDataHash` tel que le serveur le calcule : SHA-256(invitation ‖ 0x00
# ‖ clef d'appareil) — la clef des vecteurs Android synthétiques.
with open(os.path.join(ICI, "..", "synthese", "appareil.sec1"), "rb") as f:
    CLIENT = hashlib.sha256(b"invitation d'essai\x00" + f.read()).digest()
DEBUT = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
FIN = datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc)
OID = x509.ObjectIdentifier("1.2.840.113635.100.8.2")


def cle(graine, courbe=ec.SECP256R1()):
    return ec.derive_private_key(int.from_bytes(bytes([graine]) * 32, "big"), courbe)


RACINE = cle(31, ec.SECP384R1())
INTERMEDIAIRE = cle(32, ec.SECP384R1())
APPAREIL = cle(33)


# ── Un encodeur CBOR minimal ────────────────────────────────────────────────

def entete(majeur, n):
    if n < 24:
        return bytes([majeur << 5 | n])
    if n < 256:
        return bytes([majeur << 5 | 24, n])
    if n < 65536:
        return bytes([majeur << 5 | 25]) + struct.pack(">H", n)
    return bytes([majeur << 5 | 26]) + struct.pack(">I", n)


def octets(o):
    return entete(2, len(o)) + o


def texte(t):
    return entete(3, len(t)) + t


def tableau(*elements):
    return entete(4, len(elements)) + b"".join(elements)


def table(*paires):
    return entete(5, len(paires)) + b"".join(k + v for k, v in paires)


# ── L'objet ────────────────────────────────────────────────────────────────

def nom(t):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, t)])


def certificat(sujet, publique, emetteur, cle_emetteur, extension=None, algo=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(nom(sujet))
        .issuer_name(nom(emetteur))
        .public_key(publique)
        .serial_number(7)
        .not_valid_before(DEBUT)
        .not_valid_after(FIN)
    )
    if extension is not None:
        b = b.add_extension(x509.UnrecognizedExtension(OID, extension), critical=False)
    return b.sign(cle_emetteur, algo or hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def der(etiquette, contenu):
    n = len(contenu)
    longueur = bytes([n]) if n < 128 else bytes([0x81, n])
    return etiquette + longueur + contenu


def auth_data(application=APPLICATION, compteur=0, aaguid=b"appattest\0\0\0\0\0\0\0",
              identifiant=None):
    point = APPAREIL.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if identifiant is None:
        identifiant = hashlib.sha256(point).digest()
    return (hashlib.sha256(application).digest() + b"\x40" + struct.pack(">I", compteur)
            + aaguid + struct.pack(">H", len(identifiant)) + identifiant + b"\xa5\x01\x02")


def objet(ad=None, extension="bonne", fmt=b"apple-appattest", x5c=None, feuille_cle=None,
          signe_par=None):
    ad = ad if ad is not None else auth_data()
    nonce = hashlib.sha256(ad + CLIENT).digest()
    contenu = {
        "bonne": der(b"\x30", der(b"\xa1", der(b"\x04", nonce))),
        "absente": None,
        "mal": der(b"\x30", der(b"\x04", nonce)),
    }[extension]
    feuille = certificat("clef", (feuille_cle or APPAREIL).public_key(), "intermédiaire",
                         signe_par or INTERMEDIAIRE, contenu)
    inter = certificat("intermédiaire", INTERMEDIAIRE.public_key(), "racine", RACINE,
                       algo=hashes.SHA384())
    if x5c is None:
        x5c = [feuille, inter]
    return table(
        (texte(b"fmt"), texte(fmt)),
        (texte(b"attStmt"), table(
            (texte(b"x5c"), tableau(*[octets(c) for c in x5c])),
            (texte(b"receipt"), octets(b"recu")),
        )),
        (texte(b"authData"), octets(ad)),
    )


def ecrire(nom_fichier, contenu):
    with open(os.path.join(SORTIE, nom_fichier), "wb") as f:
        f.write(contenu)


def principal():
    os.makedirs(SORTIE, exist_ok=True)
    ecrire("racine.spki", RACINE.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    ecrire("client.bin", CLIENT)
    ecrire("bon.cbor", objet())
    ecrire("developpement.cbor", objet(auth_data(aaguid=b"appattestdevelop")))
    ecrire("compteur.cbor", objet(auth_data(compteur=1)))
    ecrire("autre-identifiant.cbor", objet(auth_data(identifiant=bytes(32))))
    ecrire("sans-extension.cbor", objet(extension="absente"))
    ecrire("extension-illisible.cbor", objet(extension="mal"))
    ecrire("autre-format.cbor", objet(fmt=b"android-key"))
    ecrire("feuille-p384.cbor", objet(feuille_cle=cle(34, ec.SECP384R1())))
    ecrire("mal-signee.cbor", objet(signe_par=cle(35, ec.SECP384R1())))
    ecrire("un-certificat.cbor", objet(x5c=[b"\x30\x00"]))
    for rang, taille in enumerate([20, 33, 36, 50, 54, 60, 32]):
        ecrire(f"auth-courte-{rang}.cbor", objet(auth_data()[:taille]))


if __name__ == "__main__":
    principal()
