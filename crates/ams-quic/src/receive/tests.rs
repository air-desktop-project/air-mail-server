// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que l'ouverture d'un paquet doit rendre, d'après RFC 9001 annexe A.
//!
//! # CE SONT DE VRAIS PAQUETS, ENTIERS
//!
//! Les deux `Initial` de l'annexe A font mille deux cents et cent trente-cinq
//! octets, chiffrés et masqués. Les ouvrir met en jeu toute la chaîne — la
//! grammaire, les clés, le démasquage, la reconstruction du numéro, le
//! déchiffrement —, et une seule de ces six étapes fausse fait tout échouer.
//!
//! **C'est ce qu'aucun test écrit à la main ne remplace** : chaque morceau pris
//! séparément peut être juste sans que le tout le soit.

use ams_proto_quic::{Frame, LongKind};
use ams_quic_crypto::{Keys, Role, Secret};

use super::{PacketKind, open_packet};
use crate::error::Reason;

/// Lit une suite d'octets écrite en hexadécimal.
fn hexa(morceaux: &[&str]) -> std::vec::Vec<u8> {
    let tout: std::string::String = morceaux.concat();
    let chiffres: std::vec::Vec<char> = tout.chars().collect();
    chiffres
        .chunks(2)
        .map(|paire| {
            let s: std::string::String = paire.iter().collect();
            u8::from_str_radix(&s, 16).expect("hexadécimal")
        })
        .collect()
}

/// L'identifiant que le client a choisi, dans toute l'annexe A.
fn destination() -> std::vec::Vec<u8> {
    hexa(&["8394c8f03e515708"])
}

/// Les clés `Initial` d'un côté.
fn clefs(role: Role) -> Keys {
    Secret::initial(&destination(), role)
        .expect("dérivable")
        .keys()
        .expect("dérivables")
}

/// Le paquet `Initial` du client, protégé (annexe A.2).
const PAQUET_CLIENT: [&str; 38] = [
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
    "e221af44860018ab0856972e194cd934",
];

/// Le paquet `Initial` du serveur, protégé (annexe A.3).
const PAQUET_SERVEUR: [&str; 5] = [
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a",
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3",
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84",
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4",
    "2158407dd074ee",
];

/// La trame `CRYPTO` que porte le paquet du client, sans son remplissage.
const CHARGE_CLIENT: [&str; 8] = [
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868",
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578",
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba",
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400",
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100",
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000",
    "75300901100f088394c8f03e51570806048000ffff",
];

/// Ce que porte le paquet du serveur.
const CHARGE_SERVEUR: [&str; 4] = [
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739",
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94",
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00",
    "020304",
];

/// **LE PAQUET `Initial` DU CLIENT DE L'ANNEXE A.2, OUVERT EN ENTIER.**
#[test]
fn le_paquet_du_client_de_l_annexe_s_ouvre() {
    let mut datagramme = hexa(&PAQUET_CLIENT);
    assert_eq!(
        datagramme.len(),
        1_200,
        "le paquet fait mille deux cents octets"
    );
    let ouvert = open_packet(&mut datagramme, &clefs(Role::Client), None, 0).expect("il s'ouvre");

    assert_eq!(ouvert.kind, PacketKind::Long(LongKind::Initial));
    assert_eq!(ouvert.number, 2, "le numéro que l'annexe donne");
    assert_eq!(ouvert.total, 1_200, "il occupe tout le datagramme");
    assert!(!ouvert.key_phase, "un en-tête long n'a pas de phase de clé");
    // §12.2 : la charge fait 1162 octets — la trame `CRYPTO`, puis du
    // remplissage.
    assert_eq!(ouvert.payload_len, 1_162);

    let charge = datagramme
        .get(ouvert.payload_at..ouvert.payload_at.saturating_add(ouvert.payload_len))
        .expect("la charge");
    let attendue = hexa(&CHARGE_CLIENT);
    assert_eq!(
        charge.get(..attendue.len()),
        Some(attendue.as_slice()),
        "la trame CRYPTO n'est pas celle de l'annexe"
    );
    // Le reste est du remplissage, et rien d'autre.
    assert!(
        charge
            .get(attendue.len()..)
            .unwrap_or_default()
            .iter()
            .all(|o| *o == 0),
        "le remplissage n'est pas nul"
    );

    // Et les trames se lisent.
    let (trame, lus) = Frame::parse(charge).expect("lisible");
    assert!(matches!(trame, Frame::Crypto { offset: 0, .. }));
    let reste = charge.get(lus..).expect("la suite");
    let (remplissage, _) = Frame::parse(reste).expect("lisible");
    assert_eq!(
        remplissage,
        Frame::Padding {
            count: 1_162 - attendue.len()
        }
    );
}

/// **LE PAQUET `Initial` DU SERVEUR DE L'ANNEXE A.3**, dont le numéro tient sur
/// DEUX octets — l'échantillon se prend quand même à quatre.
#[test]
fn le_paquet_du_serveur_de_l_annexe_s_ouvre() {
    let mut datagramme = hexa(&PAQUET_SERVEUR);
    let ouvert = open_packet(&mut datagramme, &clefs(Role::Server), None, 0).expect("il s'ouvre");

    assert_eq!(ouvert.kind, PacketKind::Long(LongKind::Initial));
    assert_eq!(ouvert.number, 1, "le numéro que l'annexe donne");
    assert_eq!(ouvert.total, datagramme.len());

    let charge = datagramme
        .get(ouvert.payload_at..ouvert.payload_at.saturating_add(ouvert.payload_len))
        .expect("la charge");
    assert_eq!(charge, hexa(&CHARGE_SERVEUR).as_slice());

    // Un `ACK` puis une trame `CRYPTO`, comme l'annexe l'annonce.
    let (ack, lus) = Frame::parse(charge).expect("lisible");
    assert!(matches!(ack, Frame::Ack(_)));
    let (crypto, _) = Frame::parse(charge.get(lus..).expect("la suite")).expect("lisible");
    assert!(matches!(crypto, Frame::Crypto { offset: 0, .. }));
}

/// **UN PAQUET QUI NE S'AUTHENTIFIE PAS SE JETTE**, et ne ferme rien : le port
/// est ouvert au monde entier, et fermer sur lui offrirait la connexion à qui
/// sait envoyer un datagramme.
#[test]
fn un_paquet_abime_se_jette() {
    for rang in [0_usize, 20, 100, 1_199] {
        let mut datagramme = hexa(&PAQUET_CLIENT);
        datagramme[rang] ^= 0x01;
        let issue = open_packet(&mut datagramme, &clefs(Role::Client), None, 0).expect_err("abîmé");
        assert!(issue.se_jette(), "au rang {rang} : {issue:?}");
    }

    // Avec les clés du SERVEUR, le paquet du client ne s'ouvre pas non plus.
    let mut datagramme = hexa(&PAQUET_CLIENT);
    let issue =
        open_packet(&mut datagramme, &clefs(Role::Server), None, 0).expect_err("mauvaises clés");
    assert!(issue.se_jette());
}

/// **LES BITS RÉSERVÉS SE VÉRIFIENT APRÈS LE DÉCHIFFREMENT, ET PAS AVANT**
/// (§17.2, et §9.5 de RFC 9001). Refuser plus tôt dirait à un attaquant que son
/// masque d'en-tête était bon.
///
/// On fabrique donc un paquet dont les bits réservés sont posés AVANT la
/// protection : c'est le seul moyen d'atteindre cette garde.
#[test]
fn les_bits_reserves_se_verifient_apres_le_dechiffrement() {
    // On rejoue l'annexe A.2 à l'envers : on ouvre le paquet, on pose un bit
    // réservé dans l'en-tête en clair, et l'on referme.
    let mut datagramme = hexa(&PAQUET_CLIENT);
    let clefs = clefs(Role::Client);
    let ouvert = open_packet(&mut datagramme, &clefs, None, 0).expect("il s'ouvre");

    // Le premier octet est maintenant en clair : on y pose un bit réservé.
    datagramme[0] |= 0x04;
    let fin_du_numero = ouvert.payload_at;
    let (aad, corps) = datagramme.split_at_mut(fin_du_numero);
    let ecrits = clefs
        .seal(ouvert.number, aad, corps, ouvert.payload_len)
        .expect("chiffrable");
    let total = fin_du_numero.saturating_add(ecrits);
    let mut refait = datagramme.get(..total).expect("le paquet").to_vec();
    // Le numéro fait quatre octets : l'en-tête commence au rang 18.
    ams_quic_crypto::protect(&clefs, &mut refait, 18, 4).expect("protégeable");

    let issue = open_packet(&mut refait, &clefs, None, 0).expect_err("bits réservés");
    assert_eq!(issue.reason(), Reason::ReservedBitsSet);
    assert!(
        !issue.se_jette(),
        "celle-là condamne : le pair est authentifié"
    );
    assert_eq!(
        issue.code(),
        Some(ams_proto_quic::TransportError::ProtocolViolation)
    );
}

/// **UN DATAGRAMME PORTE PLUSIEURS PAQUETS** (§12.2), et l'on avance de ce que
/// chacun occupe.
#[test]
fn un_datagramme_porte_plusieurs_paquets() {
    // Deux fois le paquet du serveur, coalisés. Le second porte le même numéro,
    // ce qui n'a pas de sens sur le fil — mais prouve que la frontière est
    // bien celle que la longueur annonce.
    let un = hexa(&PAQUET_SERVEUR);
    let mut datagramme = un.clone();
    datagramme.extend_from_slice(&un);

    let clefs = clefs(Role::Server);
    let premier = open_packet(&mut datagramme, &clefs, None, 0).expect("il s'ouvre");
    assert_eq!(premier.total, un.len(), "il s'arrête où sa longueur le dit");

    let suite = datagramme.get_mut(premier.total..).expect("la suite");
    let second = open_packet(suite, &clefs, None, 0).expect("il s'ouvre aussi");
    assert_eq!(second.number, premier.number);
    assert_eq!(second.total, un.len());
}

/// **CE QU'ON NE SAIT PAS LIRE SE JETTE**, et n'arrête pas la connexion.
#[test]
fn ce_qu_on_ne_sait_pas_lire_se_jette() {
    let clefs = clefs(Role::Client);
    // Un datagramme vide.
    let issue = open_packet(&mut [], &clefs, None, 0).expect_err("vide");
    assert_eq!(issue.reason(), Reason::NotForUs);
    assert!(issue.se_jette());

    // Un en-tête LONG tronqué : la version n'y tient même pas.
    for tronque in [
        std::vec![0xc0_u8],
        std::vec![0xc0_u8, 0x00],
        std::vec![0xc0_u8, 0x00, 0x00, 0x00, 0x01],
    ] {
        let mut copie = tronque.clone();
        let issue = open_packet(&mut copie, &clefs, None, 0).expect_err("tronqué");
        assert_eq!(issue.reason(), Reason::NotForUs, "{tronque:02x?}");
    }

    // Une négociation de version : un serveur n'en reçoit pas.
    let mut negociation = hexa(&["c000000000010203040508090a0b0c0d0e0f00000001"]);
    let issue = open_packet(&mut negociation, &clefs, None, 0).expect_err("négociation");
    assert_eq!(issue.reason(), Reason::NotForUs);

    // Un `Retry` : il ne se déchiffre pas.
    let mut retry = hexa(&["ff000000010008f067a5502a4262b5746f6b656e"]);
    retry.extend_from_slice(&[0x5a; 16]);
    let issue = open_packet(&mut retry, &clefs, None, 0).expect_err("Retry");
    assert_eq!(issue.reason(), Reason::NotForUs);

    // Un paquet dont la longueur annonce plus que le datagramme ne porte.
    let mut ment = hexa(&PAQUET_CLIENT);
    ment.truncate(100);
    let issue = open_packet(&mut ment, &clefs, None, 0).expect_err("tronqué");
    assert!(issue.se_jette());

    // Un en-tête court trop court pour un échantillon.
    let mut court = std::vec![0x41_u8; 8];
    let issue = open_packet(&mut court, &clefs, None, 0).expect_err("trop court");
    assert!(issue.se_jette());
}

/// **UN EN-TÊTE COURT VA JUSQU'AU BOUT DU DATAGRAMME** (§12.2) : il ne porte pas
/// de longueur, et ne peut donc être que le dernier.
#[test]
fn un_entete_court_va_jusqu_au_bout() {
    // On fabrique un `1-RTT` avec les clés `Initial` — la protection est la
    // même, seul l'en-tête change.
    let clefs = clefs(Role::Server);
    let identifiant = [0xde_u8, 0xad, 0xbe, 0xef];
    let mut paquet = std::vec::Vec::new();
    // Forme courte, bit fixe, numéro sur deux octets.
    paquet.push(0x41);
    paquet.extend_from_slice(&identifiant);
    paquet.extend_from_slice(&[0x00, 0x07]);
    let numero_a = paquet.len().saturating_sub(2);
    let clair = b"une charge quelconque, assez longue pour l'echantillon";
    paquet.extend_from_slice(clair);
    paquet.extend_from_slice(&[0_u8; 16]);

    let (aad, corps) = paquet.split_at_mut(numero_a.saturating_add(2));
    let ecrits = clefs.seal(7, aad, corps, clair.len()).expect("chiffrable");
    paquet.truncate(numero_a.saturating_add(2).saturating_add(ecrits));
    ams_quic_crypto::protect(&clefs, &mut paquet, numero_a, 2).expect("protégeable");

    let total = paquet.len();
    let ouvert = open_packet(&mut paquet, &clefs, Some(6), identifiant.len()).expect("il s'ouvre");
    assert_eq!(ouvert.kind, PacketKind::Short);
    assert_eq!(ouvert.number, 7);
    assert_eq!(ouvert.total, total, "il va jusqu'au bout du datagramme");
    assert!(!ouvert.key_phase);
    assert_eq!(
        paquet.get(ouvert.payload_at..ouvert.payload_at + ouvert.payload_len),
        Some(clair.as_slice())
    );
}

/// **L'ESPACE DES NUMÉROS S'ÉPUISE, ET §12.3 VEUT QU'ON AIT FERMÉ AVANT.**
/// Qu'on nous demande de reconstruire quand même veut dire qu'on a manqué cette
/// fermeture — et celle-là condamne.
#[test]
fn un_espace_epuise_condamne() {
    let mut datagramme = hexa(&PAQUET_CLIENT);
    let issue = open_packet(
        &mut datagramme,
        &clefs(Role::Client),
        Some(ams_proto_quic::PACKET_NUMBER_MAX),
        0,
    )
    .expect_err("espace épuisé");
    assert_eq!(issue.reason(), Reason::BadPacketNumber);
    assert!(!issue.se_jette(), "celle-là condamne");
    assert_eq!(
        issue.code(),
        Some(ams_proto_quic::TransportError::ProtocolViolation)
    );
}
