// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une trame de §19 a le droit d'être.

use super::{
    Directional, EcnCounts, Frame, MAX_STREAMS_LIMIT, PATH_DATA_OCTETS,
    STATELESS_RESET_TOKEN_OCTETS,
};
use crate::error::{Reason, TransportError};
use crate::varint;

/// Compose des octets à partir d'entiers de §16 et de tranches.
enum Bout<'a> {
    Entier(u64),
    Octets(&'a [u8]),
}

/// Assemble une trame.
fn octets(bouts: &[Bout<'_>]) -> std::vec::Vec<u8> {
    let mut sortie = std::vec::Vec::new();
    for bout in bouts {
        match bout {
            Bout::Entier(valeur) => {
                let mut place = [0_u8; 8];
                let ecrits = varint::encode(*valeur, &mut place).expect("écrivable");
                sortie.extend_from_slice(place.get(..ecrits).unwrap_or_default());
            }
            Bout::Octets(lus) => sortie.extend_from_slice(lus),
        }
    }
    sortie
}

/// **LE REMPLISSAGE SE COMPTE PLUTÔT QUE DE SE RENDRE UNE À UNE** : un `Initial`
/// fait au moins 1200 octets, et l'essentiel est souvent du vide.
#[test]
fn le_remplissage_se_compte() {
    let (trame, lus) = Frame::parse(&[0x00; 1_200]).expect("lisible");
    assert_eq!(trame, Frame::Padding { count: 1_200 });
    assert_eq!(lus, 1_200);

    // Il s'arrête à la première trame qui n'en est pas.
    let (trame, lus) = Frame::parse(&[0x00, 0x00, 0x01]).expect("lisible");
    assert_eq!(trame, Frame::Padding { count: 2 });
    assert_eq!(lus, 2);
}

/// Les trames sans champ se lisent en un octet.
#[test]
fn les_trames_sans_champ_se_lisent() {
    for (octet, attendue) in [(0x01_u8, Frame::Ping), (0x1e, Frame::HandshakeDone)] {
        let brut = [octet];
        let (trame, lus) = Frame::parse(&brut).expect("lisible");
        assert_eq!(trame, attendue);
        assert_eq!(lus, 1);
    }
}

/// **UN `ACK` GARDE SES INTERVALLES SUR LE FIL** : leur nombre vient du pair, et
/// les retenir tous demanderait une table dont il choisirait la taille.
#[test]
fn un_ack_se_lit_et_ses_intervalles_se_parcourent() {
    // largest = 100, delay = 3, deux intervalles, premier de 10.
    let brut = octets(&[
        Bout::Entier(0x02),
        Bout::Entier(100),
        Bout::Entier(3),
        Bout::Entier(2),
        Bout::Entier(10),
        Bout::Entier(1),
        Bout::Entier(5),
        Bout::Entier(0),
        Bout::Entier(7),
    ]);
    let (trame, lus) = Frame::parse(&brut).expect("lisible");
    assert_eq!(lus, brut.len());
    let Frame::Ack(ack) = trame else {
        panic!("ce devait être un ACK");
    };
    assert_eq!(ack.largest, 100);
    assert_eq!(ack.delay, 3);
    assert_eq!(ack.range_count, 2);
    assert_eq!(ack.first_range, 10);
    assert_eq!(ack.smallest().expect("dans l'espace"), 90);
    assert!(ack.ecn.is_none());

    let intervalles: std::vec::Vec<_> = ack.ranges().map(|issue| issue.expect("lisible")).collect();
    assert_eq!(intervalles.len(), 2);
    assert_eq!(intervalles[0].gap, 1);
    assert_eq!(intervalles[0].length, 5);
    assert_eq!(intervalles[1].gap, 0);
    assert_eq!(intervalles[1].length, 7);
}

/// **LES COMPTES ECN DISENT QUE LE RÉSEAU A EU CHAUD**, et non qu'il a perdu.
#[test]
fn un_ack_avec_ecn_porte_ses_trois_comptes() {
    let brut = octets(&[
        Bout::Entier(0x03),
        Bout::Entier(50),
        Bout::Entier(0),
        Bout::Entier(0),
        Bout::Entier(1),
        Bout::Entier(11),
        Bout::Entier(22),
        Bout::Entier(33),
    ]);
    let (trame, lus) = Frame::parse(&brut).expect("lisible");
    assert_eq!(lus, brut.len());
    let Frame::Ack(ack) = trame else {
        panic!("ce devait être un ACK");
    };
    assert_eq!(
        ack.ecn,
        Some(EcnCounts {
            ect0: 11,
            ect1: 22,
            ce: 33
        })
    );
    assert_eq!(ack.ranges().count(), 0);
}

/// **UN INTERVALLE QUI DESCEND SOUS ZÉRO EST UNE FAUTE DE CADRAGE** (§19.3.1),
/// et non un intervalle qu'on raccourcirait en silence.
#[test]
fn un_intervalle_sous_zero_se_refuse() {
    let brut = octets(&[
        Bout::Entier(0x02),
        Bout::Entier(5),
        Bout::Entier(0),
        Bout::Entier(0),
        // Le premier intervalle descend de dix sous un plus grand qui vaut cinq.
        Bout::Entier(10),
    ]);
    let (trame, _) = Frame::parse(&brut).expect("lisible");
    let Frame::Ack(ack) = trame else {
        panic!("ce devait être un ACK");
    };
    let issue = ack.smallest().expect_err("sous zéro");
    assert_eq!(issue.reason(), Reason::BadAckRange);
    assert_eq!(issue.code(), TransportError::FrameEncodingError);
}

/// **UNE FAUTE ARRÊTE LE PARCOURS** : continuer lirait les octets suivants comme
/// des intervalles, et il n'y a plus aucune raison de croire qu'ils en sont.
#[test]
fn un_intervalle_illisible_arrete_le_parcours() {
    let brut = octets(&[
        Bout::Entier(0x02),
        Bout::Entier(100),
        Bout::Entier(0),
        Bout::Entier(3),
        Bout::Entier(1),
    ]);
    // On tronque : le `ACK` annonce trois intervalles et n'en porte aucun.
    let issue = Frame::parse(&brut).expect_err("tronqué");
    assert_eq!(issue.reason(), Reason::Truncated);

    // Et un `Ack` fabriqué à la main dont les intervalles manquent s'arrête.
    let ack = super::Ack {
        largest: 100,
        delay: 0,
        first_range: 1,
        range_count: 3,
        encoded_ranges: &[0x01],
        ecn: None,
    };
    // Trois intervalles annoncés, un seul octet : le premier tour lit son écart
    // puis manque sa longueur, et le parcours s'arrête là — un seul élément
    // rendu, et c'est la faute.
    let issues: std::vec::Vec<_> = ack.ranges().collect();
    assert_eq!(issues.len(), 1, "on s'arrête à la première faute");
    assert_eq!(issues[0].expect_err("tronqué").reason(), Reason::Truncated);
}

/// Les trames de flux et de crédit, chacune avec ses champs.
#[test]
fn les_trames_de_flux_se_lisent() {
    let brut = octets(&[
        Bout::Entier(0x04),
        Bout::Entier(7),
        Bout::Entier(42),
        Bout::Entier(1_000),
    ]);
    assert_eq!(
        Frame::parse(&brut).expect("lisible").0,
        Frame::ResetStream {
            stream: 7,
            code: 42,
            final_size: 1_000
        }
    );

    let brut = octets(&[Bout::Entier(0x05), Bout::Entier(7), Bout::Entier(42)]);
    assert_eq!(
        Frame::parse(&brut).expect("lisible").0,
        Frame::StopSending {
            stream: 7,
            code: 42
        }
    );

    let brut = octets(&[Bout::Entier(0x10), Bout::Entier(65_536)]);
    assert_eq!(
        Frame::parse(&brut).expect("lisible").0,
        Frame::MaxData { maximum: 65_536 }
    );

    let brut = octets(&[Bout::Entier(0x11), Bout::Entier(3), Bout::Entier(4_096)]);
    assert_eq!(
        Frame::parse(&brut).expect("lisible").0,
        Frame::MaxStreamData {
            stream: 3,
            maximum: 4_096
        }
    );

    let brut = octets(&[Bout::Entier(0x14), Bout::Entier(99)]);
    assert_eq!(
        Frame::parse(&brut).expect("lisible").0,
        Frame::DataBlocked { limit: 99 }
    );

    let brut = octets(&[Bout::Entier(0x15), Bout::Entier(3), Bout::Entier(99)]);
    assert_eq!(
        Frame::parse(&brut).expect("lisible").0,
        Frame::StreamDataBlocked {
            stream: 3,
            limit: 99
        }
    );

    let brut = octets(&[Bout::Entier(0x19), Bout::Entier(2)]);
    assert_eq!(
        Frame::parse(&brut).expect("lisible").0,
        Frame::RetireConnectionId { sequence: 2 }
    );
}

/// **LE SENS VIENT DU BIT DE BAS DU TYPE**, et les deux familles de comptes le
/// lisent pareil.
#[test]
fn le_sens_d_un_compte_de_flux_vient_du_type() {
    for (type_de_trame, sens) in [
        (0x12_u64, Directional::Bidirectional),
        (0x13, Directional::Unidirectional),
    ] {
        let brut = octets(&[Bout::Entier(type_de_trame), Bout::Entier(100)]);
        assert_eq!(
            Frame::parse(&brut).expect("lisible").0,
            Frame::MaxStreams {
                directional: sens,
                maximum: 100
            }
        );
    }
    for (type_de_trame, sens) in [
        (0x16_u64, Directional::Bidirectional),
        (0x17, Directional::Unidirectional),
    ] {
        let brut = octets(&[Bout::Entier(type_de_trame), Bout::Entier(100)]);
        assert_eq!(
            Frame::parse(&brut).expect("lisible").0,
            Frame::StreamsBlocked {
                directional: sens,
                limit: 100
            }
        );
    }
}

/// **2^60, ET NON 2^62** (§19.11) : un numéro de flux est fait d'un compte et de
/// deux bits de type, et un compte plus grand ferait un numéro hors de l'espace.
#[test]
fn un_compte_de_flux_au_dela_de_deux_puissance_soixante_se_refuse() {
    for type_de_trame in [0x12_u64, 0x13, 0x16, 0x17] {
        // La borne elle-même passe.
        let brut = octets(&[Bout::Entier(type_de_trame), Bout::Entier(MAX_STREAMS_LIMIT)]);
        assert!(Frame::parse(&brut).is_ok(), "{type_de_trame:#x}");
        // Un de plus, non.
        let brut = octets(&[
            Bout::Entier(type_de_trame),
            Bout::Entier(MAX_STREAMS_LIMIT.saturating_add(1)),
        ]);
        let issue = Frame::parse(&brut).expect_err("hors borne");
        assert_eq!(issue.reason(), Reason::BadFrameField, "{type_de_trame:#x}");
    }
}

/// **LES TROIS BITS DE BAS D'UN `STREAM` DISENT SA FORME** (§19.8), et les huit
/// combinaisons se lisent.
#[test]
fn les_huit_formes_d_un_stream_se_lisent() {
    for type_de_trame in 0x08_u64..=0x0f {
        let avec_offset = type_de_trame & 0x04 != 0;
        let avec_longueur = type_de_trame & 0x02 != 0;
        let fin = type_de_trame & 0x01 != 0;
        let mut bouts = std::vec::Vec::from([Bout::Entier(type_de_trame), Bout::Entier(9)]);
        if avec_offset {
            bouts.push(Bout::Entier(1_000));
        }
        if avec_longueur {
            bouts.push(Bout::Entier(5));
        }
        bouts.push(Bout::Octets(b"douze"));
        let brut = octets(&bouts);
        let (trame, lus) = Frame::parse(&brut).expect("lisible");
        assert_eq!(
            trame,
            Frame::Stream {
                stream: 9,
                offset: if avec_offset { 1_000 } else { 0 },
                data: b"douze",
                fin,
            },
            "{type_de_trame:#x}"
        );
        assert_eq!(lus, brut.len(), "{type_de_trame:#x}");
    }
}

/// **SANS `LEN`, LA TRAME VA JUSQU'AU BOUT DU PAQUET** — et c'est pourquoi
/// l'appelant ne doit lui présenter que le paquet.
#[test]
fn un_stream_sans_longueur_prend_tout_le_reste() {
    let brut = octets(&[
        Bout::Entier(0x08),
        Bout::Entier(1),
        Bout::Octets(b"tout ce qui suit"),
    ]);
    let (trame, lus) = Frame::parse(&brut).expect("lisible");
    assert_eq!(
        trame,
        Frame::Stream {
            stream: 1,
            offset: 0,
            data: b"tout ce qui suit",
            fin: false,
        }
    );
    assert_eq!(lus, brut.len());
}

/// **LA FIN D'UN FLUX TIENT DANS L'ESPACE DES ENTIERS** (§19.8) : la somme du
/// décalage et de la longueur ne peut pas dépasser 2^62 - 1.
#[test]
fn un_flux_qui_deborde_l_espace_se_refuse() {
    let brut = octets(&[
        Bout::Entier(0x0e),
        Bout::Entier(1),
        Bout::Entier(crate::varint::VARINT_MAX),
        Bout::Entier(1),
        Bout::Octets(b"x"),
    ]);
    let issue = Frame::parse(&brut).expect_err("hors de l'espace");
    assert_eq!(issue.reason(), Reason::BadFrameField);

    // Et la même règle vaut pour `CRYPTO` (§19.6).
    let brut = octets(&[
        Bout::Entier(0x06),
        Bout::Entier(crate::varint::VARINT_MAX),
        Bout::Entier(1),
        Bout::Octets(b"x"),
    ]);
    let issue = Frame::parse(&brut).expect_err("hors de l'espace");
    assert_eq!(issue.reason(), Reason::BadFrameField);
}

/// `CRYPTO` et `NEW_TOKEN` portent des tranches annoncées.
#[test]
fn les_tranches_annoncees_se_lisent() {
    let brut = octets(&[
        Bout::Entier(0x06),
        Bout::Entier(16),
        Bout::Entier(5),
        Bout::Octets(b"salut"),
    ]);
    let (trame, lus) = Frame::parse(&brut).expect("lisible");
    assert_eq!(
        trame,
        Frame::Crypto {
            offset: 16,
            data: b"salut"
        }
    );
    assert_eq!(lus, brut.len());

    let brut = octets(&[Bout::Entier(0x07), Bout::Entier(3), Bout::Octets(b"abc")]);
    assert_eq!(
        Frame::parse(&brut).expect("lisible").0,
        Frame::NewToken { token: b"abc" }
    );

    // Une longueur qui annonce plus que le paquet ne porte.
    let brut = octets(&[Bout::Entier(0x07), Bout::Entier(crate::varint::VARINT_MAX)]);
    assert_eq!(
        Frame::parse(&brut).expect_err("il ment").reason(),
        Reason::Truncated
    );
}

/// `NEW_CONNECTION_ID`, et le rang de retrait qui ne peut pas dépasser le rang
/// annoncé (§19.15).
#[test]
fn un_nouvel_identifiant_se_lit() {
    let jeton = [0x77_u8; STATELESS_RESET_TOKEN_OCTETS];
    let brut = octets(&[
        Bout::Octets(&[0x18]),
        Bout::Entier(4),
        Bout::Entier(2),
        Bout::Octets(&[3, 0xaa, 0xbb, 0xcc]),
        Bout::Octets(&jeton),
    ]);
    let (trame, lus) = Frame::parse(&brut).expect("lisible");
    let Frame::NewConnectionId {
        sequence,
        retire_prior_to,
        id,
        token,
    } = trame
    else {
        panic!("ce devait être un NEW_CONNECTION_ID");
    };
    assert_eq!(sequence, 4);
    assert_eq!(retire_prior_to, 2);
    assert_eq!(id.as_bytes(), &[0xaa, 0xbb, 0xcc]);
    assert_eq!(token, jeton);
    assert_eq!(lus, brut.len());
}

/// **UN RANG DE RETRAIT AU-DELÀ DU RANG ANNONCÉ RETIRERAIT L'IDENTIFIANT QU'ON
/// DONNE** (§19.15), et une longueur nulle ou hors borne n'en est pas une.
#[test]
fn un_nouvel_identifiant_mal_forme_se_refuse() {
    let jeton = [0_u8; STATELESS_RESET_TOKEN_OCTETS];
    // Retrait au-delà du rang.
    let brut = octets(&[
        Bout::Octets(&[0x18]),
        Bout::Entier(2),
        Bout::Entier(4),
        Bout::Octets(&[1, 0xaa]),
        Bout::Octets(&jeton),
    ]);
    let issue = Frame::parse(&brut).expect_err("retrait trop haut");
    assert_eq!(issue.reason(), Reason::BadFrameField);

    // §19.15 : la longueur va de un à vingt — zéro n'est pas licite ici, alors
    // qu'un identifiant vide l'est dans un en-tête.
    for longueur in [0_u8, 21, 255] {
        let entete = [longueur];
        let corps = [0xaa_u8; 255];
        let brut = octets(&[
            Bout::Octets(&[0x18]),
            Bout::Entier(4),
            Bout::Entier(2),
            Bout::Octets(&entete),
            Bout::Octets(&corps),
            Bout::Octets(&jeton),
        ]);
        let issue = Frame::parse(&brut).expect_err("hors borne");
        assert_eq!(issue.reason(), Reason::ConnectionIdTooLong, "{longueur}");
    }
}

/// Les deux trames de chemin portent leurs huit octets.
#[test]
fn les_trames_de_chemin_portent_huit_octets() {
    let huit = [1_u8, 2, 3, 4, 5, 6, 7, 8];
    for (octet, attendue) in [
        (0x1a_u8, Frame::PathChallenge { data: huit }),
        (0x1b, Frame::PathResponse { data: huit }),
    ] {
        let brut = octets(&[Bout::Octets(&[octet]), Bout::Octets(&huit)]);
        let (trame, lus) = Frame::parse(&brut).expect("lisible");
        assert_eq!(trame, attendue);
        assert_eq!(lus, 1 + PATH_DATA_OCTETS);

        // Sept octets ne suffisent pas.
        let brut = octets(&[Bout::Octets(&[octet]), Bout::Octets(&huit[..7])]);
        assert_eq!(
            Frame::parse(&brut).expect_err("tronqué").reason(),
            Reason::Truncated
        );
    }
}

/// **C'EST LE CHAMP `frame_type` QUI DIT DE QUEL ESPACE VIENT LE CODE**, et non
/// le code lui-même : les deux espaces se recouvrent entièrement (§19.19).
#[test]
fn une_fermeture_dit_de_quel_espace_vient_son_code() {
    let brut = octets(&[
        Bout::Entier(0x1c),
        Bout::Entier(0x0a),
        Bout::Entier(0x08),
        Bout::Entier(5),
        Bout::Octets(b"assez"),
    ]);
    assert_eq!(
        Frame::parse(&brut).expect("lisible").0,
        Frame::ConnectionClose {
            code: 0x0a,
            frame_type: Some(0x08),
            reason: b"assez",
        }
    );

    let brut = octets(&[Bout::Entier(0x1d), Bout::Entier(0x0a), Bout::Entier(0)]);
    assert_eq!(
        Frame::parse(&brut).expect("lisible").0,
        Frame::ConnectionClose {
            code: 0x0a,
            frame_type: None,
            reason: b"",
        }
    );
}

/// **CE QU'ON NE CONNAÎT PAS EST UNE FAUTE** (§12.4) — et c'est l'inverse
/// d'HTTP/2, où un cadre inconnu s'ignore. Une extension QUIC se négocie AVANT
/// d'être employée.
#[test]
fn un_type_inconnu_condamne_la_connexion() {
    for type_de_trame in [0x1f_u64, 0x20, 0x40, 1_000, crate::varint::VARINT_MAX] {
        let brut = octets(&[Bout::Entier(type_de_trame)]);
        let issue = Frame::parse(&brut).expect_err("inconnu");
        assert_eq!(issue.reason(), Reason::UnknownFrame, "{type_de_trame:#x}");
        assert_eq!(issue.code(), TransportError::FrameEncodingError);
    }
    // Et un tampon vide n'est pas une trame.
    assert_eq!(
        Frame::parse(&[]).expect_err("vide").reason(),
        Reason::Truncated
    );
}

/// **CHAQUE TYPE DE TRAME SE REFUSE TRONQUÉ**, et pas seulement ceux qu'on a
/// pensé à éprouver. Une trame ne porte pas sa longueur : un décodeur qui se
/// rattraperait d'un octet lirait le reste du paquet comme des trames
/// imaginaires.
#[test]
fn chaque_type_de_trame_se_refuse_tronque() {
    let jeton = [0x77_u8; STATELESS_RESET_TOKEN_OCTETS];
    let huit = [1_u8, 2, 3, 4, 5, 6, 7, 8];
    let entieres: [std::vec::Vec<u8>; 20] = [
        // ACK, et ACK avec ses comptes ECN.
        octets(&[
            Bout::Entier(0x02),
            Bout::Entier(100),
            Bout::Entier(3),
            Bout::Entier(1),
            Bout::Entier(10),
            Bout::Entier(1),
            Bout::Entier(5),
        ]),
        octets(&[
            Bout::Entier(0x03),
            Bout::Entier(100),
            Bout::Entier(3),
            Bout::Entier(0),
            Bout::Entier(10),
            Bout::Entier(1),
            Bout::Entier(2),
            Bout::Entier(3),
        ]),
        octets(&[
            Bout::Entier(0x04),
            Bout::Entier(7),
            Bout::Entier(42),
            Bout::Entier(1_000),
        ]),
        octets(&[Bout::Entier(0x05), Bout::Entier(7), Bout::Entier(42)]),
        octets(&[
            Bout::Entier(0x06),
            Bout::Entier(16),
            Bout::Entier(5),
            Bout::Octets(b"salut"),
        ]),
        octets(&[Bout::Entier(0x07), Bout::Entier(3), Bout::Octets(b"abc")]),
        // Les quatre formes de `STREAM` qui portent une longueur : les autres
        // vont jusqu'au bout du paquet, et se lisent donc court par
        // construction.
        octets(&[
            Bout::Entier(0x0a),
            Bout::Entier(9),
            Bout::Entier(5),
            Bout::Octets(b"douze"),
        ]),
        octets(&[
            Bout::Entier(0x0b),
            Bout::Entier(9),
            Bout::Entier(5),
            Bout::Octets(b"douze"),
        ]),
        octets(&[
            Bout::Entier(0x0e),
            Bout::Entier(9),
            Bout::Entier(1_000),
            Bout::Entier(5),
            Bout::Octets(b"douze"),
        ]),
        octets(&[
            Bout::Entier(0x0f),
            Bout::Entier(9),
            Bout::Entier(1_000),
            Bout::Entier(5),
            Bout::Octets(b"douze"),
        ]),
        octets(&[Bout::Entier(0x10), Bout::Entier(65_536)]),
        octets(&[Bout::Entier(0x11), Bout::Entier(3), Bout::Entier(4_096)]),
        octets(&[Bout::Entier(0x12), Bout::Entier(100)]),
        octets(&[Bout::Entier(0x13), Bout::Entier(100)]),
        octets(&[Bout::Entier(0x14), Bout::Entier(99)]),
        octets(&[Bout::Entier(0x15), Bout::Entier(3), Bout::Entier(99)]),
        octets(&[Bout::Entier(0x16), Bout::Entier(100)]),
        octets(&[Bout::Entier(0x17), Bout::Entier(100)]),
        octets(&[
            Bout::Octets(&[0x18]),
            Bout::Entier(4),
            Bout::Entier(2),
            Bout::Octets(&[3, 0xaa, 0xbb, 0xcc]),
            Bout::Octets(&jeton),
        ]),
        octets(&[Bout::Entier(0x19), Bout::Entier(2)]),
    ];
    for entiere in &entieres {
        assert!(Frame::parse(entiere).is_ok(), "{entiere:02x?}");
        for coupure in 1..entiere.len() {
            let court = entiere.get(..coupure).expect("préfixe");
            assert!(
                Frame::parse(court).is_err(),
                "coupure {coupure} de {entiere:02x?}"
            );
        }
    }

    // Les trames de chemin et les fermetures, avec leurs octets bruts.
    for entiere in [
        octets(&[Bout::Octets(&[0x1a]), Bout::Octets(&huit)]),
        octets(&[Bout::Octets(&[0x1b]), Bout::Octets(&huit)]),
        octets(&[
            Bout::Entier(0x1c),
            Bout::Entier(0x0a),
            Bout::Entier(0x08),
            Bout::Entier(5),
            Bout::Octets(b"assez"),
        ]),
        octets(&[
            Bout::Entier(0x1d),
            Bout::Entier(0x0a),
            Bout::Entier(5),
            Bout::Octets(b"assez"),
        ]),
    ] {
        assert!(Frame::parse(&entiere).is_ok(), "{entiere:02x?}");
        for coupure in 1..entiere.len() {
            let court = entiere.get(..coupure).expect("préfixe");
            assert!(
                Frame::parse(court).is_err(),
                "coupure {coupure} de {entiere:02x?}"
            );
        }
    }
}
