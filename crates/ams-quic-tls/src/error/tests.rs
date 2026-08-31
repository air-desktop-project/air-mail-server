// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Chaque refus a son code de fermeture, et ils ne se confondent pas.

use ams_proto_quic::TransportError;

use super::{Error, Reason};

/// **CHAQUE RAISON A SON CODE, ET SON MOT.**
///
/// Le tableau est en TOTAL : chaque variante y a sa ligne. Une variante ajoutée
/// sans code réfléchi ferait échouer la compilation du `match` de `close_code`,
/// mais pas ce test — c'est pourquoi il énumère plutôt que de filtrer.
#[test]
fn chaque_raison_a_son_code_et_son_mot() {
    let cas = [
        // §20.1 de RFC 9000 : `INTERNAL_ERROR`. Le pair n'y est pour rien.
        (Reason::NoQuicSuite, 0x01_u64, "provider_quic"),
        // §4.8 : `handshake_failure` (40) donne 0x0128, et la RFC le cite.
        (Reason::Tls(40), 0x0128, "TLS a refusé"),
        (Reason::TlsSansAlerte, 0x0128, "sans produire d'alerte"),
        // §6.2 de RFC 8446 : `no_application_protocol` vaut 120.
        (Reason::WrongAlpn, 0x0178, "h3"),
        (
            Reason::Quic(ams_quic::Reason::CryptoInZeroRtt),
            0x0a,
            "niveaux de chiffrement",
        ),
        (
            Reason::Quic(ams_quic::Reason::CryptoBufferExceeded),
            0x0d,
            "niveaux de chiffrement",
        ),
        (
            Reason::Quic(ams_quic::Reason::CryptoNotConsumed),
            0x0a,
            "niveaux de chiffrement",
        ),
        (
            Reason::Quic(ams_quic::Reason::CryptoAfterLevel),
            0x0a,
            "niveaux de chiffrement",
        ),
    ];
    for (raison, code, morceau) in cas {
        let faute = Error::new(raison);
        assert_eq!(faute.reason(), raison);
        assert_eq!(faute.close_code(), code, "{raison:?}");
        let dit = std::format!("{faute}");
        assert!(dit.contains(morceau), "{raison:?} dit « {dit} »");
        // Et le message dit toujours avec quoi l'on ferme.
        assert!(dit.contains("on ferme avec"), "{raison:?} dit « {dit} »");
    }
}

/// **UNE ALERTE TLS TOMBE TOUJOURS DANS LA PLAGE `CRYPTO_ERROR`** (§4.8).
///
/// C'est ce qui permet au pair de savoir que la cause est TLS, et laquelle.
#[test]
fn une_alerte_tombe_dans_la_plage_crypto_error() {
    for alerte in 0..=u8::MAX {
        let code = Error::new(Reason::Tls(alerte)).close_code();
        assert!(
            (0x0100..=0x01ff).contains(&code),
            "l'alerte {alerte} donne {code:#06x}, hors de la plage"
        );
        assert_eq!(code, 0x0100 | u64::from(alerte));
    }
    // Et deux alertes ne se confondent pas.
    assert_ne!(
        Error::new(Reason::Tls(40)).close_code(),
        Error::new(Reason::Tls(120)).close_code()
    );
}

/// **UN PAQUET QUI SE JETTE N'A PAS DE CODE**, et pourtant il faut bien fermer.
///
/// `ams_quic::Reason::NotAuthentic` rend `None` : ce paquet-là se jette en
/// silence, parce qu'il peut venir de n'importe qui. Mais si une telle raison
/// remontait jusqu'ici, il faudrait quand même un code plutôt qu'une connexion
/// qui se fige — c'est `PROTOCOL_VIOLATION` qu'on écrit alors.
#[test]
fn une_raison_sans_code_ferme_quand_meme() {
    assert_eq!(ams_quic::Reason::NotAuthentic.code(), None);
    assert_eq!(
        Error::new(Reason::Quic(ams_quic::Reason::NotAuthentic)).close_code(),
        TransportError::ProtocolViolation.value()
    );
}

/// **UN REFUS SANS ALERTE RESTE UN REFUS.**
///
/// `rustls` ne produit pas toujours d'alerte quand il refuse — et §4.8 prévoit
/// ce cas : « QUIC permits the use of a generic code in place of a specific
/// error code ». Sans ce bras, un tel refus n'aurait pas de code, et la
/// connexion se figerait jusqu'au délai d'inactivité.
#[test]
fn un_refus_sans_alerte_reste_un_refus() {
    let sans = Error::depuis_alerte(&rustls::Error::HandshakeNotComplete, None);
    assert_eq!(sans.reason(), Reason::TlsSansAlerte);
    assert_eq!(sans.close_code(), 0x0128);

    let avec = Error::depuis_alerte(
        &rustls::Error::HandshakeNotComplete,
        Some(rustls::AlertDescription::BadCertificate),
    );
    // §6.2 de RFC 8446 : `bad_certificate` vaut 42.
    assert_eq!(avec.reason(), Reason::Tls(42));
    assert_eq!(avec.close_code(), 0x012a);
}
