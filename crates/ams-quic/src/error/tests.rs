// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une faute dit, et si elle ferme ou non.

use ams_proto_quic::TransportError;

use super::{Error, Reason};

/// **UN PAQUET QU'ON JETTE N'A PAS DE CODE**, et une faute qui ferme en a un.
/// C'est la même question posée deux fois, et elle ne peut pas diverger.
#[test]
fn jeter_et_ne_pas_avoir_de_code_sont_la_meme_chose() {
    let cas = [
        (Reason::NotForUs, None, "sache lire"),
        (Reason::NotAuthentic, None, "s'authentifie pas"),
        (
            Reason::ReservedBitsSet,
            Some(TransportError::ProtocolViolation),
            "bits réservés",
        ),
        (
            Reason::BadPacketNumber,
            Some(TransportError::ProtocolViolation),
            "ne se reconstruit pas",
        ),
    ];
    for (raison, code, morceau) in cas {
        let faute = Error::new(raison);
        assert_eq!(faute.reason(), raison);
        assert_eq!(faute.code(), code, "{raison:?}");
        assert_eq!(
            faute.se_jette(),
            code.is_none(),
            "{raison:?} : jeter et n'avoir pas de code doivent coïncider"
        );
        let dit = std::format!("{faute}");
        assert!(dit.contains(morceau), "{raison:?} dit « {dit} »");
        // Et le message dit ce qu'on va faire du paquet.
        let suite = match faute.se_jette() {
            true => "on le jette",
            false => "on ferme",
        };
        assert!(dit.contains(suite), "{raison:?} ne dit pas la suite");
    }
}
