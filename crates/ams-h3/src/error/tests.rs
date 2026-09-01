// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que §8.1 fait lire au pair.

use ams_proto_h3::H3Error;

use super::{Error, Reason};

/// **CHAQUE FAUTE PORTE LE CODE QUE LE PAIR LIRA**, et ils ne se valent pas.
///
/// §8.1 range les fautes d'HTTP/3 dans l'espace des codes applicatifs de QUIC :
/// c'est celui-là que le pair trouvera dans son journal pour comprendre ce qu'il
/// a fait de travers. Lui dire « erreur interne » quand il a oublié ses réglages
/// l'enverrait chercher au mauvais endroit.
#[test]
fn chaque_faute_porte_son_code() {
    let cas = [
        (
            Error::depuis_h3(ams_proto_h3::Error::new(
                ams_proto_h3::Reason::MissingSettings,
            )),
            H3Error::MissingSettings.value(),
            "la grammaire",
        ),
        (
            Error::transport(),
            H3Error::InternalError.value(),
            "le transport",
        ),
        (Error::interne(), H3Error::InternalError.value(), "tampon"),
        (Error::malformee(), H3Error::FrameError.value(), "contrôle"),
        (
            Error::excessive(),
            H3Error::ExcessiveLoad.value(),
            "dépasse ce qu'on lui a annoncé",
        ),
    ];
    for (faute, code, dit) in cas {
        assert_eq!(faute.close_code(), code, "pour {dit}");
        let phrase = std::format!("{faute}");
        assert!(phrase.contains(dit), "{phrase} devrait parler de {dit}");
    }
}

/// **LA RAISON SE RELIT**, et c'est ce qui la rend éprouvable.
#[test]
fn la_raison_se_relit() {
    let faute = Error::new(Reason::Malformee);
    assert_eq!(faute.reason(), Reason::Malformee);
    assert_eq!(faute, Error::malformee());
}
