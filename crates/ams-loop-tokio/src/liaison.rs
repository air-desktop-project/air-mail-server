// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les octets qui lient une authentification à SON canal TLS (RFC 9266).
//!
//! # CE QUE LA LIAISON EMPÊCHE, ET QUE TLS SEUL N'EMPÊCHE PAS
//!
//! Un intermédiaire qui tient un certificat valide pour ce nom peut ouvrir DEUX
//! sessions TLS — une avec le client, une avec le serveur — et relayer l'échange
//! SASL mot pour mot. Les deux côtés voient du chiffrement, la preuve SCRAM est
//! juste, et la session s'ouvre au nom du compte.
//!
//! La liaison ferme cela : le client mêle à sa preuve un secret **dérivé de son
//! propre canal**, que l'intermédiaire ne peut pas reproduire sur l'autre. Les
//! deux canaux diffèrent ; la preuve ne correspond plus.
//!
//! # POURQUOI SEULEMENT EN TLS 1.3, ET CE QUE CE REFUS COÛTE
//!
//! §4.2 de RFC 9266 : la liaison n'est définie que si la poignée de main produit
//! des secrets maîtres UNIQUES. C'est toujours vrai en 1.3 ; en 1.2, cela
//! suppose le secret maître étendu de RFC 7627 — **et `rustls` n'expose pas si
//! celui-ci a été négocié**. On ne peut donc pas le PROUVER pour une session 1.2,
//! et une liaison qu'on ne peut pas prouver ne vaut pas mieux que pas de liaison
//! du tout : elle en a seulement l'air.
//!
//! Le coût est nul pour la sécurité et mince en pratique : un client qui parle
//! 1.2 obtient `SCRAM-SHA-256` sans liaison, qui reste ce que ce serveur offrait
//! la veille. Le jour où `rustls` dira ce qu'il en est du secret maître étendu,
//! ce fichier est le seul à changer.

use ams_sasl::{LIAISON_CONTEXTE, LIAISON_ETIQUETTE, LIAISON_OCTETS};
use rustls::ProtocolVersion;

/// Les octets de liaison de ce canal, s'il s'en lie un.
///
/// **LE CONTEXTE EST UNE CHAÎNE VIDE, ET NON L'ABSENCE DE CONTEXTE** : RFC 5705
/// §4 distingue les deux, et ils rendent des octets différents. Se tromper ici
/// ferait échouer toute authentification `-PLUS` par « mot de passe invalide »,
/// sans que rien ne dise pourquoi.
pub(crate) fn liaison_de(connexion: &rustls::ServerConnection) -> Option<[u8; LIAISON_OCTETS]> {
    if connexion.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return None;
    }
    connexion
        .export_keying_material(
            [0_u8; LIAISON_OCTETS],
            LIAISON_ETIQUETTE,
            Some(LIAISON_CONTEXTE),
        )
        .ok()
}
