// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le magasin de comptes, **modifiable pendant que le serveur sert**.
//!
//! # CE QU'IL REMPLACE, ET POURQUOI IL A FALLU LE REMPLACER
//!
//! Les comptes étaient un `Arc<Vec<Account>>` lu une fois au démarrage. C'était
//! juste tant que rien ne les changeait : SMTP, IMAP, POP3 et l'API lisaient la
//! même tranche, sans verrou, sans coût. Ouvrir l'administration en écriture le
//! rend faux — il faut que ce qu'un administrateur change soit vu par les quatre,
//! tout de suite, sans arrêter le service.
//!
//! # LA MACHINERIE N'EST PLUS ICI, ET C'EST VOULU
//!
//! Veille du disque, verrou entre programmes, « on écrit d'abord, on publie
//! ensuite » : tout cela vit dans [`crate::magasin`], parce que le magasin
//! d'appareils en demande exactement la même. Ce qui reste ici est ce qui est
//! propre aux comptes — le type rangé, et les deux fonctions du codec.

use std::vec::Vec;

use ams_auth::Account;

use crate::magasin::{Contenu, Magasin};

pub use crate::magasin::Faute;
#[cfg(test)]
pub(crate) use crate::magasin::REGARD;

/// Comment nommer un compte qu'on ne trouve pas.
///
/// **UNE CONSTANTE PLUTÔT QU'UNE CHAÎNE RÉPÉTÉE** : l'API la construit en trois
/// endroits, et trois formulations légèrement différentes dans un journal se
/// cherchent trois fois.
pub const INTROUVABLE: Faute = Faute::Introuvable(DesComptes::INTROUVABLE);

/// Ce qui distingue le magasin de comptes de tout autre.
#[derive(Debug)]
pub struct DesComptes;

impl Contenu for DesComptes {
    type Element = Account;

    const INTROUVABLE: &'static str = "ce compte";

    fn lire(octets: &[u8]) -> Result<Vec<Account>, ams_config::Error> {
        ams_config::decode_accounts(octets)
    }

    fn ecrire(comptes: &[Account]) -> Result<Vec<u8>, ams_config::Error> {
        ams_config::encode_accounts(comptes)
    }
}

/// Les comptes du serveur, et le fichier dont ils sont la vue.
pub type Comptes = Magasin<DesComptes>;

#[cfg(test)]
mod tests;
