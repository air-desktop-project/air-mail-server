// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le vérificateur SCRAM : ce qu'on dérive du mot de passe, et **comment on le
//! range sans trahir la raison d'être de ce magasin**.
//!
//! # LE PROBLÈME, ÉCRIT AVANT LA SOLUTION
//!
//! `store.rs` énonce la règle de cette crate : « une fuite du fichier de
//! comptes ne doit pas être une fuite des mots de passe ». Le vérificateur de
//! RFC 5802 la contredit deux fois, et c'est pourquoi SCRAM avait été refusé le
//! 2026-09-06 :
//!
//! 1. **il se dérive par PBKDF2** (§2.2), que la RFC impose parce que c'est le
//!    CLIENT qui le calcule. On ne peut pas y substituer l'`argon2id` du
//!    magasin sans cesser d'interopérer, et un magasin portant les deux serait
//!    attaquable par le plus faible ;
//! 2. **il est directement exploitable** : §9 dit qu'une `ServerKey` permet
//!    d'usurper le SERVEUR auprès des clients, et qu'une conversation écoutée
//!    suffit alors à reconstituer `ClientKey`. Là où une empreinte `argon2id`
//!    demande d'abord d'être cassée, celle-là s'emploie telle quelle.
//!
//! # CE QUI LE REND ACCEPTABLE : IL NE VIT PAS AVEC LES COMPTES, ET IL EST SCELLÉ
//!
//! Le refus du 2026-09-06 nommait lui-même sa troisième condition de
//! renversement : « un magasin où le vérificateur SCRAM vivrait SÉPARÉMENT,
//! chiffré par une clé que le fichier de comptes ne porte pas ». C'est ce que
//! ce module construit.
//!
//! - **Les deux clés sont scellées** en `ChaCha20-Poly1305` sous une clé de
//!   trente-deux octets que l'exploitant range où il veut — un autre montage,
//!   un autre support. Le fichier de comptes ne la porte pas, et le magasin
//!   SCRAM non plus.
//! - **Le sel et le compte d'itérations restent en clair**, et c'est voulu : le
//!   serveur les envoie au client dans le `server-first`, avant toute preuve.
//!   Les sceller n'aurait protégé rien du tout, et aurait donné l'illusion
//!   contraire.
//! - **Le login entre dans les données associées** du scellement : un
//!   vérificateur déplacé d'un compte à l'autre dans le fichier ne s'ouvre pas.
//!   Sans cela, qui peut écrire le magasin sans connaître la clé pourrait
//!   donner à `contact` le vérificateur d'un compte dont il connaît le mot de
//!   passe.
//!
//! **CE QUE CELA NE PROTÈGE PAS**, et qu'il faut écrire plutôt que taire : un
//! serveur en marche tient la clé en mémoire. Qui lit la mémoire du processus,
//! ou qui prend la clé ET le magasin, a les deux `ServerKey`. Le scellement
//! protège de la fuite d'un fichier, pas de la compromission d'une machine.

use alloc::vec::Vec;

use ams_sasl::{CLE_OCTETS, client_key, derive_salted_password, server_key, stored_key};
use chacha20poly1305::aead::{Aead, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// La boîte de scellement, montée sur une clé de trente-deux octets.
///
/// `Key::from_slice` est déconseillée par l'amont au profit de `TryFrom` ; les
/// deux tailles sont des CONSTANTES de ce module, donc la conversion ne peut
/// pas échouer — et un `expect` ouvrirait une branche qu'aucun essai ne peut
/// atteindre (C2). `Array::from` sur un tableau de la bonne taille est
/// infaillible, et le vérifie à la compilation.
fn boite(clef: &[u8; CLE_SCELLEMENT_OCTETS]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&Key::from(*clef))
}

/// Ce que le sel d'un compte occupe.
///
/// Seize octets : §5.1 de RFC 5802 n'impose pas de taille, et seize est ce que
/// l'exemple de RFC 7677 emploie. C'est assez pour qu'aucun sel ne se répète,
/// et c'est ce qui compte — un sel n'est pas un secret, il est unique.
pub const SEL_OCTETS: usize = 16;

/// Le nonce de `ChaCha20-Poly1305` : douze octets, RFC 8439.
pub const NONCE_OCTETS: usize = 12;

/// Ce que la clé de scellement occupe.
pub const CLE_SCELLEMENT_OCTETS: usize = 32;

/// Le compte d'itérations que ce produit pose aux comptes neufs.
///
/// **TRENTE-DEUX MILLE SEPT CENT SOIXANTE-HUIT**, quand RFC 7677 §3.1 exige au
/// moins 4 096. Le choix n'est pas libre dans le sens qu'on croit : **c'est le
/// CLIENT qui paie ce coût**, à chaque ouverture de session, et sur le téléphone
/// de quelqu'un. Huit fois le minimum reste imperceptible là-bas — quelques
/// dizaines de millisecondes — et multiplie par huit le travail d'une attaque
/// hors ligne. Au-delà, on punirait surtout les appareils lents.
///
/// C'est aussi pourquoi ce n'est pas `argon2id` : PBKDF2 n'a pas de coût
/// mémoire, donc pas de résistance au matériel dédié. Le scellement du magasin
/// est ce qui compense ; le compte d'itérations n'est qu'un renchérissement.
pub const ITERATIONS: u32 = 32_768;

/// Le vérificateur d'un compte, tel qu'il se range.
///
/// **`stored_key` ET `server_key` NE SONT JAMAIS EN CLAIR DANS CE TYPE** : le
/// champ scellé les porte ensemble, et [`ouvrir`] est le seul moyen de les
/// obtenir — avec la clé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verificateur {
    /// Le sel, en clair : le serveur l'annonce dans le `server-first`.
    pub sel: [u8; SEL_OCTETS],
    /// Le compte d'itérations, en clair : annoncé lui aussi.
    pub iterations: u32,
    /// Le nonce du scellement.
    pub nonce: [u8; NONCE_OCTETS],
    /// `StoredKey ‖ ServerKey`, scellées — soixante-quatre octets et le sceau.
    pub scelle: Vec<u8>,
}

/// Les deux clés, une fois ouvertes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cles {
    /// `StoredKey` : ce à quoi le serveur compare la preuve du client.
    pub stored: [u8; CLE_OCTETS],
    /// `ServerKey` : ce avec quoi il signe le `server-final`.
    pub server: [u8; CLE_OCTETS],
}

/// Ce qui peut mal se passer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Le scellement n'a pas pu être défait.
    ///
    /// **UNE SEULE VARIANTE POUR TROIS CAUSES** — mauvaise clé, données
    /// altérées, vérificateur attribué à un autre login —, et c'est délibéré :
    /// les distinguer apprendrait à qui tâtonne laquelle des trois il a
    /// touchée.
    Sceau,
    /// Le contenu scellé ne fait pas la taille des deux clés.
    Taille,
}

/// Dérive un vérificateur **au moment où l'on tient le mot de passe en clair**.
///
/// C'est-à-dire à trois endroits, et nulle part ailleurs : `account add`,
/// `account passwd`, et la route `/v1/me/password`. Le magasin ne sait pas
/// fabriquer un vérificateur pour un compte dont il n'a que l'empreinte
/// `argon2id` — c'est la propriété même d'une fonction de dérivation.
///
/// `sel` et `nonce` viennent de l'appelant : cette crate ne sait pas tirer au
/// sort (C1), et le hasard est une entrée-sortie.
///
/// # Errors
///
/// [`Error::Sceau`] — le scellement a échoué, ce qu'aucune entrée ne devrait
/// provoquer.
pub fn deriver(
    mot_de_passe: &[u8],
    login: &[u8],
    sel: [u8; SEL_OCTETS],
    iterations: u32,
    nonce: [u8; NONCE_OCTETS],
    clef: &[u8; CLE_SCELLEMENT_OCTETS],
) -> Result<Verificateur, Error> {
    let salted = derive_salted_password(mot_de_passe, &sel, iterations);
    let stored = stored_key(&client_key(&salted));
    let server = server_key(&salted);
    let mut clair = [0_u8; CLE_OCTETS * 2];
    for (place, octet) in clair.iter_mut().zip(stored.iter().chain(server.iter())) {
        *place = *octet;
    }
    // **`map` PLUTÔT QUE `?`**, et ce n'est pas du style : le `?` ouvre une
    // branche d'échec que rien ne peut prendre — `encrypt` sur un tampon en
    // mémoire de soixante-quatre octets ne peut pas échouer —, et C2 refuse les
    // gardes inatteignables. L'erreur reste dans la signature parce que c'est
    // l'amont qui la déclare, et qu'on ne la masque pas.
    sceller(&clair, login, &nonce, clef).map(|scelle| Verificateur {
        sel,
        iterations,
        nonce,
        scelle,
    })
}

/// Ouvre un vérificateur : rend les deux clés, ou refuse.
///
/// # Errors
///
/// [`Error::Sceau`] — mauvaise clé, données altérées, ou vérificateur qui
/// n'appartient pas à ce `login` ; [`Error::Taille`] — le clair n'a pas la
/// longueur des deux clés.
pub fn ouvrir(
    verificateur: &Verificateur,
    login: &[u8],
    clef: &[u8; CLE_SCELLEMENT_OCTETS],
) -> Result<Cles, Error> {
    let clair = boite(clef)
        .decrypt(
            &Nonce::from(verificateur.nonce),
            Payload {
                msg: &verificateur.scelle,
                aad: login,
            },
        )
        .map_err(|_| Error::Sceau)?;
    if clair.len() != CLE_OCTETS * 2 {
        return Err(Error::Taille);
    }
    let mut stored = [0_u8; CLE_OCTETS];
    let mut server = [0_u8; CLE_OCTETS];
    for (place, octet) in stored
        .iter_mut()
        .zip(clair.get(..CLE_OCTETS).unwrap_or_default())
    {
        *place = *octet;
    }
    for (place, octet) in server
        .iter_mut()
        .zip(clair.get(CLE_OCTETS..).unwrap_or_default())
    {
        *place = *octet;
    }
    Ok(Cles { stored, server })
}

/// Le sel **factice** d'un compte que le magasin ne connaît pas.
///
/// # POURQUOI IL EXISTE, ET POURQUOI IL EST DÉTERMINISTE
///
/// §7 de RFC 5802 le dit : refuser tout de suite un compte inconnu rendrait le
/// magasin énumérable sans connaître un seul mot de passe. Le serveur doit donc
/// répondre un `server-first` plausible, et n'échouer qu'à la preuve.
///
/// **Un sel TIRÉ AU SORT ne suffirait pas** : il changerait à chaque tentative,
/// là où un vrai compte rend toujours le même. Deux essais suffiraient à
/// distinguer. Celui-ci se dérive de la clé de scellement et du login, donc il
/// est stable dans le temps, différent d'un compte à l'autre, et
/// imprévisible pour qui n'a pas la clé.
///
/// **ET LES ITÉRATIONS DOIVENT ÊTRE CELLES DU PRODUIT**, que l'appelant annonce
/// avec : un compte inconnu qui rendrait 4 096 quand les vrais en rendent 32 768
/// se trahirait par ce seul nombre.
#[must_use]
pub fn sel_factice(login: &[u8], clef: &[u8; CLE_SCELLEMENT_OCTETS]) -> [u8; SEL_OCTETS] {
    let empreinte = ams_sasl::hmac_sha256(clef, login);
    let mut sel = [0_u8; SEL_OCTETS];
    for (place, octet) in sel.iter_mut().zip(empreinte) {
        *place = octet;
    }
    sel
}

/// Scelle `clair` sous `clef`, avec `login` en données associées.
fn sceller(
    clair: &[u8],
    login: &[u8],
    nonce: &[u8; NONCE_OCTETS],
    clef: &[u8; CLE_SCELLEMENT_OCTETS],
) -> Result<Vec<u8>, Error> {
    boite(clef)
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: clair,
                aad: login,
            },
        )
        .map_err(|_| Error::Sceau)
}

#[cfg(test)]
mod tests;
