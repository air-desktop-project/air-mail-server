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
//! - **L'empreinte du mot de passe y entre aussi** — celle, `argon2id`, que le
//!   fichier de comptes porte au même instant. Un vérificateur ne s'ouvre donc
//!   que tant que le compte a ENCORE le mot de passe dont il a été dérivé.
//!   Changer ce mot de passe par n'importe quel chemin — l'API, l'outil
//!   d'administration, un outil qui n'existe pas encore — éteint l'ancien
//!   vérificateur sans que ce chemin ait à y penser. Voir [`Verificateur::lie`].
//!
//! **CE QUE CELA NE PROTÈGE PAS**, et qu'il faut écrire plutôt que taire : un
//! serveur en marche tient la clé en mémoire. Qui lit la mémoire du processus,
//! ou qui prend la clé ET le magasin, a les deux `ServerKey`. Le scellement
//! protège de la fuite d'un fichier, pas de la compromission d'une machine.

use alloc::string::String;
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
    /// Le compte auquel ce vérificateur appartient.
    ///
    /// **IL EST AUSSI LES DONNÉES ASSOCIÉES DU SCELLEMENT**, et c'est ce qui
    /// fait qu'une entrée déplacée d'un compte à l'autre ne s'ouvre pas. Le
    /// porter DANS le type plutôt que le passer à [`ouvrir`] retire la seule
    /// façon de se tromper : donner à l'ouverture un autre login que celui
    /// sous lequel l'entrée a été scellée.
    pub login: String,
    /// Le sel, en clair : le serveur l'annonce dans le `server-first`.
    pub sel: [u8; SEL_OCTETS],
    /// Le compte d'itérations, en clair : annoncé lui aussi.
    pub iterations: u32,
    /// Le nonce du scellement.
    pub nonce: [u8; NONCE_OCTETS],
    /// `StoredKey ‖ ServerKey`, scellées — soixante-quatre octets et le sceau.
    pub scelle: Vec<u8>,
    /// Le scellement couvre-t-il AUSSI l'empreinte du mot de passe du compte ?
    ///
    /// # POURQUOI CE CHAMP EXISTE
    ///
    /// Jusqu'en 0.2.15, le magasin SCRAM et le fichier de comptes ne se
    /// connaissaient pas : changer un mot de passe par l'API laissait l'ancien
    /// vérificateur en place, et **l'ancien mot de passe ouvrait encore la
    /// boîte par SCRAM**. Un vérificateur LIÉ scelle l'empreinte `argon2id` du
    /// compte dans ses données associées : dès que le compte change de mot de
    /// passe, il cesse de s'ouvrir.
    ///
    /// **UN VÉRIFICATEUR NON LIÉ NE S'OUVRE PLUS** — [`Error::NonLie`]. Ceux
    /// qu'ont écrits les versions précédentes se lient une fois pour toutes par
    /// [`lier`], que l'outil d'administration expose.
    pub lie: bool,
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
    /// Le vérificateur n'est pas lié à l'empreinte du compte : écrit par une
    /// version antérieure à 0.2.16, il ne s'ouvre plus tant qu'on ne l'a pas
    /// lié. Voir [`Verificateur::lie`].
    NonLie,
}

/// Dérive un vérificateur **au moment où l'on tient le mot de passe en clair**.
///
/// C'est-à-dire à `account add`, à `account passwd`, et aux routes de l'API
/// qui posent un mot de passe. Le magasin ne sait pas
/// fabriquer un vérificateur pour un compte dont il n'a que l'empreinte
/// `argon2id` — c'est la propriété même d'une fonction de dérivation.
///
/// `empreinte` est l'empreinte `argon2id` que le fichier de comptes portera
/// pour CE mot de passe : le vérificateur y est lié, et ne s'ouvrira que tant
/// que le compte la porte. Voir [`Verificateur::lie`].
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
    login: &str,
    empreinte: &str,
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
    sceller(&clair, &donnees_liees(login, empreinte), &nonce, clef).map(|scelle| Verificateur {
        login: String::from(login),
        sel,
        iterations,
        nonce,
        scelle,
        lie: true,
    })
}

/// Lie un vérificateur écrit AVANT la 0.2.16 à l'empreinte actuelle du compte.
///
/// # CE QUE L'APPELANT AFFIRME EN L'APPELANT
///
/// **Que ce vérificateur a été dérivé du mot de passe que `empreinte` décrit.**
/// Rien ici ne peut le vérifier : le mot de passe n'est plus là, et c'est tout
/// le problème que la liaison résout pour l'avenir. Lier un vérificateur
/// dérivé d'un ANCIEN mot de passe à l'empreinte du NOUVEAU rouvrirait
/// exactement la porte qu'on ferme — l'outil d'administration le dit à
/// l'exploitant avant qu'il ne l'emploie.
///
/// Un nonce NEUF est exigé : on rescelle le même clair sous d'autres données
/// associées, et réemployer le nonce avec la même clé révélerait le
/// ou-exclusif des deux scellés.
///
/// # Errors
///
/// [`Error::Sceau`] — le vérificateur ne s'ouvre pas sous son login ;
/// [`Error::Taille`] — son clair n'a pas la longueur des deux clés. **Un
/// vérificateur DÉJÀ lié se rend tel quel** : le lier deux fois n'a pas de
/// sens, et le refuser ferait échouer une migration relancée.
pub fn lier(
    verificateur: &Verificateur,
    empreinte: &str,
    nonce: [u8; NONCE_OCTETS],
    clef: &[u8; CLE_SCELLEMENT_OCTETS],
) -> Result<Verificateur, Error> {
    if verificateur.lie {
        return Ok(verificateur.clone());
    }
    let cles = ouvrir_sous(verificateur, verificateur.login.as_bytes(), clef)?;
    let mut clair = [0_u8; CLE_OCTETS * 2];
    for (place, octet) in clair
        .iter_mut()
        .zip(cles.stored.iter().chain(cles.server.iter()))
    {
        *place = *octet;
    }
    sceller(
        &clair,
        &donnees_liees(&verificateur.login, empreinte),
        &nonce,
        clef,
    )
    .map(|scelle| Verificateur {
        login: verificateur.login.clone(),
        sel: verificateur.sel,
        iterations: verificateur.iterations,
        nonce,
        scelle,
        lie: true,
    })
}

/// Les données associées d'un vérificateur lié : le login, un octet nul, et le
/// condensat SHA-256 de l'empreinte du compte.
///
/// **LE CONDENSAT, ET NON L'EMPREINTE ELLE-MÊME** : il a une taille fixe, et
/// l'octet nul qui le précède ne peut pas apparaître dans un login
/// (`check_login`) — le login et l'empreinte ne se recollent donc pas.
fn donnees_liees(login: &str, empreinte: &str) -> Vec<u8> {
    let mut donnees = Vec::with_capacity(login.len().saturating_add(33));
    donnees.extend_from_slice(login.as_bytes());
    donnees.push(0);
    donnees.extend_from_slice(&ams_sasl::sha256(empreinte.as_bytes()));
    donnees
}

/// Ouvre un vérificateur : rend les deux clés, ou refuse.
///
/// Le login vient du vérificateur lui-même : il a été scellé avec, et l'entrée
/// ne s'ouvre donc que sous le compte qui est écrit dedans. `empreinte` est
/// celle que le fichier de comptes porte **maintenant** : le vérificateur ne
/// s'ouvre que si c'est celle dont il a été dérivé.
///
/// # Errors
///
/// [`Error::Sceau`] — mauvaise clé, données altérées, entrée dont le login a
/// été changé, **ou compte qui a changé de mot de passe depuis** ;
/// [`Error::Taille`] — le clair n'a pas la longueur des deux clés ;
/// [`Error::NonLie`] — un vérificateur d'avant la 0.2.16, qu'il faut lier.
pub fn ouvrir(
    verificateur: &Verificateur,
    empreinte: &str,
    clef: &[u8; CLE_SCELLEMENT_OCTETS],
) -> Result<Cles, Error> {
    if !verificateur.lie {
        return Err(Error::NonLie);
    }
    ouvrir_sous(
        verificateur,
        &donnees_liees(&verificateur.login, empreinte),
        clef,
    )
}

/// Ouvre un vérificateur sous ces données associées.
fn ouvrir_sous(
    verificateur: &Verificateur,
    donnees: &[u8],
    clef: &[u8; CLE_SCELLEMENT_OCTETS],
) -> Result<Cles, Error> {
    let clair = boite(clef)
        .decrypt(
            &Nonce::from(verificateur.nonce),
            Payload {
                msg: &verificateur.scelle,
                aad: donnees,
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

/// Scelle `clair` sous `clef`, avec `donnees` en données associées.
fn sceller(
    clair: &[u8],
    donnees: &[u8],
    nonce: &[u8; NONCE_OCTETS],
    clef: &[u8; CLE_SCELLEMENT_OCTETS],
) -> Result<Vec<u8>, Error> {
    boite(clef)
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: clair,
                aad: donnees,
            },
        )
        .map_err(|_| Error::Sceau)
}

#[cfg(test)]
mod tests;
