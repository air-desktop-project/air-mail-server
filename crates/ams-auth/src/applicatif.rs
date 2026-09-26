// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les mots de passe applicatifs : **un secret par client, et non un par
//! compte.**
//!
//! # CE QU'ILS RÉSOLVENT
//!
//! Thunderbird et Apple Mail ne connaissent que l'identifiant et le mot de
//! passe. Avec un seul secret par compte, révoquer le Thunderbird d'un poste
//! perdu oblige à changer le mot de passe, donc à reconfigurer tous les autres
//! clients ; et rien ne dit lequel s'en sert. Un mot de passe applicatif est
//! nommé, daté, et se révoque seul.
//!
//! # LE SERVEUR LES TIRE, ET C'EST CE QUI PERMET DE NE PAS LES HACHER LENTEMENT
//!
//! Un mot de passe humain se choisit, se réemploie, se devine : il lui faut
//! Argon2id. Celui-ci porte **cent vingt-huit bits d'aléa tirés du noyau** —
//! aucun dictionnaire ne l'atteint, et un SHA-256 suffit à ce qu'une fuite du
//! magasin ne le livre pas. C'est la pratique des jetons d'accès de GitHub et
//! de GitLab.
//!
//! # IL PORTE SON PROPRE IDENTIFIANT, ET C'EST CE QUI REND LE TEMPS MUET
//!
//! `amsp-<identifiant>-<secret>`. La vérification lit l'identifiant, trouve
//! l'entrée, et compare UN condensat. Sans lui, il faudrait essayer chaque
//! entrée du compte à son tour : le temps d'un refus dirait combien le compte
//! en a, et chaque tentative coûterait autant d'essais.
//!
//! # CE QU'IL N'OUVRE PAS
//!
//! **SCRAM** : son `server-first` annonce un sel avant toute preuve, donc pour
//! un seul secret par identifiant ; il reste celui du mot de passe principal.
//! Un mot de passe applicatif passe en `PLAIN`, toujours sous TLS.
//!
//! **L'API REST** : c'est à l'appelant de ne pas l'y admettre. Un jeton obtenu
//! par lui pourrait créer d'autres mots de passe applicatifs — le client de
//! courrier d'un poste perdu deviendrait une fabrique d'accès.

use alloc::string::String;

use ams_sasl::{Credentials, egales, sha256};

use crate::store::{Account, est_ce_compte};

/// Ce par quoi tout mot de passe applicatif commence.
///
/// **UN PRÉFIXE, POUR QU'UN SECRET FUI SE RECONNAISSE** — dans un journal, un
/// dépôt, un ticket —, et pour que la vérification sache sans rien essayer
/// quel chemin prendre.
pub const PREFIXE: &str = "amsp-";

/// Les chiffres hexadécimaux de l'identifiant : huit octets.
pub const ID_CHIFFRES: usize = 16;

/// Les chiffres hexadécimaux du secret : seize octets, cent vingt-huit bits.
pub const SECRET_CHIFFRES: usize = 32;

/// Les octets d'aléa qu'il faut pour en tirer un.
pub const ALEA_OCTETS: usize = (ID_CHIFFRES + SECRET_CHIFFRES) / 2;

/// La longueur exacte d'un mot de passe applicatif.
pub const LONGUEUR: usize = PREFIXE.len() + ID_CHIFFRES + 1 + SECRET_CHIFFRES;

/// Un mot de passe applicatif, tel qu'il se range.
///
/// **LE SECRET N'Y EST PAS** : seul son condensat l'est. Le secret est montré
/// UNE fois, à sa création, et nulle part ensuite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPassword {
    /// Le compte qu'il ouvre.
    pub login: String,
    /// Son identifiant : les seize chiffres hexadécimaux qu'il porte.
    pub id: String,
    /// Le nom que son propriétaire lui a donné — « Thunderbird du bureau ».
    pub name: String,
    /// Quand il a été créé, en secondes depuis l'époque.
    pub created: u64,
    /// Quand il a servi pour la dernière fois, en secondes ; zéro s'il n'a
    /// jamais servi.
    ///
    /// **À L'HEURE PRÈS, ET NON À LA SECONDE** : l'écrire à chaque ouverture de
    /// session ferait une écriture disque par relève de courrier. Ce que son
    /// propriétaire veut savoir est « ce client sert-il encore ? », et l'heure
    /// y répond.
    pub last_used: u64,
    /// Le condensat SHA-256 du mot de passe entier, préfixe compris.
    pub digest: [u8; 32],
}

/// Ce que des identifiants ont ouvert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ouverture {
    /// Rien.
    Refusee,
    /// Le compte, par son mot de passe principal.
    Principal,
    /// Le compte, par ce mot de passe applicatif — dont voici l'identifiant,
    /// pour que l'appelant note qu'il a servi.
    Applicatif(String),
}

/// Fabrique un mot de passe applicatif à partir d'aléa, et rend
/// `(identifiant, mot de passe, condensat)`.
///
/// L'aléa vient de l'appelant : cette crate ne sait pas tirer au sort (C1).
#[must_use]
pub fn fabriquer(alea: &[u8; ALEA_OCTETS]) -> (String, String, [u8; 32]) {
    let (id, secret) = alea.split_at(ID_CHIFFRES / 2);
    let id = hexadecimal(id);
    let mut mot = String::with_capacity(LONGUEUR);
    mot.push_str(PREFIXE);
    mot.push_str(&id);
    mot.push('-');
    mot.push_str(&hexadecimal(secret));
    let condensat = sha256(mot.as_bytes());
    (id, mot, condensat)
}

/// L'identifiant que porte ce mot de passe, s'il a la forme d'un mot de passe
/// applicatif.
///
/// **LA FORME EXACTE, ET RIEN D'APPROCHANT** : préfixe, seize chiffres
/// hexadécimaux MINUSCULES, un tiret, trente-deux autres. Accepter les
/// majuscules donnerait deux écritures d'un même secret, et deux condensats.
#[must_use]
pub fn identifiant(mot_de_passe: &[u8]) -> Option<&str> {
    if mot_de_passe.len() != LONGUEUR {
        return None;
    }
    let reste = mot_de_passe.strip_prefix(PREFIXE.as_bytes())?;
    let (id, reste) = reste.split_at(ID_CHIFFRES);
    let (tiret, secret) = reste.split_at(1);
    if tiret != b"-" || !id.iter().chain(secret).all(|octet| est_hexa(*octet)) {
        return None;
    }
    core::str::from_utf8(id).ok()
}

/// Ces identifiants ouvrent-ils une session, et par quel secret ?
///
/// # DEUX CHEMINS, ET LA FORME DU MOT DE PASSE CHOISIT
///
/// Un mot de passe de la forme `amsp-…` ne se vérifie QUE comme mot de passe
/// applicatif ; tout autre, que comme mot de passe principal. Essayer les deux
/// coûterait un Argon2id à chaque mot de passe applicatif, pour le seul cas
/// d'un mot de passe principal qui aurait exactement cette forme — ce que
/// l'API refuse de poser.
///
/// # LE TEMPS NE DIT NI SI LE COMPTE EXISTE, NI SI L'ENTRÉE EXISTE
///
/// Sur le chemin applicatif, un compte ou une entrée introuvables se comparent
/// tout de même, à un condensat qu'aucun mot de passe ne produit. Le chemin
/// principal garde sa propre règle — [`crate::authenticate`] passe par
/// l'empreinte factice.
#[must_use]
pub fn authenticate_all(
    accounts: &[Account],
    applicatifs: &[AppPassword],
    credentials: &Credentials<'_>,
) -> Ouverture {
    let Some(id) = identifiant(credentials.password) else {
        return match crate::authenticate(accounts, credentials) {
            true => Ouverture::Principal,
            false => Ouverture::Refusee,
        };
    };
    // La même règle que le chemin principal : ce serveur ne délègue pas.
    if !credentials.authorization_identity.is_empty()
        && credentials.authorization_identity != credentials.authentication_identity
    {
        return Ouverture::Refusee;
    }
    let compte = accounts
        .iter()
        .find(|compte| est_ce_compte(compte, credentials.authentication_identity));
    let entree = compte.and_then(|compte| {
        applicatifs
            .iter()
            .find(|entree| entree.login == compte.login && entree.id == id)
    });
    // **UN CONDENSAT QU'AUCUN MOT DE PASSE NE PRODUIT** quand rien n'est
    // trouvé : on compare quand même, et l'on refuse ensuite.
    let attendu = entree.map_or([0_u8; 32], |entree| entree.digest);
    let juste = egales(&sha256(credentials.password), &attendu);
    match (juste, entree) {
        (true, Some(entree)) => Ouverture::Applicatif(entree.id.clone()),
        _ => Ouverture::Refusee,
    }
}

/// Un chiffre hexadécimal minuscule.
fn est_hexa(octet: u8) -> bool {
    octet.is_ascii_digit() || (b'a'..=b'f').contains(&octet)
}

/// Des octets, en hexadécimal minuscule.
fn hexadecimal(octets: &[u8]) -> String {
    const CHIFFRES: &[u8; 16] = b"0123456789abcdef";
    let mut sortie = String::with_capacity(octets.len().saturating_mul(2));
    for octet in octets {
        for moitie in [octet >> 4, octet & 0x0f] {
            sortie.push(char::from(
                CHIFFRES.get(usize::from(moitie)).copied().unwrap_or(b'0'),
            ));
        }
    }
    sortie
}

#[cfg(test)]
mod tests;
