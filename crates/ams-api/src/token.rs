// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les jetons porteurs : ce qu'un client présente au lieu de son mot de passe.
//!
//! # POURQUOI PAS UN JWT
//!
//! Un JWT porte son algorithme DANS le jeton, dans un champ `alg` que le
//! vérificateur est censé lire pour savoir comment vérifier. C'est demander à un
//! message non authentifié comment l'authentifier, et deux familles d'attaques
//! entières vivent dans cette question : `alg: none`, qui supprime la
//! vérification, et la confusion `RS256` → `HS256`, qui fait vérifier une
//! signature avec la clé publique prise pour un secret partagé.
//!
//! **Ce jeton n'a pas de champ d'algorithme.** Sa version en fixe un seul, et il
//! n'y a qu'une version. Il n'existe donc rien à négocier, et par conséquent
//! rien à confondre.
//!
//! # ET IL SE VÉRIFIE AVANT DE SE LIRE
//!
//! L'ordre est la seule chose qui compte ici : on découpe la structure, on
//! vérifie le sceau, **et alors seulement** on interprète les champs. Lire une
//! expiration avant d'avoir authentifié le jeton qui la porte, c'est faire
//! confiance à ce qu'on n'a pas encore vérifié.
//!
//! # LE TEMPS VIENT DE L'APPELANT
//!
//! Cette crate ne lit pas d'horloge (C1). Les instants sont en microsecondes
//! depuis l'époque, comme partout ailleurs dans ce dépôt.

use crate::base64url;
use crate::error::{Error, Reason};
use crate::mac::{egales, hmac_sha256};
use crate::scope::Scope;

/// La seule version de jeton qui existe.
///
/// **ELLE FIXE L'ALGORITHME**, et c'est tout son objet : une version, un
/// algorithme, et rien à négocier.
pub const VERSION: u8 = 0x01;

pub use crate::mac::MAC_OCTETS;

/// La plus petite clé qu'on accepte.
///
/// Trente-deux octets. Une clé plus courte que le sceau qu'elle produit
/// donnerait moins de sécurité que la taille du sceau ne le laisse croire — et
/// c'est la taille du sceau qu'on voit.
pub const KEY_OCTETS_MIN: usize = 32;

/// Ce qu'un nom de compte peut faire de long dans un jeton.
pub const LOGIN_OCTETS_MAX: usize = 64;

/// La plus longue vie qu'on accorde à un jeton, en microsecondes.
///
/// Douze heures. **UN JETON NE SE RÉVOQUE PAS TOUT SEUL** : sa seule fin
/// garantie est son expiration, puisqu'il se vérifie sans consulter quoi que ce
/// soit. Plus il vit, plus longtemps un vol reste utile.
pub const LIFETIME_MAX_US: u64 = 12 * 3_600 * 1_000_000;

/// Ce que la partie en clair occupe, sans le nom de compte.
///
/// Version, portées, expiration, identifiant, longueur du nom.
const ENTETE_OCTETS: usize = 1 + 1 + 8 + 8 + 1;

/// Le plus grand jeton binaire possible.
pub const TOKEN_OCTETS_MAX: usize = ENTETE_OCTETS + LOGIN_OCTETS_MAX + MAC_OCTETS;

/// Ce que le même jeton occupe une fois écrit.
pub const ENCODED_OCTETS_MAX: usize = base64url::encoded_len(TOKEN_OCTETS_MAX);

/// La clé qui scelle les jetons.
///
/// **ELLE NE SE COMPARE PAS, ET NE S'AFFICHE PAS** : pas de `PartialEq`, pas de
/// `Debug` qui la montre. Une clé qui apparaît dans un journal n'est plus une
/// clé.
#[derive(Clone)]
pub struct Key {
    /// Le secret.
    octets: [u8; KEY_OCTETS_MIN],
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // **ON N'ÉCRIT PAS LA CLÉ, MÊME EN DÉBOGAGE.** C'est la seule chose que
        // cette implémentation a à faire, et elle la fait toujours.
        f.write_str("Key(<secret>)")
    }
}

impl Key {
    /// La clé que portent ces octets.
    ///
    /// # Errors
    ///
    /// [`Reason::BadKey`] pour une clé plus courte que [`KEY_OCTETS_MIN`].
    /// **C'est notre faute** : c'est la configuration du serveur qui la fournit.
    pub fn new(octets: &[u8]) -> Result<Self, Error> {
        let lus = octets
            .get(..KEY_OCTETS_MIN)
            .ok_or(Error::new(Reason::BadKey))?;
        let mut clef = [0_u8; KEY_OCTETS_MIN];
        for (ou, lu) in clef.iter_mut().zip(lus) {
            *ou = *lu;
        }
        Ok(Self { octets: clef })
    }
}

/// Ce qu'un jeton dit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token<'o> {
    /// Le compte pour qui il vaut.
    pub login: &'o str,
    /// Ce qu'il ouvre.
    pub scope: Scope,
    /// Quand il cesse de valoir, en microsecondes depuis l'époque.
    pub expiry: u64,
    /// Ce qui l'identifie, pour qu'on puisse le révoquer.
    ///
    /// **SANS LUI, RÉVOQUER UN JETON REVIENDRAIT À RÉVOQUER LE COMPTE** : deux
    /// jetons du même compte avec la même expiration seraient identiques, et
    /// l'on ne saurait pas lequel refuser.
    pub nonce: u64,
}

/// Écrit un jeton scellé, en base64url.
///
/// Ce qui cloche dans un secret de scellement écrit en hexadécimal.
///
/// # POURQUOI TROIS CAS, ET NON UNE SEULE FAUTE
///
/// Celui qui lit ce refus est l'EXPLOITANT, et non un pair : il a écrit la
/// configuration, et il a le droit de savoir ce qu'il doit corriger. « le secret
/// est refusé » l'enverrait relire quarante caractères à la loupe.
///
/// C'est l'exact contraire de ce qu'on dit à un client de l'API, et pour la même
/// raison : ce qui apprend à qui sonde ne doit pas se dire, ce qui aide qui
/// répare doit se dire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProblem {
    /// Un nombre impair de chiffres : un octet s'écrit avec deux.
    OddLength,
    /// Un caractère qui n'est pas un chiffre hexadécimal.
    NotHex,
    /// Moins de [`KEY_OCTETS_MIN`] octets.
    ///
    /// **UNE CLÉ PLUS COURTE QUE LE SCEAU QU'ELLE PRODUIT** donnerait moins de
    /// sécurité que la taille du sceau ne le laisse croire.
    TooShort,
}

/// Lit un secret de scellement écrit en hexadécimal.
///
/// # IL VIT ICI PARCE QUE DEUX BINAIRES LE LISENT
///
/// Le serveur le lit pour vérifier les jetons, l'outil d'administration pour en
/// frapper. **Deux lectures de la même chaîne finiraient par différer** — l'une
/// acceptant une longueur impaire, l'autre non — et un secret réputé bon d'un
/// côté ne serait plus la même clé de l'autre.
///
/// # Errors
///
/// [`KeyProblem`] dit lequel des trois cas.
pub fn key_from_hex(texte: &str) -> Result<Key, KeyProblem> {
    if !texte.len().is_multiple_of(2) {
        return Err(KeyProblem::OddLength);
    }
    let mut octets = [0_u8; KEY_OCTETS_MIN];
    let mut combien = 0_usize;
    for paire in texte.as_bytes().chunks(2) {
        let valeur = core::str::from_utf8(paire)
            .ok()
            .and_then(|deux| u8::from_str_radix(deux, 16).ok())
            .ok_or(KeyProblem::NotHex)?;
        // **ON NE RETIENT QUE CE QUE LA CLÉ PORTE**, et l'on continue de LIRE le
        // reste : un chiffre fautif au-delà du trente-deuxième octet est une
        // faute de configuration, et la taire ferait accepter une chaîne que
        // l'exploitant croit correcte.
        if let Some(place) = octets.get_mut(combien) {
            *place = valeur;
        }
        combien = combien.saturating_add(1);
    }
    if combien < KEY_OCTETS_MIN {
        return Err(KeyProblem::TooShort);
    }
    Key::new(&octets).map_err(|_| KeyProblem::TooShort)
}

/// Rend du texte : l'alphabet de §5 de RFC 4648 est de l'ASCII, et l'appelant
/// n'a donc rien à convertir.
///
/// # Errors
///
/// [`Reason::BadToken`] pour un nom de compte vide ou trop long, ou une
/// expiration qui dépasse [`LIFETIME_MAX_US`] ; [`Reason::BufferTooSmall`] si
/// `sortie` ne suffit pas.
pub fn issue<'o>(
    key: &Key,
    token: &Token<'_>,
    maintenant: u64,
    sortie: &'o mut [u8],
) -> Result<&'o str, Error> {
    let login = token.login.as_bytes();
    if login.is_empty() || login.len() > LOGIN_OCTETS_MAX {
        return Err(Error::new(Reason::BadToken));
    }
    // **UNE VIE PLUS LONGUE QUE LA BORNE SE REFUSE À L'ÉMISSION.** La vérifier
    // seulement à la lecture laisserait circuler des jetons qu'on refuserait
    // ensuite sans que personne ne comprenne pourquoi.
    if token.expiry > maintenant.saturating_add(LIFETIME_MAX_US) {
        return Err(Error::new(Reason::BadToken));
    }

    let mut brut = [0_u8; TOKEN_OCTETS_MAX];
    // Le nom tient sous sa borne, donc ce total tient sous celle du jeton : la
    // découpe est bornée par construction, et une garde ici serait une branche
    // qu'aucun jeton ne peut emprunter.
    let longueur = ENTETE_OCTETS
        .saturating_add(login.len())
        .saturating_add(MAC_OCTETS);
    let (place, _) = brut.split_at_mut(longueur);
    ecrire_le_clair(place, token, login);

    let (clair, sceau) = place.split_at_mut(longueur.saturating_sub(MAC_OCTETS));
    let calcule = hmac_sha256(&key.octets, clair);
    for (ou, lu) in sceau.iter_mut().zip(calcule.iter()) {
        *ou = *lu;
    }
    let ecrit = base64url::encode(place, sortie)?;
    // **C'EST DE L'ASCII PAR CONSTRUCTION** : chaque octet sort de l'alphabet de
    // §5 de RFC 4648, qui n'en contient pas d'autre. Une garde ici serait une
    // branche qu'aucun jeton ne peut emprunter — et la cible de fuzz vérifie
    // justement que rien d'autre ne s'écrit.
    Ok(core::str::from_utf8(ecrit).unwrap_or_default())
}

/// Écrit la partie en clair d'un jeton.
fn ecrire_le_clair(place: &mut [u8], token: &Token<'_>, login: &[u8]) {
    // Les tableaux sont NOMMÉS : les enchaîner sans les lier les ferait
    // détruire avant que la chaîne ne les lise.
    let expiration = token.expiry.to_be_bytes();
    let identifiant = token.nonce.to_be_bytes();
    let tete = [VERSION, token.scope.bits()];
    let queue = [u8::try_from(login.len()).unwrap_or(0)];
    let tout = tete
        .iter()
        .chain(&expiration)
        .chain(&identifiant)
        .chain(&queue)
        .chain(login);
    for (ou, lu) in place.iter_mut().zip(tout) {
        *ou = *lu;
    }
}

/// Vérifie un jeton, et rend ce qu'il dit.
///
/// `sortie` reçoit le jeton décodé, et le nom de compte rendu y pointe.
///
/// # L'ORDRE EST TOUT
///
/// 1. on décode le base64url — et l'on refuse ce qui a plusieurs écritures ;
/// 2. on découpe la structure, **sans rien en croire** ;
/// 3. on vérifie le sceau, à temps constant ;
/// 4. **et alors seulement** on interprète les champs.
///
/// Intervertir 3 et 4 ferait agir sur une expiration, une portée ou un nom de
/// compte que personne n'a authentifiés — c'est-à-dire sur ce que l'attaquant a
/// écrit.
///
/// # Errors
///
/// [`Reason::BadToken`] pour tout ce qui ne se vérifie pas ;
/// [`Reason::TokenExpired`] pour un jeton authentique dont l'heure est passée ;
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn verify<'o>(
    key: &Key,
    presente: &[u8],
    maintenant: u64,
    sortie: &'o mut [u8],
) -> Result<Token<'o>, Error> {
    // 1. Le décodage refuse déjà les écritures multiples.
    if presente.len() > ENCODED_OCTETS_MAX {
        return Err(Error::new(Reason::BadToken));
    }
    let brut = base64url::decode(presente, sortie)?;

    // 2. On découpe, sans rien croire.
    let longueur = brut.len();
    let coupe = longueur
        .checked_sub(MAC_OCTETS)
        .filter(|clair| *clair > ENTETE_OCTETS)
        .ok_or(Error::new(Reason::BadToken))?;
    // `checked_sub` a borné la coupe : la découpe ne peut pas déborder.
    let (clair, sceau) = brut.split_at(coupe);

    // 3. Le sceau, à temps constant — et AVANT de croire quoi que ce soit.
    verifier_le_sceau(key, clair, sceau)?;

    // 4. Maintenant, et seulement maintenant, on lit.
    lire_le_clair(clair, maintenant)
}

/// Interprète la partie en clair d'un jeton dont le sceau est vérifié.
fn lire_le_clair(clair: &[u8], maintenant: u64) -> Result<Token<'_>, Error> {
    let mauvais = Error::new(Reason::BadToken);
    // L'appelant a vérifié que la partie en clair dépasse l'en-tête : le nom de
    // compte fait donc au moins un octet, et la découpe ne peut pas déborder.
    let (entete, login) = clair.split_at(ENTETE_OCTETS);
    if entete.first() != Some(&VERSION) {
        return Err(mauvais);
    }
    let scope = Scope::from_bits(entete.get(1).copied().unwrap_or(0));
    let expiry = lire_huit(entete.get(2..10).unwrap_or_default());
    let nonce = lire_huit(entete.get(10..18).unwrap_or_default());
    // **LA LONGUEUR ANNONCÉE DOIT ÊTRE CELLE QU'ON A** : le sceau la couvre, donc
    // elle est authentique — mais un émetteur qui se tromperait produirait deux
    // jetons scellés désignant le même compte de deux façons.
    let annoncee = usize::from(entete.get(18).copied().unwrap_or(0));
    if annoncee != login.len() {
        return Err(mauvais);
    }
    let login = core::str::from_utf8(login).map_err(|_| mauvais)?;

    // **L'EXPIRATION SE JUGE APRÈS LE SCEAU, ET LA DIRE NE COÛTE RIEN** : un
    // jeton qu'on déclare expiré a forcément un sceau valide, sinon on n'en
    // serait pas là. Distinguer les deux fautes n'apprend donc rien à qui forge,
    // et apprend au client honnête qu'il doit se réauthentifier.
    if maintenant >= expiry {
        return Err(Error::new(Reason::TokenExpired));
    }
    Ok(Token {
        login,
        scope,
        expiry,
        nonce,
    })
}

/// Le nombre gros-boutiste que portent ces huit octets.
fn lire_huit(octets: &[u8]) -> u64 {
    let mut valeur = 0_u64;
    for octet in octets {
        valeur = (valeur << 8) | u64::from(*octet);
    }
    valeur
}

/// Le sceau est-il celui de cette partie en clair ?
///
/// **LA COMPARAISON NE S'ARRÊTE JAMAIS PLUS TÔT** — voir [`egales`]. Un `==` sur
/// des tranches s'arrête au premier octet qui diffère, et le temps qu'il met dit
/// combien d'octets étaient bons.
fn verifier_le_sceau(key: &Key, clair: &[u8], sceau: &[u8]) -> Result<(), Error> {
    match egales(&hmac_sha256(&key.octets, clair), sceau) {
        true => Ok(()),
        false => Err(Error::new(Reason::BadToken)),
    }
}

/// Ce jeton ouvre-t-il ce que la route demande ?
///
/// `voulue` est ce que [`Resource::scope`] rend : `None` pour une ressource qui
/// n'exige rien.
///
/// [`Resource::scope`]: crate::Resource::scope
///
/// # Errors
///
/// [`Reason::Forbidden`] si la portée du jeton ne contient pas celle qu'on
/// demande. **Elle se répond en 404**, comme une ressource absente : la
/// distinguer dirait « cette ressource existe » à qui n'a pas le droit de le
/// savoir.
pub fn authorize(token: &Token<'_>, voulue: Option<Scope>) -> Result<(), Error> {
    let Some(voulue) = voulue else {
        return Ok(());
    };
    match token.scope.contains(voulue) {
        true => Ok(()),
        false => Err(Error::new(Reason::Forbidden)),
    }
}

/// Le jeton que porte un champ `Authorization`.
///
/// # LE NOM DU SCHÉMA EST INSENSIBLE À LA CASSE, ET LE JETON NE L'EST PAS
///
/// §11.1 de RFC 9110 : le schéma se compare sans égard à la casse. Le refuser
/// écarterait des clients conformes qui écrivent `bearer`. Le jeton qui suit,
/// lui, est un identifiant opaque : y toucher le changerait.
///
/// # Errors
///
/// [`Reason::BadToken`] pour un champ qui ne porte pas de jeton porteur.
pub fn bearer(valeur: &[u8]) -> Result<&[u8], Error> {
    const SCHEMA: &[u8] = b"bearer ";
    let mauvais = Error::new(Reason::BadToken);
    let (dit, reste) = valeur.split_at_checked(SCHEMA.len()).ok_or(mauvais)?;
    if !dit
        .iter()
        .zip(SCHEMA)
        .all(|(lu, attendu)| lu.eq_ignore_ascii_case(attendu))
    {
        return Err(mauvais);
    }
    // **UN SEUL ESPACE, ET RIEN D'AUTRE APRÈS** : §11.4 tolère des espaces
    // supplémentaires, mais les accepter donnerait deux écritures d'un même
    // en-tête — et c'est la valeur entière qu'un journal ou un cache retient. Un
    // jeton ne porte de toute façon aucune espace.
    match reste.is_empty() || reste.contains(&b' ') {
        true => Err(mauvais),
        false => Ok(reste),
    }
}

#[cfg(test)]
mod tests;
