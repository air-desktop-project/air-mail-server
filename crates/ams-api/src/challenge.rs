// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le défi : ce qu'un appareil signe pour prouver qu'il tient sa clef.
//!
//! # IL EST AUTO-PORTÉ, ET C'EST UN CHOIX
//!
//! Aucun registre des défis émis. Le défi porte ce qu'il faut pour se vérifier —
//! un sceau HMAC-SHA-256 sous la clé du serveur — et rien ne le retient côté
//! serveur. Un registre aurait coûté un état partagé, une purge, et une perte au
//! redémarrage qui aurait refusé des défis légitimes.
//!
//! # ET IL EST À USAGE UNIQUE SANS REGISTRE POUR AUTANT
//!
//! **CE N'EST PAS LE DÉFI QUI SE SOUVIENT, C'EST L'APPAREIL.** Ouvrir une
//! session met à jour la date de dernière session de l'appareil ; un défi n'est
//! recevable que s'il a été émis APRÈS cette date. Rejouer le même défi — ou un
//! défi plus ancien — échoue donc, et l'état qui tranche est le magasin
//! d'appareils, qui est sur disque.
//!
//! C'est exactement le mécanisme de l'invitation, dont l'usage unique vient du
//! magasin et non d'une liste : une seule idée, appliquée deux fois.
//!
//! # POURQUOI IL COMPTE EN SECONDES, ALORS QUE LE JETON COMPTE EN MICROSECONDES
//!
//! **PARCE QU'IL SE COMPARE À UNE DATE EN SECONDES.** La date de dernière
//! session d'un appareil est en secondes — c'est ce que le magasin range et ce
//! que l'utilisateur lit. Un défi qui compterait en microsecondes se comparerait
//! à une date tronquée, et **un rejeu passerait dans la même seconde que la
//! session légitime** : la date de session aurait été arrondie vers le bas, donc
//! jugée antérieure au défi qu'on rejoue.
//!
//! Compter en secondes des deux côtés ferme ce trou. Ce que cela coûte est dit :
//! deux sessions ouvertes dans la MÊME seconde sont impossibles — la seconde
//! redemande un défi, une seconde plus tard. Personne ne le remarque.
//!
//! # CE QU'IL NE PORTE PAS
//!
//! **Aucun aléa.** Il n'en a pas besoin : ce qui le rend unique est l'instant
//! de son émission, et ce qui l'empêche d'être rejoué est la date de session de
//! l'appareil. Un aléa aurait demandé une source qui peut manquer.
//!
//! **Rien qui ne soit déjà connu de celui qui le demande.** Sa partie en clair
//! porte le compte et l'appareil que l'appelant vient de nommer, et l'instant.
//! Elle est lisible — un sceau authentifie, il ne chiffre pas — et c'est sans
//! conséquence : elle ne lui apprend rien.
//!
//! **Surtout, elle ne dit pas si cet appareil EXISTE.** Un défi est émis pour
//! n'importe quel identifiant, connu ou non : refuser d'en émettre pour un
//! inconnu ferait de l'émission un oracle d'énumération.

use crate::base64url;
use crate::error::{Error, Reason};
use ams_sasl::{egales, hmac_sha256};

pub use crate::token::{Key, LOGIN_OCTETS_MAX, MAC_OCTETS};

/// La seule version de défi qui existe.
///
/// **TROISIÈME OCTET DE VERSION DU DÉPÔT** — le jeton vaut `0x01`,
/// l'invitation `0x02`. Les trois sont scellés par LA MÊME CLÉ, et c'est cet
/// octet, couvert par le sceau, qui empêche de présenter l'un à la place de
/// l'autre.
pub const VERSION: u8 = 0x03;

/// Combien de secondes un défi vaut.
///
/// Soixante. **ASSEZ POUR UNE INVITE BIOMÉTRIQUE**, qui demande à l'utilisateur
/// de poser un doigt ou de montrer son visage, et pas davantage : un défi qui
/// vivrait longtemps serait une signature réutilisable longtemps.
pub const VIE_SECONDES: u64 = 60;

/// Ce qu'un identifiant d'appareil peut faire de long dans un défi.
///
/// La même borne que dans le magasin : un identifiant plus long n'y désignerait
/// rien, et l'accepter ici ferait porter au défi ce que le magasin refuse.
pub const ID_OCTETS_MAX: usize = 64;

/// Ce que la partie en clair occupe, sans les deux noms.
///
/// Version, instant d'émission, longueur du compte, longueur de l'appareil.
const ENTETE_OCTETS: usize = 1 + 8 + 1 + 1;

/// Le plus grand défi binaire possible.
pub const CHALLENGE_OCTETS_MAX: usize =
    ENTETE_OCTETS + LOGIN_OCTETS_MAX + ID_OCTETS_MAX + MAC_OCTETS;

/// Ce que le même défi occupe une fois écrit.
pub const ENCODED_OCTETS_MAX: usize = base64url::encoded_len(CHALLENGE_OCTETS_MAX);

/// La chaîne de rôle que le condensat signé porte.
///
/// **SANS ELLE, UNE SIGNATURE OBTENUE POUR UN USAGE VAUDRAIT POUR UN AUTRE.**
/// Une clef d'appareil ne signe que des ouvertures de session ; le jour où elle
/// signerait autre chose, une autre chaîne l'en séparera.
pub const ROLE: &[u8] = b"ams-session";

/// Ce qu'un défi dit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge<'o> {
    /// Le compte dont on veut ouvrir une session.
    pub login: &'o str,
    /// L'appareil qui prétend tenir la clef.
    pub device: &'o str,
    /// Quand il a été émis, **en secondes** depuis l'époque.
    ///
    /// Le nom porte l'unité **exprès** : elle n'est pas celle des jetons, et
    /// l'en-tête du module dit pourquoi.
    pub issued_at_seconds: u64,
}

/// Écrit un défi scellé, en base64url.
///
/// # Errors
///
/// [`Reason::BadToken`] pour un compte ou un appareil vide ou trop long ;
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn issue<'o>(
    key: &Key,
    challenge: &Challenge<'_>,
    sortie: &'o mut [u8],
) -> Result<&'o str, Error> {
    let login = challenge.login.as_bytes();
    let device = challenge.device.as_bytes();
    if login.is_empty() || login.len() > LOGIN_OCTETS_MAX {
        return Err(Error::new(Reason::BadToken));
    }
    if device.is_empty() || device.len() > ID_OCTETS_MAX {
        return Err(Error::new(Reason::BadToken));
    }

    let mut brut = [0_u8; CHALLENGE_OCTETS_MAX];
    // Les deux noms tiennent sous leurs bornes, donc ce total tient sous celle
    // du défi : la découpe est bornée par construction.
    let longueur = ENTETE_OCTETS
        .saturating_add(login.len())
        .saturating_add(device.len())
        .saturating_add(MAC_OCTETS);
    let (place, _) = brut.split_at_mut(longueur);
    ecrire_le_clair(place, challenge, login, device);

    let (clair, sceau) = place.split_at_mut(longueur.saturating_sub(MAC_OCTETS));
    let calcule = hmac_sha256(key.octets(), clair);
    for (ou, lu) in sceau.iter_mut().zip(calcule.iter()) {
        *ou = *lu;
    }
    let ecrit = base64url::encode(place, sortie)?;
    // **C'EST DE L'ASCII PAR CONSTRUCTION** : chaque octet sort de l'alphabet de
    // §5 de RFC 4648, qui n'en contient pas d'autre.
    Ok(core::str::from_utf8(ecrit).unwrap_or_default())
}

/// Écrit la partie en clair d'un défi.
fn ecrire_le_clair(place: &mut [u8], challenge: &Challenge<'_>, login: &[u8], device: &[u8]) {
    // Les tableaux sont NOMMÉS : les enchaîner sans les lier les ferait détruire
    // avant que la chaîne ne les lise.
    let instant = challenge.issued_at_seconds.to_be_bytes();
    let tete = [VERSION];
    let longueurs = [
        u8::try_from(login.len()).unwrap_or(0),
        u8::try_from(device.len()).unwrap_or(0),
    ];
    let tout = tete
        .iter()
        .chain(&instant)
        .chain(&longueurs)
        .chain(login)
        .chain(device);
    for (ou, lu) in place.iter_mut().zip(tout) {
        *ou = *lu;
    }
}

/// Vérifie un défi, et rend ce qu'il dit.
///
/// `maintenant_secondes` est l'heure du serveur, **en secondes**.
///
/// # L'ORDRE EST TOUT, COMME POUR UN JETON
///
/// On décode, on découpe sans rien croire, on vérifie le sceau à temps
/// constant, **et alors seulement** on interprète — version comprise.
///
/// # Errors
///
/// [`Reason::BadToken`] pour tout ce qui ne se vérifie pas, **y compris un jeton
/// ou une invitation présentés ici** : leur version les trahit ;
/// [`Reason::TokenExpired`] pour un défi authentique dont les soixante secondes
/// sont passées — **et le distinguer est une exigence** : une horloge de client
/// qui dérive produit sinon des échecs que personne ne sait expliquer ;
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn verify<'o>(
    key: &Key,
    presente: &[u8],
    maintenant_secondes: u64,
    sortie: &'o mut [u8],
) -> Result<Challenge<'o>, Error> {
    if presente.len() > ENCODED_OCTETS_MAX {
        return Err(Error::new(Reason::BadToken));
    }
    let brut = base64url::decode(presente, sortie)?;

    let coupe = brut
        .len()
        .checked_sub(MAC_OCTETS)
        .filter(|clair| *clair > ENTETE_OCTETS)
        .ok_or(Error::new(Reason::BadToken))?;
    let (clair, sceau) = brut.split_at(coupe);

    match egales(&hmac_sha256(key.octets(), clair), sceau) {
        true => {}
        false => return Err(Error::new(Reason::BadToken)),
    }

    lire_le_clair(clair, maintenant_secondes)
}

/// Interprète la partie en clair d'un défi dont le sceau est vérifié.
fn lire_le_clair(clair: &[u8], maintenant_secondes: u64) -> Result<Challenge<'_>, Error> {
    let mauvais = Error::new(Reason::BadToken);
    // L'appelant a vérifié que la partie en clair dépasse l'en-tête.
    let (entete, noms) = clair.split_at(ENTETE_OCTETS);
    if entete.first() != Some(&VERSION) {
        return Err(mauvais);
    }
    let issued_at_seconds = lire_huit(entete.get(1..9).unwrap_or_default());
    let taille_du_login = usize::from(entete.get(9).copied().unwrap_or(0));
    let taille_de_l_appareil = usize::from(entete.get(10).copied().unwrap_or(0));

    // **LES DEUX LONGUEURS DOIVENT ÉPUISER CE QUI RESTE** : le sceau les couvre,
    // donc elles sont authentiques — mais un émetteur qui se tromperait
    // produirait deux défis scellés désignant le même appareil de deux façons.
    if taille_du_login.saturating_add(taille_de_l_appareil) != noms.len() {
        return Err(mauvais);
    }
    let (login, device) = noms.split_at(taille_du_login);
    if login.is_empty() || device.is_empty() {
        return Err(mauvais);
    }
    let login = core::str::from_utf8(login).map_err(|_| mauvais)?;
    let device = core::str::from_utf8(device).map_err(|_| mauvais)?;

    // **L'EXPIRATION SE JUGE APRÈS LE SCEAU, ET ELLE SE DIT.** Un défi qu'on
    // déclare expiré a forcément un sceau valide : la distinguer n'apprend donc
    // rien à qui forge, et elle apprend au client honnête que son horloge dérive
    // ou qu'il a trop attendu l'empreinte de son propriétaire.
    if maintenant_secondes >= issued_at_seconds.saturating_add(VIE_SECONDES) {
        return Err(Error::new(Reason::TokenExpired));
    }
    // **UN DÉFI ÉMIS DANS LE FUTUR EST UN DÉFI QU'ON N'A PAS ÉMIS**, ou une
    // horloge qui a reculé. Dans les deux cas il ne vaut rien : l'accepter
    // ferait vivre un défi bien au-delà de ses soixante secondes.
    if issued_at_seconds > maintenant_secondes {
        return Err(mauvais);
    }
    Ok(Challenge {
        login,
        device,
        issued_at_seconds,
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

/// Le condensat que l'appareil doit signer.
///
/// **CE N'EST PAS LE DÉFI NU**, et c'est ce qui lie la signature à un serveur et
/// à un usage : sans cette liaison, une signature obtenue pour ouvrir une
/// session ici vaudrait pour ouvrir une session ailleurs, ou pour autre chose.
///
/// Le condensat couvre, dans cet ordre et séparés par des octets nuls :
/// [`ROLE`], le domaine du serveur, puis **le texte du défi tel qu'il a été
/// rendu**.
///
/// # POURQUOI LE TEXTE, ET NON LES OCTETS DÉCODÉS
///
/// Le client reçoit une chaîne ; lui demander de la décoder avant de signer
/// ajouterait une étape où cinq applications natives peuvent diverger. Ce qu'il
/// signe est donc exactement ce qu'il a reçu.
///
/// # LES SÉPARATEURS NULS NE SONT PAS DÉCORATIFS
///
/// Sans eux, un domaine et un défi différents pourraient se recoller en la même
/// suite d'octets, et deux condensats distincts n'en feraient qu'un. Aucun des
/// trois éléments ne peut contenir d'octet nul : le rôle est une constante, un
/// domaine n'en porte pas, et l'alphabet de §5 de RFC 4648 non plus.
#[must_use]
pub fn digest(domaine: &[u8], defi: &[u8]) -> [u8; MAC_OCTETS] {
    // **AUCUN TAMPON, DONC RIEN À TRONQUER.** La première écriture recopiait les
    // trois morceaux dans un tableau borné, et un domaine plus long que la borne
    // chassait le défi : deux défis distincts donnaient alors le MÊME condensat,
    // donc une signature qui vaut pour les deux. Un essai l'a trouvé.
    ams_sasl::sha256_des_morceaux(&[ROLE, &[0], domaine, &[0], defi])
}

#[cfg(test)]
mod tests;
