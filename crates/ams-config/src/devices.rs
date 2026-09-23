//! Le fichier des appareils enrôlés : ce qu'il porte, et ce qu'il refuse.
//!
//! # IL NE CONTIENT AUCUN SECRET
//!
//! Une clef publique se publie par définition ; la privée vit dans l'enclave du
//! téléphone et n'en sort jamais. Une fuite de ce fichier n'ouvre donc aucune
//! session — elle apprend seulement **combien d'appareils chaque compte a**, ce
//! qui reste une information à ne pas offrir.
//!
//! # ET AUCUN IDENTIFIANT MATÉRIEL
//!
//! Ni IMEI, ni numéro de série, ni identifiant publicitaire. Un serveur de
//! courrier n'a pas à savoir quel téléphone on tient : reconnaître une clef lui
//! suffit. Les retenir en ferait un fichier de traçage que personne n'a demandé.

use alloc::string::String;
use alloc::vec::Vec;

use ams_auth::{CLE_OCTETS, Cle, check_login};
use capnp::message::ReaderOptions;
use capnp::serialize;

use crate::ams_devices_capnp::devices;
use crate::codec::{Error, TRAVERSAL_LIMIT_WORDS, texte};

/// Ce qu'un identifiant d'appareil peut faire de long.
///
/// **IL VOYAGE DANS UN CHEMIN ET DANS UN DÉFI**, et les deux sont bornés : un
/// identifiant plus long qu'un segment d'URL serait un appareil inatteignable.
pub const ID_OCTETS_MAX: usize = 64;

/// Ce qu'un nom d'appareil peut faire de long.
///
/// Il ne sert qu'à l'humain qui choisit lequel révoquer — cent vingt-huit
/// octets laissent la place à « iPhone 15 de Marie (bureau) » sans permettre
/// d'y ranger un roman.
pub const NOM_OCTETS_MAX: usize = 128;

/// Un appareil enrôlé.
#[derive(Debug, Clone)]
pub struct Device {
    /// Le compte dont il ouvre les sessions.
    pub login: String,
    /// Ce qui le désigne, **tiré par le serveur** et jamais par le client.
    pub id: String,
    /// Le nom que son propriétaire lui a donné.
    pub name: String,
    /// Sa clef publique, déjà validée comme point de la courbe.
    ///
    /// **C'EST LE TYPE QUI PORTE LA GARANTIE** : [`Cle`] ne se construit que
    /// par une lecture qui refuse ce qui n'est pas un point. Un appelant n'a
    /// donc rien à revérifier, et ne peut pas oublier de le faire.
    pub public_key: Cle,
    /// Quand il a été enrôlé, en secondes depuis l'époque.
    pub enrolled: u64,
    /// Quand il a ouvert une session pour la dernière fois. Zéro s'il ne l'a
    /// jamais fait.
    pub last_seen: u64,
}

/// Lit un fichier d'appareils.
///
/// # Ce qui est REFUSÉ au chargement, plutôt que découvert plus tard
///
/// - un compte que [`ams_auth::check_login`] refuse — le même contrôle que
///   pour le magasin de comptes, et pour la même raison ;
/// - **un identifiant en double** : deux clefs sous un même identifiant, c'est
///   une question sans réponse, et la première l'emporterait en silence ;
/// - une clef qui n'est pas un point de la courbe. **Ce n'est pas une clef
///   faible, c'est une clef qui n'existe pas** — et l'accepter ouvrirait les
///   attaques par courbe invalide ;
/// - un identifiant ou un nom vide, ou plus long que sa borne.
///
/// # Errors
///
/// [`Error`].
pub fn decode_devices(octets: &[u8]) -> Result<Vec<Device>, Error> {
    let mut reste = octets;
    let message = serialize::read_message_from_flat_slice(
        &mut reste,
        ReaderOptions {
            traversal_limit_in_words: Some(
                usize::try_from(TRAVERSAL_LIMIT_WORDS).unwrap_or(usize::MAX),
            ),
            nesting_limit: 8,
        },
    )?;
    let lu: devices::Reader<'_> = message.get_root()?;

    let mut appareils: Vec<Device> = Vec::new();
    for appareil in lu.get_devices()?.iter() {
        let login = texte(appareil.get_login()?)?;
        check_login(&login).map_err(|cause| Error::WeakAccount {
            login: login.clone(),
            cause,
        })?;

        let id = texte(appareil.get_id()?)?;
        if id.is_empty() {
            return Err(Error::Empty("device id"));
        }
        if id.len() > ID_OCTETS_MAX {
            return Err(Error::TooLong("device id"));
        }
        // **UN IDENTIFIANT DÉSIGNE UN APPAREIL, ET UN SEUL.** Deux clefs sous
        // le même nom, c'est une révocation dont on ne saurait pas laquelle
        // elle a retirée.
        if appareils.iter().any(|connu| connu.id == id) {
            return Err(Error::DuplicateDevice(id));
        }

        let name = texte(appareil.get_name()?)?;
        if name.len() > NOM_OCTETS_MAX {
            return Err(Error::TooLong("device name"));
        }

        let octets = appareil.get_public_key()?;
        if octets.len() != CLE_OCTETS {
            return Err(Error::BadDeviceKey(id));
        }
        let public_key = Cle::lire(octets).map_err(|_| Error::BadDeviceKey(id.clone()))?;

        appareils.push(Device {
            login,
            id,
            name,
            public_key,
            enrolled: appareil.get_enrolled(),
            last_seen: appareil.get_last_seen(),
        });
    }
    Ok(appareils)
}

/// Écrit un fichier d'appareils.
///
/// # Errors
///
/// [`Error::Malformed`] si l'encodage échoue — ce qui n'arrive que sur un défaut
/// de la bibliothèque, jamais sur un magasin valide.
pub fn encode_devices(appareils: &[Device]) -> Result<Vec<u8>, Error> {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<devices::Builder<'_>>();
        let mut liste = ecrit.init_devices(u32::try_from(appareils.len()).unwrap_or(u32::MAX));
        for (rang, appareil) in appareils.iter().enumerate() {
            let mut case = liste
                .reborrow()
                .get(u32::try_from(rang).unwrap_or(u32::MAX));
            case.set_login(&appareil.login);
            case.set_id(&appareil.id);
            case.set_name(&appareil.name);
            case.set_public_key(&appareil.public_key.octets());
            case.set_enrolled(appareil.enrolled);
            case.set_last_seen(appareil.last_seen);
        }
    }
    Ok(serialize::write_message_to_words(&message))
}

#[cfg(test)]
mod tests;
