//! L'enregistrement de clé publique (RFC 6376 §3.6.1).
//!
//! Il vit dans le DNS, sous `<sélecteur>._domainkey.<domaine>`, en `TXT`. Cette
//! crate ne le résout pas — elle le lit.

use crate::signature::Algorithm;
use crate::tag::{Tags, sans_blancs};
use crate::{Error, Tag};

/// Le type de clé (`k=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    /// RSA. **C'est le défaut de la RFC** : un enregistrement sans `k=` en
    /// publie une.
    #[default]
    Rsa,
    /// Ed25519 (RFC 8463).
    Ed25519,
}

impl KeyType {
    /// Lit un `k=`.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedKeyType`].
    pub fn parse(valeur: &[u8]) -> Result<Self, Error> {
        if valeur.eq_ignore_ascii_case(b"rsa") {
            return Ok(Self::Rsa);
        }
        if valeur.eq_ignore_ascii_case(b"ed25519") {
            return Ok(Self::Ed25519);
        }
        Err(Error::UnsupportedKeyType)
    }
}

/// Un enregistrement de clé publique, lu et vérifié dans sa cohérence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyRecord<'a> {
    /// `k=` — de quel type est la clé.
    pub key_type: KeyType,
    /// `p=` — la clé, en base64 encore plié. **Jamais vide** : un `p=` vide est
    /// une révocation, et elle est rendue comme une erreur.
    pub key: &'a [u8],
    /// `h=` — les condensats que cette clé accepte, si la liste est donnée.
    pub hashes: Option<&'a [u8]>,
    /// `t=y` — la clé est en essai, et un vérificateur ne doit pas traiter un
    /// échec plus sévèrement qu'une absence de signature.
    pub testing: bool,
    /// `t=s` — l'identité `i=` doit être **exactement** le domaine `d=`, sans
    /// sous-domaine.
    pub strict_identity: bool,
}

impl<'a> PublicKeyRecord<'a> {
    /// Lit un enregistrement.
    ///
    /// # Ce qui fait échouer, et ce que chacun protège
    ///
    /// - **`p=` vide : la clé est RÉVOQUÉE** (§3.6.1). Ce n'est pas une faute de
    ///   forme, c'est une déclaration — le détenteur du domaine dit que cette
    ///   clé ne doit plus rien signer. La traiter comme un enregistrement
    ///   illisible reviendrait à ignorer une révocation.
    /// - **`s=` sans `email` ni `*`** : cette clé sert un autre service, et s'en
    ///   servir pour du courrier serait employer une clé hors de l'usage que son
    ///   détenteur a déclaré.
    /// - **`v=` présent et différent de `DKIM1`** : un format qu'on ne connaît
    ///   pas ne se lit pas « au mieux ».
    ///
    /// # Errors
    ///
    /// Voir [`Error`].
    pub fn parse(valeur: &'a [u8]) -> Result<Self, Error> {
        let mut version: Option<&[u8]> = None;
        let mut genre: Option<KeyType> = None;
        let mut cle: Option<&[u8]> = None;
        let mut condensats: Option<&[u8]> = None;
        let mut services: Option<&[u8]> = None;
        let mut drapeaux: Option<&[u8]> = None;

        for etiquette in Tags::new(valeur) {
            let Tag { name, value } = etiquette?;
            match name {
                b"v" => poser(&mut version, value)?,
                b"k" => poser(&mut genre, KeyType::parse(value)?)?,
                b"p" => poser(&mut cle, value)?,
                b"h" => poser(&mut condensats, value)?,
                b"s" => poser(&mut services, value)?,
                b"t" => poser(&mut drapeaux, value)?,
                // §3.6.1 : `n=` porte une note pour l'administrateur, et les
                // étiquettes inconnues s'ignorent.
                _ => {}
            }
        }

        // `v=` est FACULTATIF, mais s'il est là il vient EN PREMIER et vaut
        // `DKIM1`. On ne vérifie pas sa place — la RFC dit « DOIT être premier »
        // sans que rien n'en dépende — mais on vérifie sa valeur.
        if let Some(dit) = version
            && !dit.eq_ignore_ascii_case(b"DKIM1")
        {
            return Err(Error::NotDkimKey);
        }

        let key = cle.ok_or(Error::MissingTag("p"))?;
        if key.is_empty() {
            return Err(Error::RevokedKey);
        }

        if let Some(liste) = services
            && !liste.split(|octet| *octet == b':').any(|service| {
                let service = service.trim_ascii();
                service == b"*" || service.eq_ignore_ascii_case(b"email")
            })
        {
            return Err(Error::NotForEmail);
        }

        let drapeaux = drapeaux.unwrap_or_default();
        let porte = |lettre: &[u8]| {
            drapeaux
                .split(|octet| *octet == b':')
                .any(|drapeau| drapeau.trim_ascii().eq_ignore_ascii_case(lettre))
        };

        Ok(Self {
            key_type: genre.unwrap_or_default(),
            key,
            hashes: condensats,
            testing: porte(b"y"),
            strict_identity: porte(b"s"),
        })
    }

    /// Cette clé accepte-t-elle le condensat de cet algorithme ?
    ///
    /// Une liste `h=` absente les accepte tous (§3.6.1). Une liste présente qui
    /// ne le nomme pas est un refus : le détenteur du domaine a restreint ce que
    /// sa clé couvre, et passer outre reviendrait à décider à sa place.
    #[must_use]
    pub fn accepts(&self, algorithm: Algorithm) -> bool {
        let Some(liste) = self.hashes else {
            return true;
        };
        liste
            .split(|octet| *octet == b':')
            .any(|nom| nom.trim_ascii().eq_ignore_ascii_case(algorithm.hash_name()))
    }

    /// Ce type de clé va-t-il avec cet algorithme de signature ?
    ///
    /// Une clé RSA ne vérifie pas une signature Ed25519, et l'essayer quand même
    /// ne rendrait pas « faux » mais « illisible » — ce qui se confond trop
    /// facilement avec une panne.
    #[must_use]
    pub fn matches(&self, algorithm: Algorithm) -> bool {
        matches!(
            (self.key_type, algorithm),
            (KeyType::Rsa, Algorithm::RsaSha256) | (KeyType::Ed25519, Algorithm::Ed25519Sha256)
        )
    }

    /// Le `p=` sans ses blancs, prêt à décoder.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`].
    pub fn key_base64<'b>(&self, sortie: &'b mut [u8]) -> Result<&'b [u8], Error> {
        sans_blancs(self.key, sortie)
    }
}

/// Pose une valeur, ou dit qu'elle l'était déjà.
fn poser<T>(place: &mut Option<T>, valeur: T) -> Result<(), Error> {
    if place.is_some() {
        return Err(Error::DuplicateTag);
    }
    *place = Some(valeur);
    Ok(())
}

#[cfg(test)]
mod tests;
