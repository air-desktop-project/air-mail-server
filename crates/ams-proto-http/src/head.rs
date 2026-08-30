// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Une requête décodée, et les règles qui disent si elle est recevable.
//!
//! # LE DÉCOMPRESSEUR NE JUGE RIEN, ET C'EST VOULU
//!
//! HPACK et QPACK rendent des paires `(nom, valeur)`, dans l'ordre, sans savoir
//! ce qu'un serveur HTTP en attend. **Toutes les règles de §8.3 vivent donc
//! ici** : l'ordre des pseudo-en-têtes, leur unicité, ce qui est obligatoire, ce
//! qui est interdit. Les mettre dans le décompresseur les écrirait deux fois —
//! une pour HPACK, une pour QPACK — et deux écritures d'une même règle finissent
//! toujours par différer.
//!
//! # L'ACCUMULATEUR EST NOURRI CHAMP PAR CHAMP
//!
//! [`HeadBuilder::field`] refuse dès qu'il voit, plutôt qu'à la fin : une liste
//! de mille champs dont le premier est fautif n'a pas à être lue en entier. Et
//! l'ordre compte — c'est [`HeadBuilder`] qui vérifie que les pseudo-en-têtes
//! viennent avant, ce que seule une lecture séquentielle peut voir.

use crate::field::{FieldKind, field_kind, field_value_is_valid};
use crate::{Error, Limits, Method};

/// Combien de champs ordinaires une requête peut porter.
///
/// C'est la borne du TABLEAU, celle qu'aucune configuration ne peut franchir ;
/// [`Limits::max_fields`] peut la resserrer, jamais l'élargir.
pub const FIELDS_MAX: usize = 64;

/// Ce que RFC 9113 §6.5.2 compte en plus du nom et de la valeur.
///
/// Ces trente-deux octets ne sont pas sur le fil : ils représentent ce qu'une
/// entrée coûte à retenir. Les omettre ferait passer pour gratuits dix mille
/// champs vides — et c'est ainsi qu'on fabrique une bombe de décompression.
const SURCOUT_PAR_CHAMP: usize = 32;

/// Une requête décodée et vérifiée.
pub struct RequestHead<'a> {
    /// La méthode.
    method: Method,
    /// Le schéma : `http` ou `https`.
    scheme: &'a [u8],
    /// L'autorité — de `:authority`, ou à défaut du champ `host`.
    authority: &'a [u8],
    /// La cible.
    path: &'a [u8],
    /// Les champs ordinaires, dans l'ordre où ils sont arrivés.
    fields: [(&'a [u8], &'a [u8]); FIELDS_MAX],
    /// Combien de `fields` valent.
    fields_len: usize,
    /// Ce que `content-length` annonçait, s'il était là.
    content_length: Option<u64>,
}

impl<'a> RequestHead<'a> {
    /// La méthode.
    #[must_use]
    pub fn method(&self) -> Method {
        self.method
    }

    /// Le schéma.
    #[must_use]
    pub fn scheme(&self) -> &'a [u8] {
        self.scheme
    }

    /// L'autorité — jamais vide : `finish` a refusé la requête qui n'en portait
    /// aucune.
    #[must_use]
    pub fn authority(&self) -> &'a [u8] {
        self.authority
    }

    /// La cible.
    #[must_use]
    pub fn path(&self) -> &'a [u8] {
        self.path
    }

    /// Les champs ordinaires, dans l'ordre.
    #[must_use]
    pub fn fields(&self) -> &[(&'a [u8], &'a [u8])] {
        self.fields.get(..self.fields_len).unwrap_or_default()
    }

    /// La première valeur de ce champ, s'il est là.
    ///
    /// **LA PREMIÈRE, ET NON LA DERNIÈRE.** Un champ répété est licite pour
    /// certains noms (§5.3), et prendre la dernière laisserait un client
    /// remplacer ce qu'un intermédiaire a posé devant.
    #[must_use]
    pub fn field(&self, nom: &[u8]) -> Option<&'a [u8]> {
        self.fields()
            .iter()
            .find(|(connu, _)| *connu == nom)
            .map(|(_, valeur)| *valeur)
    }

    /// Ce que `content-length` annonçait, s'il était là.
    ///
    /// `None` ne veut pas dire « pas de corps » : en h2 comme en h3, la fin du
    /// corps est marquée par un fanion de cadre, pas par ce champ. C'est un
    /// RENSEIGNEMENT, à confronter à ce qu'on a effectivement reçu.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }
}

impl core::fmt::Debug for RequestHead<'_> {
    /// **ON NE MONTRE PAS LES VALEURS DES CHAMPS.** Un `authorization` dans un
    /// journal est un mot de passe dans un journal ; le compte suffit à
    /// diagnostiquer.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RequestHead")
            .field("method", &self.method)
            .field("scheme", &DebugOctets(self.scheme))
            .field("authority", &DebugOctets(self.authority))
            .field("path", &DebugOctets(self.path))
            .field("fields", &self.fields_len)
            .field("content_length", &self.content_length)
            .finish()
    }
}

/// Montre des octets comme du texte quand ils en sont, et par leur longueur
/// sinon.
struct DebugOctets<'a>(&'a [u8]);

impl core::fmt::Debug for DebugOctets<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match core::str::from_utf8(self.0) {
            Ok(texte) => write!(f, "{texte:?}"),
            Err(_) => write!(f, "<{} octets>", self.0.len()),
        }
    }
}

/// Accumule une liste de champs décodée, et la vérifie au fil de l'eau.
pub struct HeadBuilder<'a> {
    /// Les bornes.
    limits: Limits,
    /// `:method`, une fois lu.
    method: Option<Method>,
    /// `:scheme`.
    scheme: Option<&'a [u8]>,
    /// `:authority`.
    authority: Option<&'a [u8]>,
    /// `:path`.
    path: Option<&'a [u8]>,
    /// Les champs ordinaires.
    fields: [(&'a [u8], &'a [u8]); FIELDS_MAX],
    /// Combien valent.
    fields_len: usize,
    /// A-t-on déjà vu un champ ordinaire ? Alors plus aucun pseudo n'est admis.
    vu_un_champ: bool,
    /// Ce que `content-length` annonçait.
    content_length: Option<u64>,
    /// Ce que la liste pèse, surcoût compris.
    poids: usize,
}

impl<'a> HeadBuilder<'a> {
    /// Ouvre l'accumulation.
    #[must_use]
    pub fn new(limits: &Limits) -> Self {
        Self {
            limits: *limits,
            method: None,
            scheme: None,
            authority: None,
            path: None,
            fields: [(&[], &[]); FIELDS_MAX],
            fields_len: 0,
            vu_un_champ: false,
            content_length: None,
            poids: 0,
        }
    }

    /// Ajoute un champ décodé.
    ///
    /// # Errors
    ///
    /// Toutes les fautes de §8.2 et §8.3, dès qu'elles se voient.
    pub fn field(&mut self, nom: &'a [u8], valeur: &'a [u8]) -> Result<(), Error> {
        // LE POIDS D'ABORD : c'est la borne qui arrête une bombe de
        // décompression, et elle doit s'appliquer AVANT tout examen — le coût
        // d'un champ ne dépend pas de sa validité.
        self.poids = self
            .poids
            .saturating_add(nom.len())
            .saturating_add(valeur.len())
            .saturating_add(SURCOUT_PAR_CHAMP);
        if self.poids > self.limits.max_header_list {
            return Err(Error::FieldTooLong);
        }
        if nom.len() > self.limits.max_field_name || valeur.len() > self.limits.max_field_value {
            return Err(Error::FieldTooLong);
        }
        if !field_value_is_valid(valeur) {
            return Err(Error::MalformedFieldValue);
        }
        match field_kind(nom) {
            FieldKind::Invalid => Err(Error::MalformedFieldName),
            FieldKind::Pseudo => self.pseudo(nom, valeur),
            FieldKind::Ordinary => self.ordinaire(nom, valeur),
        }
    }

    /// Range un pseudo-en-tête.
    fn pseudo(&mut self, nom: &'a [u8], valeur: &'a [u8]) -> Result<(), Error> {
        // §8.3 : TOUS EN TÊTE. L'ordre n'est pas une convention de présentation
        // — c'est ce qui permet de décider qu'une liste est complète sans
        // l'avoir lue en entier.
        if self.vu_un_champ {
            return Err(Error::PseudoAfterField);
        }
        match nom {
            b":method" => {
                if self.method.is_some() {
                    return Err(Error::DuplicatePseudo);
                }
                self.method = Some(Method::parse(valeur).ok_or(Error::UnsupportedMethod)?);
            }
            b":scheme" => {
                if self.scheme.is_some() {
                    return Err(Error::DuplicatePseudo);
                }
                // LE SCHÉMA EST UN VOCABULAIRE FERMÉ ICI. Que `http` soit
                // recevable sur une connexion chiffrée est une question de
                // POLITIQUE, et elle se tranche à l'étage au-dessus : la
                // grammaire ne refuse que ce qu'elle ne saurait pas lire.
                if valeur != b"https" && valeur != b"http" {
                    return Err(Error::UnsupportedScheme);
                }
                self.scheme = Some(valeur);
            }
            b":authority" => {
                if self.authority.is_some() {
                    return Err(Error::DuplicatePseudo);
                }
                if valeur.len() > self.limits.max_authority {
                    return Err(Error::FieldTooLong);
                }
                self.authority = Some(valeur);
            }
            b":path" => {
                if self.path.is_some() {
                    return Err(Error::DuplicatePseudo);
                }
                if valeur.len() > self.limits.max_path {
                    return Err(Error::FieldTooLong);
                }
                self.path = Some(valeur);
            }
            // §8.3.1 : LA LISTE DES PSEUDO-EN-TÊTES DE REQUÊTE EST FERMÉE. Un
            // `:status` dans une requête, ou un nom inventé, rend la requête mal
            // formée — et non « ignorable » : un intermédiaire qui l'ignorerait
            // et un serveur qui l'honorerait ne verraient pas la même requête.
            _ => return Err(Error::UnknownPseudo),
        }
        Ok(())
    }

    /// Range un champ ordinaire.
    fn ordinaire(&mut self, nom: &'a [u8], valeur: &'a [u8]) -> Result<(), Error> {
        self.vu_un_champ = true;
        if crate::field::is_connection_specific(nom) {
            return Err(Error::ConnectionSpecificField);
        }
        // §8.2.2 : `te` survit, mais UNE SEULE VALEUR lui est permise. Les
        // autres — `gzip`, `chunked` — décrivent un cadrage qui n'existe plus.
        if nom == b"te" && valeur != b"trailers" {
            return Err(Error::ConnectionSpecificField);
        }
        if nom == b"content-length" {
            let annonce = lire_une_longueur(valeur)?;
            // §8.1.2 de RFC 9110 : deux `content-length` qui se contredisent,
            // c'est la contrebande. Deux qui s'accordent sont licites, et le
            // sont restées.
            if self.content_length.is_some_and(|deja| deja != annonce) {
                return Err(Error::MalformedContentLength);
            }
            self.content_length = Some(annonce);
        }
        let borne = self.limits.max_fields.min(FIELDS_MAX);
        let Some(place) = self.fields.get_mut(self.fields_len).filter(|_| {
            // LA BORNE DE CONFIGURATION PEUT RESSERRER, JAMAIS ÉLARGIR : le
            // tableau reste le dernier mot.
            self.fields_len < borne
        }) else {
            return Err(Error::TooManyFields { limit: borne });
        };
        *place = (nom, valeur);
        self.fields_len = self.fields_len.saturating_add(1);
        Ok(())
    }

    /// Conclut, et rend la requête si elle tient debout.
    ///
    /// # Errors
    ///
    /// [`Error::MissingPseudo`] s'il manque `:method`, `:scheme` ou `:path` ;
    /// [`Error::MalformedPath`] pour une cible qu'on ne saurait pas router ;
    /// [`Error::AuthorityMismatch`] si `:authority` et `host` se contredisent.
    pub fn finish(self) -> Result<RequestHead<'a>, Error> {
        let (method, scheme, path) = match (self.method, self.scheme, self.path) {
            (Some(method), Some(scheme), Some(path)) => (method, scheme, path),
            _ => return Err(Error::MissingPseudo),
        };

        // §8.3.1 : POUR `http` ET `https`, IL FAUT UNE AUTORITÉ — de
        // `:authority`, ou à défaut du champ `host`. Sans elle, un serveur qui
        // en héberge plusieurs ne sait pas lequel on demande.
        let host = self
            .fields
            .get(..self.fields_len)
            .unwrap_or_default()
            .iter()
            .find(|(nom, _)| *nom == b"host")
            .map(|(_, valeur)| *valeur);
        let authority = match (self.authority, host) {
            // LES DEUX, ET ELLES SE CONTREDISENT : c'est la contrebande
            // déplacée dans le nom d'hôte. §8.3.1 l'interdit.
            (Some(pseudo), Some(champ)) if pseudo != champ => {
                return Err(Error::AuthorityMismatch);
            }
            (Some(pseudo), _) => pseudo,
            (None, Some(champ)) => champ,
            (None, None) => return Err(Error::MissingPseudo),
        };
        if authority.is_empty() {
            return Err(Error::MissingPseudo);
        }

        // §8.3.1 : `:path` NE PEUT PAS ÊTRE VIDE pour `http`/`https`, et la
        // forme `*` n'est licite que pour `OPTIONS`. Tout le reste doit
        // commencer par `/` — une cible en forme absolue serait une requête de
        // mandataire, et ce serveur n'en est pas un.
        let chemin_recevable = match path {
            b"*" => method == Method::Options,
            _ => path.first() == Some(&b'/'),
        };
        if !chemin_recevable {
            return Err(Error::MalformedPath);
        }

        Ok(RequestHead {
            method,
            scheme,
            authority,
            path,
            fields: self.fields,
            fields_len: self.fields_len,
            content_length: self.content_length,
        })
    }
}

/// Lit un `content-length`.
///
/// **QUE DES CHIFFRES, ET AU MOINS UN.** Ni signe, ni espace, ni `0x10` : un
/// analyseur indulgent lirait `+10` comme dix là où le suivant y verrait une
/// faute, et l'écart entre les deux est la longueur d'une requête clandestine.
fn lire_une_longueur(valeur: &[u8]) -> Result<u64, Error> {
    if valeur.is_empty() || !valeur.iter().all(u8::is_ascii_digit) {
        return Err(Error::MalformedContentLength);
    }
    let mut total = 0_u64;
    for chiffre in valeur {
        total = total
            .checked_mul(10)
            .and_then(|dizaines| dizaines.checked_add(u64::from(chiffre.wrapping_sub(b'0'))))
            .ok_or(Error::MalformedContentLength)?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests;
