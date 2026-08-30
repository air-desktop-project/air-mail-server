// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'accumulation d'un bloc d'en-têtes (§4.3, §6.10).
//!
//! # UN BLOC PEUT S'ÉTALER SUR AUTANT DE CADRES QU'ON VEUT
//!
//! Un `HEADERS` porte un fragment ; s'il n'a pas le fanion `END_HEADERS`, des
//! `CONTINUATION` suivent, et le bloc n'est complet qu'au dernier. **Rien dans
//! la RFC ne borne leur nombre.** Un pair peut donc envoyer un `HEADERS` puis
//! des `CONTINUATION` sans fin, chacun d'un octet, et un serveur qui accumule
//! sans compter s'arrête quand sa mémoire s'arrête.
//!
//! C'est la faille dite « CONTINUATION flood », et elle a touché la plupart des
//! implémentations en 2024. Elle n'est pas une erreur de code : c'est une borne
//! que la RFC ne donne pas et que chacun devait poser. **On en pose deux** — le
//! nombre de cadres, et le total accumulé — parce qu'aucune ne suffit seule : mille
//! cadres d'un octet passent sous une borne de taille, et un seul cadre de seize
//! mébioctets passe sous une borne de nombre.
//!
//! # LES `CONTINUATION` SE SUIVENT, SANS RIEN ENTRE ELLES
//!
//! §6.10 : « A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE
//! or CONTINUATION frame without the END_HEADERS flag set. » Et §4.3 ajoute que
//! les cadres d'un bloc doivent se suivre **sans aucun autre cadre entre eux**,
//! sur aucun flux. Ce n'est pas une commodité de mise en œuvre : la table HPACK
//! est mise à jour dans l'ordre du bloc, et laisser un autre cadre s'intercaler
//! rendrait cet ordre dépendant de l'entrelacement — donc non reproductible.

use crate::error::{Cause, Error, ErrorCode};
use crate::frame::{FrameHeader, FrameKind};

/// Combien de `CONTINUATION` on accepte pour un même bloc.
///
/// Seize. Un client sérieux n'en envoie aucun : un bloc d'en-têtes de requête
/// tient dans un cadre de seize kibioctets. Ce chiffre laisse la place à un
/// client bavard, et refuse le millier.
pub const CONTINUATIONS_MAX: u32 = 16;

/// Ce qu'un bloc d'en-têtes peut peser, COMPRIMÉ, en octets.
///
/// # CE N'EST PAS LA BORNE DE LA LISTE DÉCOMPRIMÉE
///
/// Celle-là vit dans [`ams_proto_http::Limits::max_header_list`], et compte ce
/// que les champs coûtent une fois lus. Celle-ci compte ce qu'on ACCUMULE avant
/// de décoder — et les deux sont nécessaires : la première n'existe qu'après le
/// décodage, qui n'a lieu qu'une fois le bloc entier reçu.
pub const BLOCK_OCTETS_MAX: usize = 16 * 1024;

/// Ce que l'arrivée d'un cadre a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockState {
    /// Le bloc continue : d'autres `CONTINUATION` sont attendues.
    More,
    /// Le bloc est complet, et occupe `n` octets de l'accumulateur.
    Complete(usize),
}

/// Accumule les fragments d'un bloc d'en-têtes.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeaderBlock {
    /// Le flux dont on accumule le bloc, si l'on en accumule un.
    flux: Option<u32>,
    /// Combien d'octets sont accumulés.
    octets: usize,
    /// Combien de `CONTINUATION` sont arrivées.
    continuations: u32,
    /// Le fanion `END_STREAM` du `HEADERS` qui a ouvert le bloc.
    ///
    /// **IL EST SUR LE PREMIER CADRE, ET NULLE PART AILLEURS** : un
    /// `CONTINUATION` n'en porte pas. Le lire sur le dernier cadre ferait
    /// manquer la fin de tous les messages dont le bloc s'étale.
    fin_de_message: bool,
}

impl HeaderBlock {
    /// Un accumulateur vide.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            flux: None,
            octets: 0,
            continuations: 0,
            fin_de_message: false,
        }
    }

    /// Un bloc est-il en cours ?
    #[must_use]
    pub const fn in_progress(&self) -> bool {
        self.flux.is_some()
    }

    /// Le flux dont on accumule le bloc.
    #[must_use]
    pub const fn stream(&self) -> Option<u32> {
        self.flux
    }

    /// Le message se terminait-il avec ce bloc ?
    #[must_use]
    pub const fn end_stream(&self) -> bool {
        self.fin_de_message
    }

    /// Le cadre qui arrive est-il admissible ici ?
    ///
    /// # §4.3 : RIEN NE S'INTERCALE DANS UN BLOC
    ///
    /// Quand un bloc est en cours, le SEUL cadre admissible est une
    /// `CONTINUATION` sur le MÊME flux. Tout le reste — un `DATA`, un `PING`, un
    /// `HEADERS` sur un autre flux — est une faute de connexion, et non de flux :
    /// l'état HPACK est commun, et il est déjà perdu.
    ///
    /// # Errors
    ///
    /// [`Cause::BlockInterrupted`] pour ce qui s'intercale, ou pour une
    /// `CONTINUATION` qui n'a rien à continuer.
    pub fn accepts(&self, entete: FrameHeader) -> Result<(), Error> {
        let interrompu = || {
            Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::BlockInterrupted,
            ))
        };
        match (self.flux, entete.kind()) {
            // Un bloc en cours n'admet que sa suite, sur son flux.
            (Some(attendu), FrameKind::Continuation) if attendu == entete.stream() => Ok(()),
            (Some(_), _) => interrompu(),
            // Hors bloc, une `CONTINUATION` ne continue rien.
            (None, FrameKind::Continuation) => interrompu(),
            (None, _) => Ok(()),
        }
    }

    /// Range le fragment d'un `HEADERS` ou d'une `CONTINUATION`.
    ///
    /// `charge` est la charge du cadre, remplissage déjà ôté et priorité déjà
    /// écartée. `vers` est l'accumulateur, que l'appelant garde d'un cadre à
    /// l'autre.
    ///
    /// # Errors
    ///
    /// [`Cause::BlockInterrupted`] si le cadre n'a pas sa place ;
    /// [`Cause::BlockTooLong`] au-delà des deux bornes.
    pub fn push(
        &mut self,
        entete: FrameHeader,
        charge: &[u8],
        vers: &mut [u8],
    ) -> Result<BlockState, Error> {
        self.accepts(entete)?;
        match entete.kind() {
            FrameKind::Headers => {
                self.flux = Some(entete.stream());
                self.octets = 0;
                self.continuations = 0;
                // §6.2 : `END_STREAM` est sur le `HEADERS`, et un
                // `CONTINUATION` n'en porte pas.
                self.fin_de_message = entete.flags().end_stream();
            }
            FrameKind::Continuation => {
                // **DEUX BORNES, ET AUCUNE NE SUFFIT SEULE** : mille cadres d'un
                // octet passent sous une borne de taille, et un seul cadre
                // énorme passe sous une borne de nombre.
                self.continuations = self.continuations.saturating_add(1);
                if self.continuations > CONTINUATIONS_MAX {
                    return Err(Error::connection(
                        ErrorCode::EnhanceYourCalm,
                        Cause::BlockTooLong,
                    ));
                }
            }
            // `accepts` n'a laissé passer que ces deux-là hors bloc, et la
            // `CONTINUATION` en cours de bloc. Un autre type n'ouvre pas de
            // bloc : l'appelant ne l'apporte pas ici.
            _ => {
                return Err(Error::connection(
                    ErrorCode::ProtocolError,
                    Cause::BlockInterrupted,
                ));
            }
        }

        let fin = self.octets.saturating_add(charge.len());
        if fin > BLOCK_OCTETS_MAX {
            return Err(Error::connection(
                ErrorCode::EnhanceYourCalm,
                Cause::BlockTooLong,
            ));
        }
        let place = vers
            .get_mut(self.octets..fin)
            .ok_or_else(|| Error::connection(ErrorCode::InternalError, Cause::BufferTooSmall))?;
        place.copy_from_slice(charge);
        self.octets = fin;

        match entete.flags().end_headers() {
            true => {
                let total = self.octets;
                self.flux = None;
                self.octets = 0;
                self.continuations = 0;
                Ok(BlockState::Complete(total))
            }
            false => Ok(BlockState::More),
        }
    }
}

#[cfg(test)]
mod tests;
