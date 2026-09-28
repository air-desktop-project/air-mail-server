// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le côté CLIENT d'HTTP/2 (RFC 9113) — une requête, une réponse, et c'est
//! tout.
//!
//! # POURQUOI UNE SEULE REQUÊTE PAR CONNEXION
//!
//! Ce client porte les réveils des appareils vers APNs, FCM et Web Push. Ils
//! sont rares — regroupés à trente secondes par destination — et une connexion
//! par réveil coûte une poignée de main TLS de plus, pas une panne. En échange,
//! pas de multiplexage, pas de flux concurrents, pas de fenêtre de connexion à
//! rendre : le flux est toujours le 1, la réponse tient dans un tampon borné,
//! et tout ce qui sortirait de ce cadre est une faute qu'on dit.
//!
//! # CE QU'IL FAIT
//!
//! [`Client::start`] écrit le préambule, nos `SETTINGS` — sans push serveur —
//! et la tête de la requête. Le corps attend les `SETTINGS` du serveur : c'est
//! lui qui dit la taille de cadre et la fenêtre qu'il accepte, et envoyer avant
//! serait deviner. [`Client::receive`] consomme les cadres entiers qu'on lui
//! donne, acquitte `SETTINGS` et `PING`, envoie le corps quand il le peut, et
//! retient le statut et le corps de la réponse.
//!
//! Il ne fait aucune entrée-sortie (C1) : l'appelant lit, écrit, et attend.

use crate::block::{BLOCK_OCTETS_MAX, BlockState, HeaderBlock};
use crate::error::{Cause, Error, ErrorCode};
use crate::frame::{FRAME_HEADER_OCTETS, FrameHeader, FrameKind, FrameReader, Need, Padded};
use crate::hpack::Decoder;
use crate::hpack::encode_field;
use crate::preface::PREFACE;
use crate::settings::{Settings, SettingsReader};

/// Le seul flux qu'ouvre ce client.
const FLUX: u32 = 1;

/// Ce qu'une valeur d'en-tête décodée peut occuper.
const CHAMP_MAX: usize = 4 * 1024;

/// Ce qu'on écrit au plus en une fois : préambule, `SETTINGS`, le
/// `WINDOW_UPDATE` de la connexion, tête.
pub const START_OCTETS_MAX: usize = 24
    + FRAME_HEADER_OCTETS
    + Settings::OCTETS_MAX
    + FRAME_HEADER_OCTETS
    + 4
    + FRAME_HEADER_OCTETS
    + REQUEST_HEAD_MAX;

/// Ce que la tête d'une requête peut occuper : un seul cadre `HEADERS`, à la
/// taille que tout serveur accepte (§4.2).
pub const REQUEST_HEAD_MAX: usize = 16_384;

/// Une requête.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// `POST`, `GET`…
    pub method: &'a [u8],
    /// L'hôte, tel qu'il va dans `:authority`.
    pub authority: &'a [u8],
    /// Le chemin, requête comprise.
    pub path: &'a [u8],
    /// Les autres champs, noms EN MINUSCULES (§8.2.1).
    pub fields: &'a [(&'a [u8], &'a [u8])],
    /// Le corps ; vide pour une requête sans corps.
    pub body: &'a [u8],
}

/// Ce qu'un appel à [`Client::receive`] a fait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Combien d'octets du tampon ont été consommés — des cadres entiers.
    pub consumed: usize,
    /// Combien d'octets sont à écrire, au début de `out`.
    pub written: usize,
    /// La réponse est complète.
    pub done: bool,
}

/// Ce que le client laisse le serveur lui envoyer sans attendre, par flux et
/// pour la connexion : huit mébioctets.
///
/// **SANS ELLE, UNE RÉPONSE S'ARRÊTE À 64 KIO** : la fenêtre par défaut de §6.9.2
/// est de 65 535 octets, et ce client n'envoie aucun `WINDOW_UPDATE` en cours
/// de route — il n'en a pas besoin pour une réponse qu'il reçoit d'un trait.
/// Huit mébioctets couvrent la liste de révocation de Google (0.2.40) avec
/// plus qu'assez de marge ; ce que l'appelant accepte vraiment se borne
/// ailleurs, par la place qu'il donne au corps.
pub const RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;

/// Le client d'une requête.
#[derive(Debug)]
pub struct Client {
    decodeur: Decoder,
    bloc: HeaderBlock,
    tete: [u8; BLOCK_OCTETS_MAX],
    champ: [u8; CHAMP_MAX],
    /// Les réglages du serveur, une fois reçus.
    pair: Option<Settings>,
    /// Le corps est parti.
    corps_envoye: bool,
    statut: Option<u16>,
    lus: usize,
    fini: bool,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Un client neuf.
    #[must_use]
    pub fn new() -> Self {
        Self {
            decodeur: Decoder::new(),
            bloc: HeaderBlock::new(),
            tete: [0; BLOCK_OCTETS_MAX],
            champ: [0; CHAMP_MAX],
            pair: None,
            corps_envoye: false,
            statut: None,
            lus: 0,
            fini: false,
        }
    }

    /// Nos réglages : pas de push serveur, le reste par défaut.
    const fn nos_reglages() -> Settings {
        Settings {
            enable_push: false,
            initial_window_size: RECEIVE_WINDOW,
            ..Settings::DEFAULT
        }
    }

    /// Écrit le préambule, nos `SETTINGS` et la tête de la requête, et rend ce
    /// qu'ils occupent.
    ///
    /// # Errors
    ///
    /// [`Cause::BufferTooSmall`] si `out` ne suffit pas ;
    /// [`Cause::ResponseHeadTooLong`] si la tête ne tient pas dans un cadre.
    pub fn start(&mut self, requete: &Request<'_>, out: &mut [u8]) -> Result<usize, Error> {
        let ecrits = poser(out, 0, PREFACE)?;
        let mut reglages = [0_u8; Settings::OCTETS_MAX];
        // `OCTETS_MAX` borne tous les réglages : l'écriture tient toujours.
        let longueur = Self::nos_reglages()
            .write(&mut reglages)
            .unwrap_or_default();
        let ecrits = poser_un_cadre(
            out,
            ecrits,
            FrameKind::Settings,
            0,
            0,
            reglages.get(..longueur).unwrap_or_default(),
        )?;
        // **LA FENÊTRE DE LA CONNEXION S'OUVRE D'EMBLÉE** (§6.9.2) : `SETTINGS`
        // ne règle que celle des flux, et celle de la connexion reste à
        // 65 535 octets tant qu'un `WINDOW_UPDATE` ne l'élargit pas.
        let ecrits = poser_un_cadre(
            out,
            ecrits,
            FrameKind::WindowUpdate,
            0,
            0,
            &RECEIVE_WINDOW.saturating_sub(65_535).to_be_bytes(),
        )?;

        let mut tete = [0_u8; REQUEST_HEAD_MAX];
        let mut dans = 0_usize;
        let mut coder = |nom: &[u8], valeur: &[u8]| -> Result<(), Error> {
            let place = tete.get_mut(dans..).unwrap_or_default();
            let n = encode_field(nom, valeur, place).map_err(|_| {
                Error::connection(ErrorCode::InternalError, Cause::ResponseHeadTooLong)
            })?;
            dans = dans.saturating_add(n);
            Ok(())
        };
        // §8.3.1 : les pseudo-champs d'abord, puis les autres.
        let pseudos: [(&[u8], &[u8]); 4] = [
            (b":method", requete.method),
            (b":scheme", b"https"),
            (b":authority", requete.authority),
            (b":path", requete.path),
        ];
        for (nom, valeur) in pseudos.iter().chain(requete.fields) {
            coder(nom, valeur)?;
        }
        let drapeaux = match requete.body.is_empty() {
            // Pas de corps : la requête finit avec sa tête.
            true => FIN_DE_FLUX | FIN_DE_TETE,
            false => FIN_DE_TETE,
        };
        self.corps_envoye = requete.body.is_empty();
        poser_un_cadre(
            out,
            ecrits,
            FrameKind::Headers,
            drapeaux,
            FLUX,
            tete.get(..dans).unwrap_or_default(),
        )
    }

    /// Consomme les cadres ENTIERS du début de `tampon`.
    ///
    /// `corps` est le corps de la requête — le même qu'à [`Client::start`] ;
    /// `out` reçoit ce qu'il faut écrire en retour (acquittements, corps) ;
    /// `reponse` reçoit le corps de la réponse.
    ///
    /// # Errors
    ///
    /// Toute faute de protocole du serveur, un flux réinitialisé, une
    /// connexion refusée par `GOAWAY`, un corps de requête qui ne tient pas
    /// dans sa fenêtre, une réponse plus longue que `reponse`.
    pub fn receive(
        &mut self,
        tampon: &[u8],
        corps: &[u8],
        out: &mut [u8],
        reponse: &mut [u8],
    ) -> Result<Progress, Error> {
        let mut consommes = 0_usize;
        let mut ecrits = 0_usize;
        while !self.fini {
            let reste = tampon.get(consommes..).unwrap_or_default();
            let taille_max = Self::nos_reglages().max_frame_size;
            let Need::Complete(entete) = FrameReader::poll(reste, taille_max)? else {
                break;
            };
            let charge = reste
                .get(FRAME_HEADER_OCTETS..entete.total())
                .unwrap_or_default();
            ecrits = self.cadre(entete, charge, corps, out, ecrits, reponse)?;
            consommes = consommes.saturating_add(entete.total());
        }
        Ok(Progress {
            consumed: consommes,
            written: ecrits,
            done: self.fini,
        })
    }

    /// Le statut de la réponse finale, une fois reçu.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.statut
    }

    /// Combien d'octets de corps de réponse ont été reçus.
    #[must_use]
    pub const fn body_len(&self) -> usize {
        self.lus
    }

    /// Traite un cadre, et rend le nouveau compte de ce qui est à écrire.
    fn cadre(
        &mut self,
        entete: FrameHeader,
        charge: &[u8],
        corps: &[u8],
        out: &mut [u8],
        ecrits: usize,
        reponse: &mut [u8],
    ) -> Result<usize, Error> {
        // §3.4 : le premier cadre du serveur est ses `SETTINGS`.
        if self.pair.is_none() && entete.kind() != FrameKind::Settings {
            return Err(faute(
                ErrorCode::ProtocolError,
                Cause::FirstFrameNotSettings,
            ));
        }
        // Un bloc d'en-tête en cours n'admet que sa suite.
        self.bloc.accepts(entete)?;
        if entete.stream() != 0 && entete.stream() != FLUX {
            return Err(faute(ErrorCode::ProtocolError, Cause::BadStreamId));
        }
        match entete.kind() {
            FrameKind::Settings => self.reglages(entete, charge, corps, out, ecrits),
            FrameKind::Ping if !entete.flags().ack() => {
                poser_un_cadre(out, ecrits, FrameKind::Ping, ACQUITTE, 0, charge)
            }
            FrameKind::Headers | FrameKind::Continuation => {
                self.en_tete(entete, charge)?;
                Ok(ecrits)
            }
            FrameKind::Data => {
                let utile = Padded::strip(charge, entete.flags().padded())?.data();
                let fin = self.lus.saturating_add(utile.len());
                let place = reponse
                    .get_mut(self.lus..fin)
                    .ok_or_else(|| faute(ErrorCode::EnhanceYourCalm, Cause::ResponseBodyTooLong))?;
                place.copy_from_slice(utile);
                self.lus = fin;
                if entete.flags().end_stream() {
                    self.terminer()?;
                }
                Ok(ecrits)
            }
            FrameKind::RstStream => Err(faute(ErrorCode::Cancel, Cause::StreamReset)),
            // §6.8 : un `GOAWAY` qui laisse passer notre flux n'empêche pas sa
            // réponse d'arriver ; un `GOAWAY` en deçà l'a refusé.
            FrameKind::GoAway => {
                let dernier = charge.get(..4).map_or(0, |octets| {
                    u32::from_be_bytes([
                        octets.first().copied().unwrap_or(0),
                        octets.get(1).copied().unwrap_or(0),
                        octets.get(2).copied().unwrap_or(0),
                        octets.get(3).copied().unwrap_or(0),
                    ]) & 0x7fff_ffff
                });
                match dernier >= FLUX {
                    true => Ok(ecrits),
                    false => Err(faute(ErrorCode::RefusedStream, Cause::Refused)),
                }
            }
            // §8.4 : nous avons dit `ENABLE_PUSH = 0`.
            FrameKind::PushPromise => Err(faute(ErrorCode::ProtocolError, Cause::PushFromClient)),
            // Acquittements, fenêtres, priorités, types inconnus : rien à faire
            // pour une requête de quelques kibioctets.
            _ => Ok(ecrits),
        }
    }

    /// Les `SETTINGS` du serveur : les acquitter, et envoyer le corps.
    fn reglages(
        &mut self,
        entete: FrameHeader,
        charge: &[u8],
        corps: &[u8],
        out: &mut [u8],
        ecrits: usize,
    ) -> Result<usize, Error> {
        if entete.flags().ack() {
            return Ok(ecrits);
        }
        let mut pair = self.pair.unwrap_or(Settings::DEFAULT);
        SettingsReader::apply_all(charge, &mut pair)?;
        self.pair = Some(pair);
        let mut ecrits = poser_un_cadre(out, ecrits, FrameKind::Settings, ACQUITTE, 0, &[])?;
        if self.corps_envoye {
            return Ok(ecrits);
        }
        // LE CORPS DOIT TENIR DANS LA FENÊTRE DU FLUX ET DANS CELLE DE LA
        // CONNEXION, qui vaut toujours 65 535 au départ (§6.9.2). Attendre une
        // mise à jour de fenêtre servirait des corps que ce client n'envoie pas.
        let fenetre = usize::try_from(pair.initial_window_size.min(65_535)).unwrap_or(0);
        if corps.len() > fenetre {
            return Err(faute(
                ErrorCode::FlowControlError,
                Cause::RequestBodyTooLarge,
            ));
        }
        let taille = usize::try_from(pair.max_frame_size)
            .unwrap_or(16_384)
            .max(1);
        let morceaux = corps.chunks(taille);
        let combien = morceaux.len();
        for (rang, morceau) in morceaux.enumerate() {
            let drapeaux = match rang.saturating_add(1) == combien {
                true => FIN_DE_FLUX,
                false => 0,
            };
            ecrits = poser_un_cadre(out, ecrits, FrameKind::Data, drapeaux, FLUX, morceau)?;
        }
        self.corps_envoye = true;
        Ok(ecrits)
    }

    /// Un cadre de bloc d'en-tête ; décodé une fois complet.
    fn en_tete(&mut self, entete: FrameHeader, charge: &[u8]) -> Result<(), Error> {
        let utile = match entete.kind() {
            FrameKind::Headers => {
                let sans = Padded::strip(charge, entete.flags().padded())?.data();
                // §6.2 : cinq octets de priorité, qu'on ne lit pas.
                match entete.flags().priority() {
                    true => sans
                        .get(5..)
                        .ok_or_else(|| faute(ErrorCode::ProtocolError, Cause::PaddingTooLong))?,
                    false => sans,
                }
            }
            _ => charge,
        };
        let BlockState::Complete(longueur) = self.bloc.push(entete, utile, &mut self.tete)? else {
            return Ok(());
        };
        let fin_de_flux = self.bloc.end_stream();
        self.decodeur.begin_block();
        let mut statut = None;
        let mut lu = 0_usize;
        while let Some(decode) = self.decodeur.next(
            self.tete.get(lu..longueur).unwrap_or_default(),
            &mut self.champ,
        )? {
            if decode.field.name == b":status" {
                statut = core::str::from_utf8(decode.field.value)
                    .ok()
                    .and_then(|texte| texte.parse::<u16>().ok());
            }
            lu = lu.saturating_add(decode.read);
        }
        match (self.statut, statut) {
            // Une réponse informative (1xx) n'est pas la réponse : on attend
            // la suivante.
            (None, Some(code)) if (100..200).contains(&code) => {}
            // §15 de RFC 9110 : une réponse finale est de 200 à 599. Un `0`,
            // un `42` ou un `999` n'en est pas une, et le prendre pour un statut
            // ferait décider sur un nombre qui ne veut rien dire — c'est le
            // fuzz qui l'a trouvé.
            (None, Some(code)) if (200..600).contains(&code) => self.statut = Some(code),
            // Des en-têtes de fin (trailers), après la réponse : rien à lire.
            (Some(_), None) => {}
            _ => return Err(faute(ErrorCode::ProtocolError, Cause::NoStatus)),
        }
        if fin_de_flux {
            self.terminer()?;
        }
        Ok(())
    }

    /// Le flux est fini : il faut qu'une réponse finale soit arrivée.
    fn terminer(&mut self) -> Result<(), Error> {
        match self.statut {
            Some(_) => {
                self.fini = true;
                Ok(())
            }
            None => Err(faute(ErrorCode::ProtocolError, Cause::NoStatus)),
        }
    }
}

/// `END_STREAM`.
const FIN_DE_FLUX: u8 = 0x1;
/// `END_HEADERS`.
const FIN_DE_TETE: u8 = 0x4;
/// `ACK`.
const ACQUITTE: u8 = 0x1;

/// Une faute du serveur, qui condamne la connexion.
const fn faute(code: ErrorCode, cause: Cause) -> Error {
    Error::connection(code, cause)
}

/// Recopie `octets` à `ecrits`, et rend le nouveau compte.
fn poser(out: &mut [u8], ecrits: usize, octets: &[u8]) -> Result<usize, Error> {
    let fin = ecrits.saturating_add(octets.len());
    out.get_mut(ecrits..fin)
        .ok_or_else(|| Error::connection(ErrorCode::InternalError, Cause::BufferTooSmall))?
        .copy_from_slice(octets);
    Ok(fin)
}

/// Écrit un cadre entier.
fn poser_un_cadre(
    out: &mut [u8],
    ecrits: usize,
    genre: FrameKind,
    drapeaux: u8,
    flux: u32,
    charge: &[u8],
) -> Result<usize, Error> {
    let longueur = u32::try_from(charge.len()).unwrap_or(u32::MAX);
    let entete = FrameHeader::new(genre, drapeaux, flux, longueur).write();
    let ecrits = poser(out, ecrits, &entete)?;
    poser(out, ecrits, charge)
}

#[cfg(test)]
mod tests;
