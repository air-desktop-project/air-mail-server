// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le conducteur HTTP/3 **côté client**, sans entrée-sortie (C1).
//!
//! # POURQUOI IL N'ÉTAIT PAS LÀ, ET POURQUOI IL L'EST MAINTENANT
//!
//! Ce dépôt n'avait qu'un serveur : [`crate::Http3`] SERT des requêtes. Le
//! cadrage, QPACK, les réglages et l'état de connexion, eux, n'ont jamais eu de
//! côté — ce qui manquait est **l'ordre des gestes**, et il n'est pas le même :
//! un client ouvre un flux et écrit une requête, puis lit une réponse.
//!
//! `air-service-locator` en a besoin pour que ses daemons parlent à l'annuaire,
//! et la règle de ce dépôt-là est de ne jamais réécrire une pile empruntée. La
//! moitié manquante s'écrit donc ici, à côté de l'autre.
//!
//! # CE QU'IL SAIT FAIRE, ET CE QU'IL NE SAIT PAS
//!
//! **Il sait** : ouvrir ses trois flux, écrire une requête avec son corps, lire
//! les réglages du serveur, lire une réponse — son code d'état et son corps.
//!
//! **Il ne sait pas** : les promesses de poussée (§4.6), les trames étendues
//! (§9), l'interrogation d'un `GOAWAY` reçu pour rejouer ailleurs. Les deux
//! premières se refusent proprement ; la troisième est une politique de reprise,
//! et elle vit chez l'appelant — `asl_client::Reprise` en est une.
//!
//! # UNE RÉPONSE NE PORTE QUE SON CODE ET SON CORPS
//!
//! Les champs ordinaires sont DÉCODÉS — il le faut, sans quoi une faute de
//! compression passerait — mais ils ne sont pas retenus. La raison est écrite
//! sur `ams_proto_h3::qpack::read_response_section` : retenir une table de
//! champs demanderait de choisir combien et où, pour un appelant qu'on ne
//! connaît pas.

use ams_proto_h3::{
    Connection as H3Connection, FrameHeader, FrameKind, Message, Placement, Settings, StreamHead,
    StreamKind, accept_stream, qpack, read_stream_head,
};
use ams_proto_http::StatusCode;
use ams_proto_quic::{Directional, Initiator, StreamId, varints};
use ams_quic::RecvState;

use crate::error::{Error, Reason};
use crate::transport::Transport;
use crate::{
    CHAMPS_OCTETS_MAX, CHARGE_OCTETS_MAX, CORPS_OCTETS_MAX, ENTETE_OCTETS_MAX, TAMPON_OCTETS_MAX,
    ouvrir_nos_flux,
};

/// Ce qu'un flux du pair est, une fois sa tête lue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Le flux de réponse d'une de nos requêtes.
    Reponse,
    /// Le flux de contrôle du serveur (§6.2.1).
    Controle,
    /// Un flux QPACK du serveur, qui ne dira rien (§4.2 de RFC 9204).
    Qpack,
    /// Un flux d'un type qu'on ignore, et dont on jette les octets (§6.2).
    Inconnu,
    /// La tête n'est pas encore lue.
    Neuf,
}

/// Ce qu'on suit, un par flux vivant.
#[derive(Debug)]
struct Suivi {
    flux: StreamId,
    role: Role,
    /// Ce qu'on a lu et pas encore compris.
    tampon: Vec<u8>,
    /// Ce qu'il reste à lire du corps de la trame `DATA` en cours.
    ///
    /// # SEULE `DATA` SE LIT PAR MORCEAUX, ET C'EST POURQUOI IL N'Y A PAS DE TYPE
    ///
    /// Une section d'en-têtes se décode d'un bloc — on ne l'entame donc jamais,
    /// on attend qu'elle soit entière. Ce qu'on ignore passe par `a_sauter`.
    /// Porter le type ici aurait fait un bras de `match` que rien n'atteint.
    reste_du_corps: u64,
    /// Combien d'octets d'une trame ignorée restent à jeter (§9).
    a_sauter: u64,
    /// L'état de message de ce flux (§4.1).
    message: Message,
    /// Le code d'état, une fois la section d'en-têtes lue.
    statut: Option<StatusCode>,
    /// Le corps, tel qu'il arrive.
    corps: Vec<u8>,
    /// Le pair a-t-il fini d'écrire ?
    fini: bool,
}

impl Suivi {
    fn neuf(flux: StreamId) -> Self {
        Self {
            flux,
            role: Role::Neuf,
            tampon: Vec::new(),
            reste_du_corps: 0,
            a_sauter: 0,
            message: Message::new(),
            statut: None,
            corps: Vec::new(),
            fini: false,
        }
    }
}

/// Une réponse entière.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reponse {
    /// Le code d'état (§4.3.2).
    pub statut: StatusCode,
    /// Le corps, tel qu'il est arrivé.
    pub corps: Vec<u8>,
}

/// Le conducteur HTTP/3 d'une connexion cliente.
#[derive(Debug)]
pub struct Http3Client {
    /// L'état de connexion de §6.2 et §7.2.
    h3: H3Connection,
    /// Ce qu'on suit, un par flux vivant.
    suivis: Vec<Suivi>,
    /// Nos trois flux, une fois ouverts.
    controle: Option<StreamId>,
    encodeur: Option<StreamId>,
    decodeur: Option<StreamId>,
    /// Les réglages qu'on annonce.
    nos_reglages: Settings,
}

impl Default for Http3Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Http3Client {
    /// Un conducteur pour une connexion qui vient de s'établir.
    #[must_use]
    pub fn new() -> Self {
        Self {
            h3: H3Connection::new(),
            suivis: Vec::new(),
            controle: None,
            encodeur: None,
            decodeur: None,
            nos_reglages: Settings::DEFAULT,
        }
    }

    /// Notre flux de contrôle, une fois ouvert.
    #[must_use]
    pub const fn control_stream(&self) -> Option<StreamId> {
        self.controle
    }

    /// Les réglages que le serveur a annoncés (§7.2.4).
    #[must_use]
    pub const fn peer_settings(&self) -> Option<Settings> {
        self.h3.peer_settings()
    }

    /// La connexion QUIC est établie : on ouvre nos trois flux.
    ///
    /// **C'EST LE MÊME GESTE QUE CÔTÉ SERVEUR**, et §6.2.1 l'exige des deux :
    /// « Each side MUST initiate a single control stream at the beginning of the
    /// connection and send its SETTINGS frame as the first frame on this
    /// stream. » L'ouverture est donc écrite une fois, dans `ouvrir_nos_flux`.
    ///
    /// # Errors
    ///
    /// [`Reason::Transport`] si le pair n'a pas ouvert de quoi ouvrir trois flux
    /// unidirectionnels.
    pub fn on_established<T: Transport>(&mut self, quic: &mut T) -> Result<(), Error> {
        if self.controle.is_some() {
            return Ok(());
        }
        let (controle, encodeur, decodeur) = ouvrir_nos_flux(quic, &self.nos_reglages)?;
        self.controle = Some(controle);
        self.encodeur = Some(encodeur);
        self.decodeur = Some(decodeur);
        Ok(())
    }

    /// Ouvre un flux, y écrit cette requête, et le termine.
    ///
    /// Rend l'identifiant du flux : c'est par lui que la réponse se réclamera.
    ///
    /// # LE FLUX EST TERMINÉ TOUT DE SUITE, ET C'EST UN CHOIX
    ///
    /// §4.1 : une requête est une section d'en-têtes, puis un corps. Ce
    /// conducteur écrit les deux d'un coup et conclut — il ne sait pas
    /// **diffuser** un corps qui arriverait par morceaux.
    ///
    /// Ce n'est pas une limite subie : les corps de l'API qui l'emploie tiennent
    /// en quelques centaines d'octets, et un `finish` différé demanderait de
    /// tenir un état de flux ouvert dont personne n'a besoin. Le jour où un
    /// appelant voudra diffuser, ce sera un ajout.
    ///
    /// # Errors
    ///
    /// [`Reason::Transport`] si le pair n'a pas ouvert de quoi ouvrir un flux
    /// bidirectionnel, ou si le flux n'accepte pas tout ; [`Reason::H3`] si la
    /// requête ne s'écrit pas.
    pub fn request<T: Transport>(
        &mut self,
        quic: &mut T,
        methode: &[u8],
        chemin: &[u8],
        autorite: &[u8],
        champs: &[(&[u8], &[u8])],
        corps: &[u8],
    ) -> Result<StreamId, Error> {
        let mut section = [0_u8; CHAMPS_OCTETS_MAX];
        let combien =
            qpack::write_request_section(methode, b"https", autorite, chemin, champs, &mut section)
                .map_err(Error::depuis_h3)?;

        // **CES DEUX ÉCRITURES NE PEUVENT PAS ÉCHOUER**, et un `?` ouvrirait
        // deux branches que rien ne peut emprunter : un en-tête de §7.1 fait au
        // plus neuf octets — un type sur un, une longueur sur huit —, et le
        // tampon en fait seize. C'est l'idiome de `ouvrir_nos_flux`, et pour la
        // même raison.
        let mut sortie = Vec::new();
        let mut entete = [0_u8; ENTETE_OCTETS_MAX];
        let pose = ams_proto_h3::write_header(
            FrameKind::Headers,
            u64::try_from(combien).unwrap_or(u64::MAX),
            &mut entete,
        )
        .expect("un en-tête de §7.1 tient dans seize octets");
        sortie.extend_from_slice(entete.get(..pose).unwrap_or_default());
        sortie.extend_from_slice(section.get(..combien).unwrap_or_default());

        if !corps.is_empty() {
            let pose = ams_proto_h3::write_header(
                FrameKind::Data,
                u64::try_from(corps.len()).unwrap_or(u64::MAX),
                &mut entete,
            )
            .expect("un en-tête de §7.1 tient dans seize octets");
            sortie.extend_from_slice(entete.get(..pose).unwrap_or_default());
            sortie.extend_from_slice(corps);
        }

        let flux = quic.open_bi()?;
        // **TOUT OU RIEN** : un flux qui n'aurait pris qu'une partie de la
        // requête laisserait le serveur attendre une section incomplète, et rien
        // dans ce qu'il verrait ne lui dirait qu'elle ne viendra pas.
        if quic.write(flux, &sortie)? != sortie.len() {
            return Err(Error::new(Reason::Interne));
        }
        quic.finish(flux)?;
        self.suivis.push(Suivi::neuf(flux));
        Ok(flux)
    }

    /// Ce flux a de quoi être lu.
    ///
    /// # Errors
    ///
    /// [`Reason::H3`] pour ce que §4, §6.2 et §7.2 refusent ;
    /// [`Reason::Transport`] si le transport refuse.
    pub fn on_readable<T: Transport>(&mut self, quic: &mut T, flux: StreamId) -> Result<(), Error> {
        // §6.1 : nos propres flux unidirectionnels ne portent rien qu'on lise.
        if matches!(flux.initiator(), Initiator::Client)
            && matches!(flux.directional(), Directional::Unidirectional)
        {
            return Ok(());
        }
        let rang = self.rang_de(flux);
        self.avaler(quic, rang)?;

        // §6.2.1 et §4.2 de RFC 9204 : un flux critique qui se ferme est une
        // faute, et il n'y a pas de cas où c'est acceptable.
        if matches!(self.suivis[rang].role, Role::Controle | Role::Qpack)
            && matches!(
                quic.recv_state(flux),
                Some(RecvState::DataRecvd | RecvState::DataRead)
            )
        {
            return Err(Error::depuis_h3(
                self.h3
                    .on_critical_stream_closed()
                    .expect_err("cette fonction ne rend jamais `Ok`"),
            ));
        }
        Ok(())
    }

    /// La réponse de ce flux, si elle est entière.
    ///
    /// **ELLE SE PREND UNE FOIS** : le suivi disparaît avec elle. Un appelant
    /// qui la redemanderait obtiendrait `None`, ce qui est exact — il l'a déjà.
    pub fn take_response(&mut self, flux: StreamId) -> Option<Reponse> {
        let rang = self
            .suivis
            .iter()
            .position(|suivi| suivi.flux == flux && suivi.fini)?;
        let suivi = self.suivis.remove(rang);
        Some(Reponse {
            // **UN FLUX FINI PORTE TOUJOURS SON STATUT.** `peut_etre_finir` ne
            // pose `fini` qu'après `Message::on_end`, qui refuse un message sans
            // section d'en-têtes ; et une section lue pose toujours un statut,
            // puisque `read_response_section` refuse celles qui n'en ont pas.
            // Un `?` ici ouvrirait une branche qu'aucun essai ne pourrait
            // atteindre.
            statut: suivi
                .statut
                .expect("un flux fini a passé `on_end`, donc il a une section"),
            corps: suivi.corps,
        })
    }

    /// Le rang de ce flux, en le créant au besoin.
    fn rang_de(&mut self, flux: StreamId) -> usize {
        if let Some(rang) = self.suivis.iter().position(|suivi| suivi.flux == flux) {
            return rang;
        }
        self.suivis.push(Suivi::neuf(flux));
        self.suivis.len().saturating_sub(1)
    }

    /// Lit ce qui est prêt, et avance tant que ça avance.
    fn avaler<T: Transport>(&mut self, quic: &mut T, rang: usize) -> Result<(), Error> {
        let flux = self.suivis[rang].flux;
        let mut vers = [0_u8; TAMPON_OCTETS_MAX];
        loop {
            if self.suivis[rang].a_sauter > 0 {
                let combien = usize::try_from(self.suivis[rang].a_sauter)
                    .unwrap_or(usize::MAX)
                    .min(vers.len());
                let lus = quic.read(flux, vers.get_mut(..combien).unwrap_or_default());
                if lus == 0 {
                    return Ok(());
                }
                self.suivis[rang].a_sauter = self.suivis[rang]
                    .a_sauter
                    .saturating_sub(u64::try_from(lus).unwrap_or(0));
                continue;
            }

            let lus = quic.read(flux, &mut vers);
            self.suivis[rang]
                .tampon
                .extend_from_slice(vers.get(..lus).unwrap_or_default());
            if !self.un_pas(quic, rang)? {
                return Ok(());
            }
        }
    }

    /// Fait avancer ce flux d'un pas, s'il peut avancer.
    ///
    /// Rend `false` quand il faut davantage d'octets — c'est la condition
    /// d'arrêt de la boucle, et la seule.
    fn un_pas<T: Transport>(&mut self, quic: &T, rang: usize) -> Result<bool, Error> {
        match self.suivis[rang].role {
            Role::Neuf => self.lire_la_tete(rang),
            Role::Reponse => self.un_pas_de_reponse(quic, rang),
            Role::Controle => self.un_pas_de_controle(rang),
            // §4.2 de RFC 9204 : nous avons annoncé une table nulle, donc le
            // serveur n'a aucune instruction à nous donner. Ce qu'il enverrait
            // quand même, on le jette — sans le lire, il n'y a rien à en faire.
            Role::Qpack | Role::Inconnu => {
                self.suivis[rang].tampon.clear();
                Ok(false)
            }
        }
    }

    /// Lit le type d'un flux du pair (§6.2).
    fn lire_la_tete(&mut self, rang: usize) -> Result<bool, Error> {
        // Un flux BIDIRECTIONNEL que nous avons ouvert ne porte pas de type :
        // c'est une réponse, et elle commence par une trame.
        if matches!(
            self.suivis[rang].flux.directional(),
            Directional::Bidirectional
        ) {
            self.suivis[rang].role = Role::Reponse;
            return Ok(true);
        }
        let StreamHead::Ready { kind, read } = read_stream_head(&self.suivis[rang].tampon) else {
            return Ok(false);
        };
        self.suivis[rang].tampon.drain(..read);
        self.suivis[rang].role = match kind {
            // **PAS D'`accept_stream` ICI** : elle ne refuse que ce qu'on ne
            // conduit pas, et un flux de contrôle, on le conduit. Un `?` sur un
            // appel qui rend toujours `Ok` serait une branche que rien ne peut
            // emprunter. C'est `on_peer_stream` qui garde le vrai refus : un
            // SECOND flux de contrôle (§6.2.1).
            StreamKind::Control => {
                self.h3.on_peer_stream(kind).map_err(Error::depuis_h3)?;
                Role::Controle
            }
            StreamKind::QpackEncoder | StreamKind::QpackDecoder => {
                self.h3.on_peer_stream(kind).map_err(Error::depuis_h3)?;
                Role::Qpack
            }
            // **UNE POUSSÉE SE REFUSE, ELLE NE SE JETTE PAS.**
            //
            // §4.6 : nous n'avons annoncé aucun `SETTINGS_MAX_PUSH_ID`, donc le
            // serveur n'a pas le droit d'en ouvrir une. La jeter en silence le
            // laisserait croire qu'elle est partie ; `accept_stream` la nomme.
            StreamKind::Push => {
                return Err(Error::depuis_h3(
                    accept_stream(kind).expect_err("une poussée se refuse toujours"),
                ));
            }
            // §6.2 : « Recipients of unknown stream types MUST either abort
            // reading of the stream or discard incoming data without further
            // processing. » On jette, ce qui ne coûte rien et ne condamne rien —
            // c'est ce que la même section demande, et c'est ce qui laisse
            // l'extensibilité ouverte.
            _ => Role::Inconnu,
        };
        Ok(true)
    }

    /// Un pas sur le flux de contrôle du serveur (§6.2.1, §7.2).
    fn un_pas_de_controle(&mut self, rang: usize) -> Result<bool, Error> {
        let Ok(entete) = FrameHeader::parse(&self.suivis[rang].tampon) else {
            return Ok(false);
        };
        entete
            .check_stream(Placement::Control)
            .map_err(Error::depuis_h3)?;
        let total = usize::try_from(entete.total()).unwrap_or(usize::MAX);
        if self.suivis[rang].tampon.len() < total {
            // **UNE CHARGE PLUS LONGUE QUE NOTRE BORNE NE VIENDRA JAMAIS
            // ENTIÈRE** : c'est notre borne (C3), et l'attendre serait attendre
            // pour toujours.
            if total > CHARGE_OCTETS_MAX.saturating_add(ENTETE_OCTETS_MAX) {
                return Err(Error::depuis_h3(ams_proto_h3::Error::new(
                    ams_proto_h3::Reason::MalformedFrame,
                )));
            }
            return Ok(false);
        }
        let charge = self.suivis[rang]
            .tampon
            .get(entete.header_len()..total)
            .unwrap_or_default()
            .to_vec();
        let reglages = match entete.kind() {
            FrameKind::Settings => Some(Settings::read(&charge).map_err(Error::depuis_h3)?),
            _ => None,
        };
        let identifiant = match entete.kind() {
            FrameKind::GoAway | FrameKind::MaxPushId => {
                varints::decode(&charge).map_or(0, |(valeur, _)| valeur)
            }
            _ => 0,
        };
        self.h3
            .on_control_frame(entete.kind(), reglages, identifiant)
            .map_err(Error::depuis_h3)?;
        self.suivis[rang].tampon.drain(..total);
        Ok(true)
    }

    /// Un pas sur un flux de réponse (§4.1).
    fn un_pas_de_reponse<T: Transport>(&mut self, quic: &T, rang: usize) -> Result<bool, Error> {
        if self.suivis[rang].reste_du_corps > 0 {
            let pris = usize::try_from(self.suivis[rang].reste_du_corps)
                .unwrap_or(usize::MAX)
                .min(self.suivis[rang].tampon.len());
            if pris == 0 {
                return self.peut_etre_finir(quic, rang);
            }
            let morceau: Vec<u8> = self.suivis[rang].tampon.drain(..pris).collect();
            // **NOTRE BORNE, PAS CELLE DU PAIR** (C3) : sans elle, un serveur
            // choisirait combien nous retenons.
            if self.suivis[rang].corps.len().saturating_add(morceau.len()) > CORPS_OCTETS_MAX {
                return Err(Error::new(Reason::Excessive));
            }
            self.suivis[rang].corps.extend_from_slice(&morceau);
            self.suivis[rang].reste_du_corps = self.suivis[rang]
                .reste_du_corps
                .saturating_sub(u64::try_from(pris).unwrap_or(0));
            return Ok(true);
        }

        let Ok(entete) = FrameHeader::parse(&self.suivis[rang].tampon) else {
            return self.peut_etre_finir(quic, rang);
        };
        entete
            .check_stream(Placement::Request)
            .map_err(Error::depuis_h3)?;
        self.suivis[rang]
            .message
            .on_frame(entete.kind())
            .map_err(Error::depuis_h3)?;

        match entete.kind() {
            FrameKind::Headers => {
                let total = usize::try_from(entete.total()).unwrap_or(usize::MAX);
                if entete.length() > u64::try_from(CHAMPS_OCTETS_MAX).unwrap_or(u64::MAX) {
                    return Err(Error::new(Reason::Excessive));
                }
                if self.suivis[rang].tampon.len() < total {
                    return Ok(false);
                }
                let section = self.suivis[rang]
                    .tampon
                    .get(entete.header_len()..total)
                    .unwrap_or_default()
                    .to_vec();
                let mut place = [0_u8; CHAMPS_OCTETS_MAX];
                let statut =
                    qpack::read_response_section(&section, &mut place).map_err(Error::depuis_h3)?;
                // **CE CONDUCTEUR REFUSE LES REMORQUES, ET IL FAUT LE DIRE.**
                //
                // §4.1 permet une seconde section de champs après le corps.
                // `read_response_section` la refuse — elle ne porte pas de
                // `:status` —, donc on n'arrive jamais ici deux fois, et il n'y
                // a pas de « garder la première » à écrire.
                //
                // Ce n'est pas une limite subie : l'API que ce conducteur sert
                // n'en émet aucune, et les accepter demanderait de choisir où
                // les retenir. Le jour où l'une d'elles portera quelque chose,
                // ce sera un ajout, et il se verra ici.
                self.suivis[rang].statut = Some(statut);
                self.suivis[rang].tampon.drain(..total);
                Ok(true)
            }
            FrameKind::Data => {
                self.suivis[rang].tampon.drain(..entete.header_len());
                self.suivis[rang].reste_du_corps = entete.length();
                Ok(true)
            }
            // §9 : ce qu'on ne connaît pas se saute, charge comprise.
            _ => {
                self.suivis[rang].tampon.drain(..entete.header_len());
                // **CE QUI EST DÉJÀ LÀ SE JETTE ICI, ET NON AU TOUR SUIVANT.**
                // `a_sauter` fait lire le TRANSPORT ; si la charge est déjà dans
                // le tampon, elle n'y reviendrait jamais — et le flux
                // attendrait des octets que le pair a déjà envoyés.
                let a_sauter = entete.length();
                let ici = usize::try_from(a_sauter)
                    .unwrap_or(usize::MAX)
                    .min(self.suivis[rang].tampon.len());
                self.suivis[rang].tampon.drain(..ici);
                self.suivis[rang].a_sauter =
                    a_sauter.saturating_sub(u64::try_from(ici).unwrap_or(0));
                Ok(true)
            }
        }
    }

    /// Le pair a-t-il fini d'écrire ce flux ?
    fn peut_etre_finir<T: Transport>(&mut self, quic: &T, rang: usize) -> Result<bool, Error> {
        if !matches!(
            quic.recv_state(self.suivis[rang].flux),
            Some(RecvState::DataRecvd | RecvState::DataRead)
        ) {
            return Ok(false);
        }
        if !self.suivis[rang].tampon.is_empty() {
            return Ok(false);
        }
        // §4.1 : un message qui s'arrête au mauvais endroit n'en est pas un.
        self.suivis[rang]
            .message
            .on_end()
            .map_err(Error::depuis_h3)?;
        self.suivis[rang].fini = true;
        Ok(false)
    }
}

#[cfg(test)]
mod tests;
