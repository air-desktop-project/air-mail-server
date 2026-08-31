// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La collection de flux d'une connexion, **sans entrée-sortie** (C1).
//!
//! # LES MACHINES EXISTAIENT ; RIEN NE SAVAIT LAQUELLE CHOISIR
//!
//! [`Send`], [`Recv`], [`Flow`] et [`Concurrences`] savent chacun tenir un
//! compte. Aucun ne sait à quel flux une trame s'adresse, ni lequel ouvrir, ni
//! quand oublier ce qui est fini. **C'est tout ce que ce module décide**, et
//! rien d'autre.
//!
//! # CE QU'IL NE GARDE PAS : LES OCTETS
//!
//! Les fenêtres de réception et les tampons d'émission restent à l'appelant :
//! [`Recv::on_stream`] demande déjà sa fenêtre en argument, et ce module se
//! contente de la lui passer. Il rend en échange un rang de table stable
//! ([`Streams::slot`]) qui sert à les indexer.
//!
//! **C'est ce qui garde ce crate `no_std` et sa taille bornée** : un flux coûte
//! ici quelques centaines d'octets d'état, et non la taille de sa fenêtre.
//!
//! # POURQUOI UN PLAFOND PAR QUADRANT, ET NON UN SEUL POUR LA TABLE
//!
//! §4.6 compte quatre familles de flux : deux sens d'ouverture, deux
//! directionnalités. Si les quatre puisaient dans le même crédit, le pair
//! pourrait remplir la table avec une seule famille et rendre les trois autres
//! inutilisables — sans jamais dépasser aucune limite annoncée.
//!
//! Chaque famille a donc sa part, et la somme des parts est la table. **Le
//! débordement devient impossible par construction**, et non gardé par un test
//! qu'aucun essai n'atteindrait.

use ams_proto_quic::{Directional, Initiator, StreamId, TransportParameters};

use crate::error::{Error, Reason};
use crate::flow::{Concurrences, Flow};
use crate::recv::Recv;
use crate::send::Send;

/// Combien de flux d'une même famille (§4.6) une connexion tient à la fois.
///
/// C'est le plafond qu'on annonce, et non un vœu : [`Streams::max_streams`] le
/// rend pour que l'appelant écrive CE nombre dans ses paramètres de transport
/// plutôt qu'un autre. Annoncer plus que ce qu'on tient ferait refuser un flux
/// qu'on avait promis d'accepter.
pub const FLUX_PAR_FAMILLE_MAX: u64 = 8;

/// Les quatre familles de §4.6 : deux sens d'ouverture, deux
/// directionnalités.
const FAMILLES: usize = 4;

/// Les bidirectionnels que le pair ouvre.
const ENTRANTS_BIDI: usize = 0;
/// Les unidirectionnels que le pair ouvre.
const ENTRANTS_UNI: usize = 1;
/// Les bidirectionnels que nous ouvrons.
const SORTANTS_BIDI: usize = 2;
/// Les unidirectionnels que nous ouvrons.
const SORTANTS_UNI: usize = 3;

/// La part de table d'une famille.
///
/// **CHAQUE FAMILLE A SES PLACES, ET NE PEUT PAS PRENDRE CELLES DES AUTRES.**
/// Un seul réservoir laisserait le pair remplir la table avec une famille et
/// rendre les trois autres inutilisables — sans dépasser aucune limite qu'on
/// lui a annoncée.
///
/// C'est le même nombre que [`FLUX_PAR_FAMILLE_MAX`], dans le type que compte
/// une table plutôt que dans celui que compte §4.6 ; l'assertion ci-dessous
/// échoue à la compilation s'ils divergent.
const PLACES_PAR_FAMILLE: usize = 8;

const _: () = assert!(FLUX_PAR_FAMILLE_MAX == PLACES_PAR_FAMILLE as u64);

/// Combien de flux vivants au total.
pub const FLUX_MAX: usize = FAMILLES.saturating_mul(PLACES_PAR_FAMILLE);

/// Un flux, et les moitiés qu'il a.
///
/// **UN FLUX UNIDIRECTIONNEL N'A QU'UNE MOITIÉ** (§2.1), et c'est l'absence qui
/// le dit : rien ne peut émettre sur un flux entrant, parce qu'il n'y a rien
/// pour le faire.
#[derive(Debug, Clone, Copy)]
struct Flux {
    /// Son numéro.
    id: StreamId,
    /// Le côté émission, si l'on a le droit d'écrire.
    envoi: Option<Send>,
    /// Le côté réception, si le pair a le droit d'écrire.
    reception: Option<Recv>,
}

impl Flux {
    /// Ce flux est-il fini des deux côtés ?
    ///
    /// C'est la condition pour libérer sa place : §3.3 ne dit rien du moment,
    /// mais tant qu'une moitié bouge encore, un `MAX_STREAM_DATA` ou un `ACK`
    /// peut arriver pour elle.
    const fn oubliable(&self) -> bool {
        let envoi = match self.envoi {
            Some(envoi) => envoi.state().fini(),
            None => true,
        };
        let reception = match self.reception {
            Some(reception) => reception.state().fini(),
            None => true,
        };
        envoi && reception
    }
}

/// Les trois limites par flux de §18.2, vues d'un côté.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limites {
    /// `initial_max_stream_data_bidi_local` : ce que celui qui l'annonce
    /// applique aux bidirectionnels **qu'il a ouverts**.
    bidi_local: u64,
    /// `initial_max_stream_data_bidi_remote` : ce qu'il applique à ceux que le
    /// PAIR a ouverts.
    bidi_remote: u64,
    /// `initial_max_stream_data_uni` : ce qu'il applique aux unidirectionnels
    /// entrants.
    uni: u64,
}

impl Limites {
    /// Les limites que ces paramètres annoncent.
    const fn de(parametres: &TransportParameters) -> Self {
        Self {
            bidi_local: parametres.initial_max_stream_data_bidi_local,
            bidi_remote: parametres.initial_max_stream_data_bidi_remote,
            uni: parametres.initial_max_stream_data_uni,
        }
    }
}

/// Les flux d'une connexion.
#[derive(Debug, Clone, Copy)]
pub struct Streams {
    /// La table, tassée ou non — un rang libéré ne bouge pas les autres, sans
    /// quoi les tampons de l'appelant suivraient le mauvais flux.
    flux: [Option<Flux>; FLUX_MAX],
    /// Le contrôle de flux de connexion en réception (§4.1).
    entrant: Flow,
    /// Et en émission.
    sortant: Flow,
    /// Les quatre comptes de §4.6.
    concurrences: Concurrences,
    /// Qui nous sommes.
    nous: Initiator,
    /// Ce que NOUS avons annoncé : les limites de réception.
    nos: Limites,
    /// Ce que le PAIR a annoncé : les limites d'émission.
    ses: Limites,
    /// Combien de flux de chaque famille ont été rendus à la table.
    ///
    /// **C'EST CE QUI FAIT MONTER LE PLAFOND** : §4.6 compte les flux ouverts
    /// depuis toujours, jamais les vivants. Sans ce compte, une connexion
    /// n'aurait droit qu'à huit flux par famille pour toute sa vie — et une
    /// page HTTP/3 en demande davantage.
    rendus: [u64; FAMILLES],
}

impl Streams {
    /// Les flux d'une connexion qui vient de s'établir.
    ///
    /// `nos` sont les paramètres qu'on a annoncés, `ses` ceux qu'on a reçus.
    ///
    /// **LES PLAFONDS DE FLUX SONT RAMENÉS À CE QU'ON TIENT** : ce qu'on annonce
    /// doit être ce qu'on honore, et [`Streams::max_streams`] rend le nombre
    /// adopté pour que l'appelant l'écrive dans ses paramètres.
    #[must_use]
    pub fn new(nous: Initiator, nos: &TransportParameters, ses: &TransportParameters) -> Self {
        let annonces = (
            nos.initial_max_streams_bidi.min(FLUX_PAR_FAMILLE_MAX),
            nos.initial_max_streams_uni.min(FLUX_PAR_FAMILLE_MAX),
        );
        // **CE QUE LE PAIR NOUS OUVRE EST BORNÉ AUSSI, ET POUR UNE AUTRE
        // RAISON** : la table est la nôtre. Un pair généreux ne doit pas nous
        // faire ouvrir plus de flux que nous n'avons de place.
        let recus = (
            ses.initial_max_streams_bidi.min(FLUX_PAR_FAMILLE_MAX),
            ses.initial_max_streams_uni.min(FLUX_PAR_FAMILLE_MAX),
        );
        Self {
            flux: [None; FLUX_MAX],
            entrant: Flow::receiving(nos.initial_max_data),
            sortant: Flow::sending(ses.initial_max_data),
            concurrences: Concurrences::new(nous, annonces, recus),
            nous,
            nos: Limites::de(nos),
            ses: Limites::de(ses),
            rendus: [0; FAMILLES],
        }
    }

    /// Le plafond qu'on tient réellement pour cette famille (§4.6).
    #[must_use]
    pub const fn max_streams(&self, sens: Directional) -> u64 {
        self.concurrences.incoming(sens).limit()
    }

    /// Le contrôle de flux de connexion en réception.
    #[must_use]
    pub const fn incoming(&self) -> &Flow {
        &self.entrant
    }

    /// Et en émission.
    #[must_use]
    pub const fn outgoing(&self) -> &Flow {
        &self.sortant
    }

    /// Le rang de ce flux dans la table, s'il est vivant.
    ///
    /// **C'EST PAR LÀ QUE L'APPELANT RETROUVE SES TAMPONS.** Le rang ne change
    /// pas tant que le flux vit, et n'est réattribué qu'après [`Streams::oublier`].
    #[must_use]
    pub fn slot(&self, flux: StreamId) -> Option<usize> {
        self.flux
            .iter()
            .position(|place| place.is_some_and(|vivant| vivant.id == flux))
    }
}

impl Streams {
    /// La limite de RÉCEPTION d'un flux : celle que NOUS annonçons (§18.2).
    const fn notre_limite(&self, flux: StreamId) -> u64 {
        match flux.directional() {
            Directional::Unidirectional => self.nos.uni,
            // §18.2 : `bidi_local` vaut pour les flux que CELUI QUI ANNONCE a
            // ouverts. C'est nous qui annonçons, donc c'est bien notre côté.
            Directional::Bidirectional => match self.est_notre(flux) {
                true => self.nos.bidi_local,
                false => self.nos.bidi_remote,
            },
        }
    }

    /// La limite d'ÉMISSION d'un flux : celle que le PAIR annonce.
    ///
    /// # LES DEUX NOMS S'INVERSENT, ET C'EST LÀ QU'ON SE TROMPE
    ///
    /// `bidi_local` d'un paramètre reçu parle des flux que LE PAIR a ouverts, et
    /// `bidi_remote` de ceux que NOUS avons ouverts — puisque c'est lui qui
    /// annonce. Prendre le même nom des deux côtés donnerait la mauvaise limite
    /// exactement pour les flux qu'on ouvre soi-même, ceux dont on se sert le
    /// plus.
    const fn sa_limite(&self, flux: StreamId) -> u64 {
        match flux.directional() {
            Directional::Unidirectional => self.ses.uni,
            Directional::Bidirectional => match self.est_notre(flux) {
                true => self.ses.bidi_remote,
                false => self.ses.bidi_local,
            },
        }
    }

    /// Est-ce nous qui avons ouvert ce flux ?
    const fn est_notre(&self, flux: StreamId) -> bool {
        matches!(
            (flux.initiator(), self.nous),
            (Initiator::Client, Initiator::Client) | (Initiator::Server, Initiator::Server)
        )
    }

    /// À quelle famille de §4.6 ce flux appartient.
    ///
    /// Les deux entrantes d'abord, pour que [`Streams::grant_streams`] les
    /// désigne par le même rang que [`Directional`].
    const fn famille(&self, flux: StreamId) -> usize {
        match (self.est_notre(flux), flux.directional()) {
            (false, Directional::Bidirectional) => ENTRANTS_BIDI,
            (false, Directional::Unidirectional) => ENTRANTS_UNI,
            (true, Directional::Bidirectional) => SORTANTS_BIDI,
            (true, Directional::Unidirectional) => SORTANTS_UNI,
        }
    }

    /// Les rangs que cette famille possède.
    const fn part(famille: usize) -> core::ops::Range<usize> {
        let debut = famille.saturating_mul(PLACES_PAR_FAMILLE);
        debut..debut.saturating_add(PLACES_PAR_FAMILLE)
    }

    /// Le rang d'une place libre dans la part de cette famille.
    fn place_libre(&self, famille: usize) -> Option<usize> {
        let part = Self::part(famille);
        let debut = part.start;
        self.flux
            .get(part)
            .unwrap_or_default()
            .iter()
            .position(Option::is_none)
            .map(|dans| debut.saturating_add(dans))
    }

    /// Le flux vivant de ce rang.
    fn a(&mut self, rang: usize) -> Option<&mut Flux> {
        self.flux.get_mut(rang).and_then(Option::as_mut)
    }

    /// Trouve ce flux, ou l'ouvre si le pair vient d'en parler (§2.1).
    ///
    /// # Errors
    ///
    /// [`Reason::StreamLimit`] au-delà du plafond annoncé,
    /// [`Reason::WrongStreamDirection`] si le pair écrit là où il n'a pas le
    /// droit, [`Reason::SendClosed`] si le flux est déjà fini et oublié — celui
    /// -là, §3.3 le range parmi les fautes seulement pour ce qu'on n'a jamais
    /// ouvert, et une trame retardataire ne doit pas fermer la connexion.
    fn trouver_ou_ouvrir(&mut self, flux: StreamId) -> Result<usize, Error> {
        if let Some(rang) = self.slot(flux) {
            return Ok(rang);
        }
        // **UN FLUX À NOUS QU'ON N'A PAS OUVERT N'EXISTE PAS** (§19.8) : « An
        // endpoint that receives a STREAM frame for a locally-initiated stream
        // that has not yet been created MUST terminate the connection with
        // STREAM_STATE_ERROR. » §2.1 donne à chaque côté ses numéros, et c'est
        // celui qui ouvre qui choisit quand.
        //
        // Le créer ici en ferait un second, portant le même numéro, le jour où
        // `open` prendrait ce rang — et deux entrées pour un flux, c'est deux
        // contrôles de flux qui divergent en silence.
        if self.est_notre(flux) {
            return Err(Error::new(Reason::StreamNotCreated));
        }
        // §4.6 : le plafond ensuite. Le refuser avant de prendre une place est
        // ce qui borne la table.
        self.concurrences.seen(flux)?;
        // **LA PLACE EXISTE FORCÉMENT** : le plafond de cette famille ne monte
        // jamais au-delà de ce qu'elle a rendu plus ses huit places, et
        // `seen` vient de le faire respecter. Un `?` ici serait une garde
        // qu'aucun essai ne pourrait atteindre.
        let rang = self
            .place_libre(self.famille(flux))
            .expect("une famille a toujours une place sous son plafond");
        let reception = flux
            .peer_can_send(self.nous)
            .then(|| Recv::new(self.notre_limite(flux)));
        let envoi = flux
            .we_can_send(self.nous)
            .then(|| Send::new(self.sa_limite(flux)));
        self.flux[rang] = Some(Flux {
            id: flux,
            envoi,
            reception,
        });
        Ok(rang)
    }
}

/// Ce qu'une trame `STREAM` ou `RESET_STREAM` fait au contrôle de connexion.
impl Streams {
    /// Ouvre ce flux si le pair vient d'en parler, ou le retrouve (§2.1).
    ///
    /// Rend son rang de table, par lequel l'appelant retrouve ses tampons.
    ///
    /// # Errors
    ///
    /// [`Reason::StreamLimit`], [`Reason::WrongStreamDirection`].
    pub fn accueillir(&mut self, flux: StreamId) -> Result<usize, Error> {
        self.trouver_ou_ouvrir(flux)
    }

    /// Range une trame `STREAM` (§19.8).
    ///
    /// `fenetre` porte les octets déjà reçus à partir de ce que l'application a
    /// lu, et fait au moins la limite qu'on a annoncée pour ce flux.
    ///
    /// # LE CRÉDIT DE CONNEXION SE VÉRIFIE AVANT DE RANGER, ET NON APRÈS
    ///
    /// §4.1 compte la somme des plus grands décalages de tous les flux. Ranger
    /// d'abord ferait monter celui du flux avant de découvrir que la connexion
    /// n'en avait pas le crédit — et l'état qu'on rapporterait en fermant
    /// n'aurait plus rien à voir avec celui d'avant la trame.
    ///
    /// # Errors
    ///
    /// [`Reason::FlowControl`] au-delà du crédit du flux OU de la connexion,
    /// [`Reason::FinalSize`], [`Reason::TooManyHoles`],
    /// [`Reason::WrongStreamDirection`] si le pair écrit là où il ne peut pas.
    pub fn on_stream(
        &mut self,
        flux: StreamId,
        decalage: u64,
        octets: &[u8],
        fin_de_flux: bool,
        fenetre: &mut [u8],
    ) -> Result<(), Error> {
        let rang = self.trouver_ou_ouvrir(flux)?;
        let disponible = self.entrant.available();
        let place = self
            .a(rang)
            .expect("le rang vient d'être ouvert ou retrouvé");
        let reception = place
            .reception
            .as_mut()
            .ok_or_else(|| Error::new(Reason::WrongStreamDirection))?;
        // Ce que cette trame ferait monter, avant de la ranger.
        let longueur = u64::try_from(octets.len()).unwrap_or(u64::MAX);
        let attendu = decalage
            .saturating_add(longueur)
            .saturating_sub(reception.largest());
        if attendu > disponible {
            return Err(Error::new(Reason::FlowControl));
        }
        let monte = reception.on_stream(decalage, octets, fin_de_flux, fenetre)?;
        self.entrant
            .consume(monte)
            .expect("la place a été vérifiée avant de ranger");
        Ok(())
    }

    /// Range un `RESET_STREAM` (§19.4).
    ///
    /// §4.5 fait compter la taille finale dans le contrôle de connexion **même
    /// si l'on n'a jamais reçu ces octets** : sans cela, un pair qui annule tous
    /// ses flux récupérerait du crédit qu'il n'a jamais rendu.
    ///
    /// # Errors
    ///
    /// [`Reason::FlowControl`], [`Reason::FinalSize`], [`Reason::StreamLimit`],
    /// [`Reason::WrongStreamDirection`].
    pub fn on_reset_stream(&mut self, flux: StreamId, taille_finale: u64) -> Result<(), Error> {
        let rang = self.trouver_ou_ouvrir(flux)?;
        let disponible = self.entrant.available();
        let place = self
            .a(rang)
            .expect("le rang vient d'être ouvert ou retrouvé");
        let reception = place
            .reception
            .as_mut()
            .ok_or_else(|| Error::new(Reason::WrongStreamDirection))?;
        let attendu = taille_finale.saturating_sub(reception.largest());
        if attendu > disponible {
            return Err(Error::new(Reason::FlowControl));
        }
        let monte = reception.on_reset(taille_finale)?;
        self.entrant
            .consume(monte)
            .expect("la place a été vérifiée avant de ranger");
        Ok(())
    }

    /// Range un `STOP_SENDING` (§19.5).
    ///
    /// **CE N'EST PAS UNE FERMETURE** : [`Send::stop_sending`] dit ensuite qu'il
    /// y a une décision à prendre, et c'est l'appelant qui la prend.
    ///
    /// # Errors
    ///
    /// [`Reason::StreamLimit`], [`Reason::WrongStreamDirection`] — §19.5 : un
    /// pair ne peut pas demander l'arrêt d'un flux sur lequel nous n'écrivons
    /// pas.
    pub fn on_stop_sending(&mut self, flux: StreamId, code: u64) -> Result<(), Error> {
        let rang = self.trouver_ou_ouvrir(flux)?;
        let place = self
            .a(rang)
            .expect("le rang vient d'être ouvert ou retrouvé");
        place
            .envoi
            .as_mut()
            .ok_or_else(|| Error::new(Reason::WrongStreamDirection))?
            .on_stop_sending(code);
        Ok(())
    }

    /// Range un `MAX_DATA` (§19.9).
    pub const fn on_max_data(&mut self, limite: u64) {
        self.sortant.set_limit(limite);
    }

    /// Range un `MAX_STREAM_DATA` (§19.10).
    ///
    /// # Errors
    ///
    /// [`Reason::StreamLimit`], [`Reason::WrongStreamDirection`] — §19.10 : le
    /// pair ne peut ouvrir du crédit que là où nous pouvons écrire.
    pub fn on_max_stream_data(&mut self, flux: StreamId, limite: u64) -> Result<(), Error> {
        let rang = self.trouver_ou_ouvrir(flux)?;
        let place = self
            .a(rang)
            .expect("le rang vient d'être ouvert ou retrouvé");
        place
            .envoi
            .as_mut()
            .ok_or_else(|| Error::new(Reason::WrongStreamDirection))?
            .set_limit(limite);
        Ok(())
    }

    /// Range un `MAX_STREAMS` (§19.11).
    ///
    /// **ON NE MONTE PAS AU-DELÀ DE CE QU'ON TIENT** : le pair peut nous en
    /// offrir mille, la table en tient [`FLUX_PAR_FAMILLE_MAX`], et ouvrir plus
    /// que ça échouerait chez nous, pas chez lui.
    pub const fn on_max_streams(&mut self, sens: Directional, plafond: u64) {
        let famille = match sens {
            Directional::Bidirectional => SORTANTS_BIDI,
            Directional::Unidirectional => SORTANTS_UNI,
        };
        let tenu = self.rendus[famille].saturating_add(FLUX_PAR_FAMILLE_MAX);
        let borne = match plafond > tenu {
            true => tenu,
            false => plafond,
        };
        self.concurrences.outgoing_mut(sens).set_limit(borne);
    }
}

/// Ce que l'application demande, et ce qu'on décide d'annoncer.
impl Streams {
    /// On ouvre un flux (§2.1).
    ///
    /// # Errors
    ///
    /// [`Reason::StreamLimit`] au-delà du plafond que le pair a annoncé — **et
    /// c'est notre faute** : il faut attendre un `MAX_STREAMS`, non ouvrir.
    pub fn open(&mut self, sens: Directional) -> Result<StreamId, Error> {
        let rang = self.concurrences.outgoing_mut(sens).open_local()?;
        let flux = StreamId::from_index(rang, self.nous, sens)
            .expect("un rang tiré d'un plafond de huit reste sous la borne de 2^60 de §19.11");
        let place = self
            .place_libre(self.famille(flux))
            .expect("une famille a toujours une place sous son plafond");
        self.flux[place] = Some(Flux {
            id: flux,
            envoi: Some(Send::new(self.sa_limite(flux))),
            reception: match sens {
                Directional::Bidirectional => Some(Recv::new(self.notre_limite(flux))),
                Directional::Unidirectional => None,
            },
        });
        Ok(flux)
    }

    /// L'application prend ce qui est prêt sur ce flux, dans l'ordre.
    ///
    /// Rend combien d'octets ont été pris ; zéro si le flux n'existe pas ou ne
    /// reçoit rien.
    pub fn read(&mut self, flux: StreamId, fenetre: &mut [u8], vers: &mut [u8]) -> usize {
        let Some(rang) = self.slot(flux) else {
            return 0;
        };
        // `slot` ne rend que le rang d'un flux vivant : un `else` ici serait une
        // garde qu'aucun essai ne pourrait atteindre.
        let place = self.flux[rang]
            .as_mut()
            .expect("`slot` ne rend que le rang d'un flux vivant");
        let Some(reception) = place.reception.as_mut() else {
            return 0;
        };
        reception.read(fenetre, vers)
    }

    /// Combien on peut émettre sur ce flux, **crédit de connexion compris**.
    ///
    /// §4.1 : les deux limites s'appliquent, et c'est la plus basse qui décide.
    /// N'en regarder qu'une ferait écrire une trame que le pair refuserait.
    #[must_use]
    pub fn credit(&self, flux: StreamId) -> u64 {
        let Some(rang) = self.slot(flux) else {
            return 0;
        };
        let place = self.flux[rang]
            .as_ref()
            .expect("`slot` ne rend que le rang d'un flux vivant");
        let Some(envoi) = place.envoi.as_ref() else {
            return 0;
        };
        envoi.allowed(self.sortant.available())
    }

    /// Note que des octets de ce flux viennent de partir.
    ///
    /// Rend le décalage du premier — celui à écrire dans la trame `STREAM`.
    ///
    /// # Errors
    ///
    /// [`Reason::SendClosed`] si le flux n'existe pas ou n'émet pas,
    /// [`Reason::SendClosed`], [`Reason::SendOverflow`] au-delà du crédit du
    /// flux ou de celui de la connexion. **CES DEUX-LÀ SONT NOS FAUTES** :
    /// [`Streams::credit`] disait déjà combien on pouvait écrire.
    pub fn on_sent(
        &mut self,
        flux: StreamId,
        longueur: u64,
        fin_de_flux: bool,
    ) -> Result<u64, Error> {
        let rang = self
            .slot(flux)
            .ok_or_else(|| Error::new(Reason::SendClosed))?;
        // **LE CRÉDIT DE CONNEXION SE VÉRIFIE AVANT DE RIEN BOUGER**, comme en
        // réception. Le consommer d'abord laisserait, si le flux refusait
        // ensuite, un crédit dépensé pour des octets jamais émis — et l'écart ne
        // se rattrape pas.
        let disponible = self.sortant.available();
        let place = self.flux[rang]
            .as_mut()
            .expect("`slot` ne rend que le rang d'un flux vivant");
        let envoi = place
            .envoi
            .as_mut()
            .ok_or_else(|| Error::new(Reason::SendClosed))?;
        if longueur > disponible {
            return Err(Error::new(Reason::SendOverflow));
        }
        let decalage = envoi.on_sent(longueur, fin_de_flux)?;
        self.sortant
            .consume(longueur)
            .expect("le crédit a été vérifié avant d'émettre");
        Ok(decalage)
    }

    /// Le pair a accusé un morceau de ce flux.
    ///
    /// # Errors
    ///
    /// [`Reason::SendClosed`] si le flux n'existe pas ou n'émet pas ;
    /// [`Reason::TooManyHoles`].
    pub fn on_acked(&mut self, flux: StreamId, decalage: u64, longueur: u64) -> Result<(), Error> {
        let rang = self
            .slot(flux)
            .ok_or_else(|| Error::new(Reason::SendClosed))?;
        let place = self.flux[rang]
            .as_mut()
            .expect("`slot` ne rend que le rang d'un flux vivant");
        place
            .envoi
            .as_mut()
            .ok_or_else(|| Error::new(Reason::SendClosed))?
            .on_acked(decalage, longueur)
    }

    /// On annule ce flux (§19.4). Rend la taille finale à écrire.
    ///
    /// # Errors
    ///
    /// [`Reason::SendClosed`].
    pub fn reset(&mut self, flux: StreamId) -> Result<u64, Error> {
        let rang = self
            .slot(flux)
            .ok_or_else(|| Error::new(Reason::SendClosed))?;
        let place = self.flux[rang]
            .as_mut()
            .expect("`slot` ne rend que le rang d'un flux vivant");
        place
            .envoi
            .as_mut()
            .ok_or_else(|| Error::new(Reason::SendClosed))?
            .reset()
    }

    /// La limite de connexion à annoncer pour laisser passer `voulu` de plus,
    /// ou `None` si celle en vigueur suffit (§19.9).
    #[must_use]
    pub const fn grant_data(&self, voulu: u64) -> Option<u64> {
        self.entrant.grant(voulu)
    }

    /// Le plafond de flux à annoncer pour cette famille, ou `None` s'il ne dit
    /// rien de neuf (§19.11).
    ///
    /// C'est ce qu'on a rendu, **plus ce que la table tient**. Les deux termes
    /// comptent : un pair qui nous avait annoncé peu nous laisse de la place dès
    /// le départ, et chaque flux rendu en libère une de plus.
    ///
    /// Ce qu'on n'annonce jamais, c'est au-delà de la table — cela promettrait
    /// un flux qu'on n'aurait pas où mettre.
    #[must_use]
    pub const fn grant_streams(&self, sens: Directional) -> Option<u64> {
        let famille = match sens {
            Directional::Bidirectional => ENTRANTS_BIDI,
            Directional::Unidirectional => ENTRANTS_UNI,
        };
        let tenu = self.rendus[famille].saturating_add(FLUX_PAR_FAMILLE_MAX);
        match tenu > self.concurrences.incoming(sens).limit() {
            true => Some(tenu),
            false => None,
        }
    }

    /// Entérine le plafond qu'on vient d'annoncer par un `MAX_STREAMS`.
    ///
    /// **À N'APPELER QU'UNE FOIS LA TRAME ÉCRITE** : c'est ce qui fait accepter
    /// les flux que le pair ouvrira. L'appeler trop tôt accepterait des flux
    /// qu'il n'a pas le droit d'ouvrir ; ne pas l'appeler du tout ferait refuser
    /// ceux qu'on vient de lui promettre.
    pub const fn set_max_streams(&mut self, sens: Directional, plafond: u64) {
        self.concurrences.incoming_mut(sens).set_limit(plafond);
    }

    /// Le flux que ce rang porte, s'il en porte un.
    ///
    /// C'est par là qu'on parcourt la table sans tenir soi-même la liste de ce
    /// qui vit — et c'est la seule façon de savoir à quel flux appartiennent les
    /// tampons d'un rang.
    #[must_use]
    pub fn occupant(&self, rang: usize) -> Option<StreamId> {
        self.flux
            .get(rang)
            .and_then(|place| place.as_ref())
            .map(|vivant| vivant.id)
    }

    /// Le flux de ce rang est-il fini des deux côtés ?
    #[must_use]
    pub fn fini(&self, rang: usize) -> bool {
        self.flux
            .get(rang)
            .and_then(|place| place.as_ref())
            .is_some_and(Flux::oubliable)
    }

    /// Rend sa place à la table, et rend son numéro.
    ///
    /// L'appelant peut alors relâcher les tampons de ce rang. **APRÈS QUOI LE
    /// RANG SE RÉATTRIBUE** : le garder ailleurs ferait suivre le mauvais flux.
    pub fn oublier(&mut self, rang: usize) -> Option<StreamId> {
        if !self.fini(rang) {
            return None;
        }
        // `fini` vient de dire que ce rang porte un flux : un `?` ici serait une
        // garde qu'aucun essai ne pourrait atteindre.
        let parti = self.flux[rang]
            .take()
            .expect("`fini` ne dit vrai que d'un rang occupé");
        // La famille se relit du numéro, et non du rang : c'est la même chose,
        // mais l'une des deux se vérifie.
        let famille = self.famille(parti.id);
        self.rendus[famille] = self.rendus[famille].saturating_add(1);
        // **LE PLAFOND NE MONTE PAS ICI.** Une place libre n'est pas une
        // promesse : tant que le `MAX_STREAMS` n'est pas parti, le pair ne sait
        // rien de ce crédit. C'est [`Streams::grant_streams`] qui le propose et
        // [`Streams::set_max_streams`] qui l'entérine, une fois la trame écrite.
        Some(parti.id)
    }
}

#[cfg(test)]
mod tests;
