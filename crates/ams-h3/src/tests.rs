// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que §6.2, §6.2.1 et §7.2 imposent à l'ouverture d'une connexion HTTP/3.
//!
//! # LE TRANSPORT EST UN FAUX, ET C'EST CE QUI REND CES ESSAIS UTILES
//!
//! Un vrai transport demanderait un certificat et une poignée de main complète à
//! chaque essai — plusieurs secondes, et ce qu'ils montreraient porterait autant
//! sur TLS que sur HTTP/3. Ici, chaque essai dit UNE chose sur HTTP/3.
//!
//! Ce que la vraie pile fait, un essai d'`ams-loop-tokio` le montre sur une
//! socket : celui-ci ne remplace pas celui-là.

use std::collections::HashMap;

use ams_proto_h3::{FrameKind, Settings, StreamKind, write_header};
use ams_proto_quic::{Directional, Initiator, StreamId, varints};
use ams_quic::RecvState;

use super::{Http3, Transport};
use crate::error::{Error, Reason};

/// Un transport de fer-blanc : des files d'octets, et rien d'autre.
#[derive(Debug, Default)]
struct Faux {
    /// Ce que le pair a envoyé, par flux.
    entrant: HashMap<u64, Vec<u8>>,
    /// Ce que nous avons écrit, par flux.
    sortant: HashMap<u64, Vec<u8>>,
    /// L'état de réception qu'on prétend, par flux.
    etats: HashMap<u64, RecvState>,
    /// Le prochain rang de flux unidirectionnel qu'on ouvrira.
    prochain: u64,
    /// Le pair nous a-t-il ouvert de quoi ouvrir ?
    plafond: u64,
    /// À partir de quelle écriture refuse-t-il ?
    ///
    /// **UN RANG PLUTÔT QU'UN FANION** : un transport peut laisser passer le flux
    /// de contrôle et refuser le suivant, et c'est même le cas intéressant —
    /// `on_established` en ouvre trois d'affilée. Un booléen ne saurait dire
    /// « celui-là oui, celui-ci non ».
    ///
    /// **UN SEUL FAUX TRANSPORT, ET NON DEUX** : chaque type qui traverse un
    /// générique en fait recopier le code, et une seconde copie demanderait
    /// d'éprouver deux fois chaque branche pour n'en montrer aucune de plus.
    refuse_a_partir_de: Option<usize>,
    /// Combien d'écritures ont abouti.
    ecritures: usize,
    /// Les flux qu'on a annulés, et avec quel code (§19.4 de RFC 9000).
    annules: Vec<(u64, u64)>,
}

impl Faux {
    /// Un transport qui laisse ouvrir huit flux.
    fn new() -> Self {
        Self {
            plafond: 8,
            ..Self::default()
        }
    }

    /// Le pair écrit ceci sur ce flux.
    fn le_pair_dit(&mut self, flux: u64, octets: &[u8]) {
        self.entrant
            .entry(flux)
            .or_default()
            .extend_from_slice(octets);
        self.etats.entry(flux).or_insert(RecvState::Recv);
    }

    /// Ce qu'on a écrit sur ce flux.
    fn ce_qu_on_a_dit(&self, flux: u64) -> &[u8] {
        self.sortant.get(&flux).map_or(&[][..], Vec::as_slice)
    }
}

impl Transport for Faux {
    fn open_uni(&mut self) -> Result<StreamId, Error> {
        if self.prochain >= self.plafond {
            return Err(Error::transport());
        }
        let flux = StreamId::from_index(
            self.prochain,
            Initiator::Server,
            Directional::Unidirectional,
        )
        .expect("un rang qui tient");
        self.prochain = self.prochain.saturating_add(1);
        Ok(flux)
    }

    fn read(&mut self, flux: StreamId, vers: &mut [u8]) -> usize {
        let Some(file) = self.entrant.get_mut(&flux.value()) else {
            return 0;
        };
        let combien = file.len().min(vers.len());
        vers.get_mut(..combien)
            .expect("la borne vient d'être prise")
            .copy_from_slice(file.get(..combien).expect("de même"));
        file.drain(..combien);
        combien
    }

    fn write(&mut self, flux: StreamId, octets: &[u8]) -> Result<usize, Error> {
        if self
            .refuse_a_partir_de
            .is_some_and(|rang| self.ecritures >= rang)
        {
            return Err(Error::transport());
        }
        self.ecritures = self.ecritures.saturating_add(1);
        self.sortant
            .entry(flux.value())
            .or_default()
            .extend_from_slice(octets);
        Ok(octets.len())
    }

    fn reset(&mut self, flux: StreamId, code: u64) -> Result<(), Error> {
        if self
            .refuse_a_partir_de
            .is_some_and(|rang| self.ecritures >= rang)
        {
            return Err(Error::transport());
        }
        self.annules.push((flux.value(), code));
        Ok(())
    }

    fn finish(&mut self, _flux: StreamId) -> Result<(), Error> {
        Ok(())
    }

    fn recv_state(&self, flux: StreamId) -> Option<RecvState> {
        self.etats.get(&flux.value()).copied()
    }
}

/// Un service d'essai : il redit ce qu'on lui a envoyé.
#[derive(Debug, Default)]
struct Echo {
    /// Ce qu'il a servi : la cible, puis le corps.
    servi: std::vec::Vec<(std::vec::Vec<u8>, std::vec::Vec<u8>)>,
    /// Ajoute-t-il un champ que §4.2 interdit ?
    champ_interdit: bool,
}

impl super::Service for Echo {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> super::Reponse<'o> {
        self.servi.push((tete.path().to_vec(), corps.to_vec()));
        let combien = corps.len().min(sortie.len());
        sortie
            .get_mut(..combien)
            .expect("la borne vient d'être prise")
            .copy_from_slice(corps.get(..combien).expect("de même"));
        let reponse = super::Reponse::new(ams_proto_http::StatusCode::OK, &sortie[..combien])
            .avec_champ(b"content-type", b"text/plain");
        match self.champ_interdit {
            // §4.2 : les champs propres à la connexion n'existent pas en
            // HTTP/3, et en écrire un ferait douter un client de tout le reste.
            true => reponse.avec_champ(b"connection", b"keep-alive"),
            false => reponse,
        }
    }
}

/// Le numéro d'un flux unidirectionnel du client.
fn du_client(rang: u64) -> StreamId {
    StreamId::from_index(rang, Initiator::Client, Directional::Unidirectional)
        .expect("un rang qui tient")
}

/// Un flux de contrôle du client, avec ses réglages.
fn controle_du_client(faux: &mut Faux, rang: u64) -> StreamId {
    let flux = du_client(rang);
    let mut octets = Vec::new();
    let mut tampon = [0_u8; 32];
    let ecrits = varints::encode(StreamKind::Control.value(), &mut tampon).expect("écrivable");
    octets.extend_from_slice(&tampon[..ecrits]);

    let mut charge = [0_u8; 64];
    let combien = Settings::DEFAULT.write(&mut charge).expect("écrivables");
    let ecrits = write_header(
        FrameKind::Settings,
        u64::try_from(combien).expect("tient"),
        &mut tampon,
    )
    .expect("écrivable");
    octets.extend_from_slice(&tampon[..ecrits]);
    octets.extend_from_slice(&charge[..combien]);

    faux.le_pair_dit(flux.value(), &octets);
    flux
}

/// **§6.2.1 EXIGE UN FLUX DE CONTRÔLE, ET `SETTINGS` EN PREMIER.**
///
/// « Each side MUST initiate a single control stream at the beginning of the
/// connection and send its SETTINGS frame as the first frame on this stream. »
/// Un client qui ne recevrait pas nos réglages devrait supposer les valeurs par
/// défaut, et refuserait des réponses que nous jugeons acceptables.
#[test]
fn on_ouvre_un_flux_de_controle_et_l_on_y_dit_ses_reglages() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let controle = h3.control_stream().expect("il est ouvert");
    assert_eq!(
        controle.directional(),
        Directional::Unidirectional,
        "§6.2 : un flux de contrôle est unidirectionnel"
    );
    let dit = faux.ce_qu_on_a_dit(controle.value());
    assert_eq!(
        dit.first(),
        Some(&0x00),
        "§6.2 : le type du flux vient en tête, et `Control` vaut zéro"
    );
    assert_eq!(
        dit.get(1),
        Some(&0x04),
        "§6.2.1 : et `SETTINGS` est la première trame"
    );

    // **UNE FOIS, ET UNE SEULE** : le rouvrir épuiserait le plafond de §4.6.
    h3.on_established(&mut faux)
        .expect("le redire ne fait rien");
    assert_eq!(h3.control_stream(), Some(controle));
}

/// **ON N'OUVRE PAS CE QU'ON NE PEUT PAS OUVRIR.**
///
/// Un pair qui n'aurait ouvert aucun flux unidirectionnel nous laisserait sans
/// flux de contrôle. Le taire ferait croire la connexion prête.
#[test]
fn on_n_ouvre_pas_ce_qu_on_ne_peut_pas_ouvrir() {
    let mut faux = Faux::new();
    faux.plafond = 0;
    let mut h3 = Http3::new();
    assert!(h3.on_established(&mut faux).is_err());
    assert_eq!(h3.control_stream(), None);
}

/// **LES RÉGLAGES DU PAIR SE LISENT** (§7.2.4).
#[test]
fn les_reglages_du_pair_se_lisent() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = controle_du_client(&mut faux, 0);

    assert_eq!(h3.peer_settings(), None, "rien n'est encore lu");
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("ses réglages passent");
    assert_eq!(
        h3.peer_settings(),
        Some(Settings::DEFAULT),
        "§7.2.4 : et les voilà"
    );
}

/// **UN TYPE DE FLUX INCONNU N'EST PAS UNE FAUTE DE CONNEXION** (§6.2).
///
/// « The recipient MUST NOT consider unknown stream types to be a connection
/// error of any kind. » Le refuser casserait les pairs qui emploient une
/// extension qu'on ne connaît pas — et c'est exactement ce que §9 sert à
/// permettre.
#[test]
fn un_type_de_flux_inconnu_n_est_pas_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = du_client(0);
    let mut tampon = [0_u8; 32];
    // 0x21 : un type que §6.2 n'attribue pas.
    let ecrits = varints::encode(0x21, &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);
    faux.le_pair_dit(flux.value(), b"n'importe quoi, et beaucoup");

    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("§6.2 : on abandonne CE flux, et rien d'autre");

    // **ET L'ON CONSOMME CE QU'IL DIT** : les octets non lus ne rouvriraient
    // jamais la fenêtre du flux, et le pair finirait bloqué sans comprendre.
    assert!(
        faux.entrant.get(&flux.value()).is_none_or(Vec::is_empty),
        "ce qu'on abandonne, on le consomme"
    );
}

/// **UN FLUX DE POUSSÉE VENANT D'UN CLIENT EST UNE FAUTE** (§6.2.2).
///
/// C'est un serveur qui les ouvre. En recevoir un veut dire que le client se
/// prend pour nous, et rien de ce qui suivrait n'aurait le sens qu'on lui
/// prêterait.
#[test]
fn un_flux_de_poussee_venant_d_un_client_est_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = du_client(0);
    let mut tampon = [0_u8; 32];
    let ecrits = varints::encode(StreamKind::Push.value(), &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);

    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("§6.2.2 la refuse");
    // §8.1 : `H3_ID_ERROR` — « a stream ID or push ID was used incorrectly ».
    // C'est bien l'emploi du flux qui est faux, et non sa création.
    assert_eq!(faute.close_code(), ams_proto_h3::H3Error::IdError.value());
}

/// **UN SECOND FLUX DE CONTRÔLE EST UNE FAUTE** (§6.2.1).
#[test]
fn un_second_flux_de_controle_est_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let premier = controle_du_client(&mut faux, 0);
    h3.on_readable(&mut faux, &mut Echo::default(), premier)
        .expect("le premier passe");

    let second = controle_du_client(&mut faux, 1);
    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), second)
        .expect_err("§6.2.1 refuse le second");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::StreamCreationError.value()
    );
}

/// **LE FLUX DE CONTRÔLE COMMENCE PAR `SETTINGS`, ET RIEN D'AUTRE** (§6.2.1).
///
/// « If the first frame of the control stream is any other frame type, this MUST
/// be treated as a connection error of type H3_MISSING_SETTINGS. »
#[test]
fn le_flux_de_controle_commence_par_ses_reglages() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = du_client(0);
    let mut tampon = [0_u8; 32];
    let ecrits = varints::encode(StreamKind::Control.value(), &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);
    // Un `GOAWAY` en premier : §7.2 l'admet sur ce flux, §6.2.1 non.
    let ecrits = write_header(FrameKind::GoAway, 1, &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);
    faux.le_pair_dit(flux.value(), &[0x00]);

    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("§6.2.1 la refuse");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::MissingSettings.value(),
        "**LE CODE COMPTE** : lui dire « trame inattendue » l'enverrait chercher \
         au mauvais endroit"
    );
}

/// **UNE TRAME QUI N'A PAS SA PLACE SUR LE CONTRÔLE EST UNE FAUTE** (§7.2).
#[test]
fn une_trame_hors_de_sa_place_est_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = controle_du_client(&mut faux, 0);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("ses réglages passent");

    // Un `DATA` sur le flux de contrôle : §7.2.1 ne l'admet pas.
    let mut tampon = [0_u8; 32];
    let ecrits = write_header(FrameKind::Data, 0, &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);

    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("§7.2 la refuse");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::FrameUnexpected.value()
    );
}

/// **UNE TRAME INCONNUE SE SAUTE, SANS SE RETENIR** (§9).
///
/// « Implementations MUST ignore unknown or unsupported values in all
/// extensible protocol elements. » Et la sauter sans la mettre en tampon est ce
/// qui empêche le pair de choisir combien nous retenons.
#[test]
fn une_trame_inconnue_se_saute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = controle_du_client(&mut faux, 0);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("ses réglages passent");

    // Un type inconnu, avec une charge bien plus grande que notre tampon.
    let mut tampon = [0_u8; 32];
    let ecrits = write_header(FrameKind::Unknown(0x21), 500, &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);
    faux.le_pair_dit(flux.value(), &std::vec![0x5a_u8; 500]);
    // Puis un `GOAWAY`, pour montrer qu'on a bien retrouvé la suite.
    let ecrits = write_header(FrameKind::GoAway, 1, &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);
    faux.le_pair_dit(flux.value(), &[0x04]);

    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("§9 : on saute, et l'on reprend");
    assert!(
        faux.entrant.get(&flux.value()).is_none_or(Vec::is_empty),
        "tout a été consommé"
    );
}

/// **UNE TRAME COUPÉE EN DEUX N'EST PAS UNE FAUTE.**
///
/// Un flux QUIC livre par morceaux, et un en-tête peut s'étaler sur deux
/// datagrammes. Refuser ici serait refuser un pair qui n'a rien fait de mal.
#[test]
fn une_trame_coupee_en_deux_n_est_pas_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = du_client(0);
    // Le type du flux, un octet à la fois.
    faux.le_pair_dit(flux.value(), &[0x00]);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("un octet, et l'on attend");
    assert_eq!(h3.peer_settings(), None);

    // Puis l'en-tête de `SETTINGS`, coupé avant sa charge.
    let mut charge = [0_u8; 64];
    let combien = Settings::DEFAULT.write(&mut charge).expect("écrivables");
    let mut tampon = [0_u8; 32];
    let ecrits = write_header(
        FrameKind::Settings,
        u64::try_from(combien).expect("tient"),
        &mut tampon,
    )
    .expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("l'en-tête seul attend");
    assert_eq!(h3.peer_settings(), None, "la charge n'est pas là");

    faux.le_pair_dit(flux.value(), &charge[..combien]);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("et voilà la charge");
    assert_eq!(h3.peer_settings(), Some(Settings::DEFAULT));
}

/// **UN FLUX CRITIQUE QUI SE FERME EST UNE FAUTE** (§6.2.1).
///
/// §6.2.1 n'a pas de cas où c'est acceptable : le flux de contrôle vit aussi
/// longtemps que la connexion, et sa fermeture veut dire que le pair a renoncé
/// sans le dire.
#[test]
fn un_flux_critique_qui_se_ferme_est_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = controle_du_client(&mut faux, 0);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("ses réglages passent");

    faux.etats.insert(flux.value(), RecvState::DataRecvd);
    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("§6.2.1 la refuse");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::ClosedCriticalStream.value()
    );
}

/// **NOS PROPRES FLUX NE SE LISENT PAS**, ni les bidirectionnels — pas encore.
#[test]
fn nos_propres_flux_ne_se_lisent_pas() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let notre = h3.control_stream().expect("il est ouvert");

    h3.on_readable(&mut faux, &mut Echo::default(), notre)
        .expect("rien à y lire");
    let requete = StreamId::new(0).expect("un bidirectionnel du client");
    h3.on_readable(&mut faux, &mut Echo::default(), requete)
        .expect("les requêtes viendront ensuite");
}

/// **UNE CHARGE DE CONTRÔLE DÉMESURÉE EST MAL FORMÉE** (§7.2).
///
/// Les trames qu'on lit sont courtes par construction : des réglages, ou un seul
/// entier de §16. Une qui dépasse donnerait au pair le moyen de choisir combien
/// nous retenons.
#[test]
fn une_charge_de_controle_demesuree_est_mal_formee() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = controle_du_client(&mut faux, 0);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("ses réglages passent");

    let mut tampon = [0_u8; 32];
    let ecrits = write_header(FrameKind::GoAway, 10_000, &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);

    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("elle est refusée");
    assert_eq!(faute.reason(), Reason::Malformee);
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::FrameError.value()
    );
}

/// Un flux QPACK du client, dont on a lu la tête.
fn qpack_du_client(faux: &mut Faux, rang: u64, genre: StreamKind) -> StreamId {
    let flux = du_client(rang);
    let mut tampon = [0_u8; 32];
    let ecrits = varints::encode(genre.value(), &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);
    flux
}

/// Ce que le pair a dit et qu'on n'a pas encore consommé.
fn reste_a_lire(faux: &Faux, flux: StreamId) -> usize {
    faux.entrant.get(&flux.value()).map_or(0, Vec::len)
}

/// **§4.2 DE RFC 9204 : NOS DEUX FLUX QPACK S'OUVRENT, ET NE DISENT QUE LEUR
/// TYPE.**
///
/// « Each endpoint MUST initiate, at most, one encoder stream and, at most, one
/// decoder stream. » *At most*, donc les ouvrir n'est pas dû — mais un flux
/// absent et un flux muet ne se distinguent pas d'un flux qui tarde, et un pair
/// qui attend ceux de son vis-à-vis attendrait pour rien.
///
/// Ils ne portent rien d'autre : notre encodeur n'insère jamais (§3.2.3), et
/// notre décodeur n'a aucun accusé à rendre (§4.4.1).
#[test]
fn on_ouvre_aussi_les_deux_flux_qpack() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let encodeur = h3.qpack_encoder_stream().expect("il est ouvert");
    let decodeur = h3.qpack_decoder_stream().expect("il est ouvert");
    let controle = h3.control_stream().expect("il est ouvert");
    assert_ne!(encodeur, decodeur, "§4.2 : deux flux, et non un");
    assert_ne!(
        encodeur, controle,
        "et ni l'un ni l'autre n'est le contrôle"
    );

    for (flux, genre) in [
        (encodeur, StreamKind::QpackEncoder),
        (decodeur, StreamKind::QpackDecoder),
    ] {
        assert_eq!(
            flux.directional(),
            Directional::Unidirectional,
            "§4.2 : un flux QPACK est unidirectionnel"
        );
        assert_eq!(
            faux.ce_qu_on_a_dit(flux.value()),
            &[u8::try_from(genre.value()).expect("un type qui tient sur un octet")],
            "SON TYPE, ET RIEN D'AUTRE"
        );
    }
}

/// **TROIS FLUX DEMANDENT TROIS CRÉDITS**, et un pair qui n'en donne pas assez
/// ne verra pas la connexion s'ouvrir.
///
/// §6.2 de RFC 9114 demande justement d'en donner assez pour ces trois-là. On le
/// dit par [`Reason::Transport`] plutôt que de servir à moitié.
#[test]
fn sans_credit_pour_trois_flux_on_ne_s_ouvre_pas() {
    // Un crédit : le contrôle passe, l'encodeur non. Deux : le décodeur non.
    for plafond in [1, 2] {
        let mut faux = Faux::new();
        faux.plafond = plafond;
        let mut h3 = Http3::new();
        let faute = h3.on_established(&mut faux).expect_err("il en manque un");
        assert!(matches!(faute.reason(), Reason::Transport), "{plafond}");
    }
}

/// **§3.2.3 : UNE INSERTION EST REFUSÉE SUR SON SEUL PREMIER OCTET.**
///
/// « When the maximum table capacity is zero, the encoder MUST NOT insert
/// entries into the dynamic table [...] » Nous annonçons zéro.
///
/// **ET L'ON N'EN LIT PAS LA CHARGE** : c'est ce que montre l'octet unique. §4.3.3
/// ne borne ni le nom ni la valeur d'une insertion ; attendre de les avoir pour
/// refuser donnerait au pair le moyen de choisir combien nous retenons (C3).
#[test]
fn une_insertion_est_refusee_sans_lire_sa_charge() {
    // §4.3.2 `1Txxxxxx`, §4.3.3 `01Hxxxxx`, §4.3.4 `000xxxxx` : les trois types
    // qui insèrent, et rien de plus qu'un octet pour chacun.
    for premier in [0b1100_0001_u8, 0b0100_0001, 0b0000_0001] {
        let mut faux = Faux::new();
        let mut h3 = Http3::new();
        h3.on_established(&mut faux).expect("on peut ouvrir");
        let flux = qpack_du_client(&mut faux, 0, StreamKind::QpackEncoder);
        faux.le_pair_dit(flux.value(), &[premier]);

        let faute = h3
            .on_readable(&mut faux, &mut Echo::default(), flux)
            .expect_err("§3.2.3 refuse toute insertion");
        assert!(matches!(
            faute.reason(),
            Reason::H3(ams_proto_h3::Reason::DynamicTableRefused)
        ));
        assert_eq!(
            faute.close_code(),
            ams_proto_h3::H3Error::QpackEncoderStreamError.value(),
            "§6 nomme un code PAR FLUX : le pair doit savoir lequel a fauté"
        );
    }
}

/// **UNE CAPACITÉ NULLE PASSE, UNE CAPACITÉ NON NULLE NON** (§4.3.1, §3.2.3).
///
/// §3.2.3 demande à la lettre de n'envoyer aucune instruction quand la table est
/// nulle. Celle-ci ne demande pourtant rien qu'on refuse — et fermer la connexion
/// d'un pair qui annonce renoncer à la table serait le punir de nous avoir obéi.
#[test]
fn une_capacite_se_juge_sur_sa_valeur() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = qpack_du_client(&mut faux, 0, StreamKind::QpackEncoder);
    // §4.3.1 : `001xxxxx`, préfixe de cinq bits, valeur nulle.
    faux.le_pair_dit(flux.value(), &[0b0010_0000]);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("une table nulle est celle qu'on a annoncée");
    assert_eq!(reste_a_lire(&faux, flux), 0, "et elle a été consommée");

    // Soixante-quatre : au-delà des trente et un du préfixe, donc deux octets.
    faux.le_pair_dit(flux.value(), &[0b0011_1111, 0x21]);
    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("§3.2.3 borne la capacité par ce qu'on a annoncé");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::QpackEncoderStreamError.value()
    );
}

/// **UNE INSTRUCTION D'ENCODEUR À CHEVAL ATTEND SA SUITE**, elle aussi.
///
/// Une capacité nulle tient sur un octet ; toute autre déborde le préfixe de cinq
/// bits de §4.3.1 et s'étale. Celle-ci sera donc refusée une fois entière — mais
/// pas avant d'être entière : refuser sur un tampon incomplet serait refuser un
/// pair qui n'a rien fait de mal.
#[test]
fn une_instruction_d_encodeur_coupee_en_deux_se_recolle() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = qpack_du_client(&mut faux, 0, StreamKind::QpackEncoder);

    faux.le_pair_dit(flux.value(), &[0b0011_1111]);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("il en manque, et c'est tout");

    faux.le_pair_dit(flux.value(), &[0x00]);
    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("trente et un dépassent le zéro qu'on annonce");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::QpackEncoderStreamError.value()
    );
}

/// **ET UNE CAPACITÉ NULLE REDITE SANS FIN EST UNE CHARGE EXCESSIVE.**
///
/// Elle est licite, et ne change rien : c'est exactement ce que le compteur de
/// service existe pour voir. Le flux d'encodeur est critique au sens de §4.2, donc
/// rien d'autre ne le borne.
#[test]
fn des_capacites_nulles_sans_fin_sont_une_charge_excessive() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = qpack_du_client(&mut faux, 0, StreamKind::QpackEncoder);
    let combien = usize::try_from(ams_proto_h3::SERVICE_FRAMES_MAX).expect("tient") + 1;
    faux.le_pair_dit(flux.value(), &vec![0b0010_0000; combien]);

    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("le pair n'envoie plus que ce qui n'avance rien");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::ExcessiveLoad.value()
    );
}

/// **§4.4.1 ET §4.4.3 : ACCUSER CE QU'ON N'A PAS ENVOYÉ EST UNE FAUTE.**
///
/// Notre encodeur n'insère rien : aucune section que nous émettons ne déclare un
/// compte d'insertions non nul. Tout accusé de section, et tout incrément, porte
/// donc sur ce qui n'existe pas — et un pair qui compte autrement que nous ne
/// tient plus la même table.
#[test]
fn un_accuse_qui_ne_porte_sur_rien_est_une_faute() {
    // §4.4.1 `1xxxxxxx` sur le flux 0 ; §4.4.3 `00xxxxxx` d'incrément nul, puis
    // d'incrément non nul — les deux que §4.4.3 nomme.
    for octet in [0b1000_0000_u8, 0b0000_0000, 0b0000_0001] {
        let mut faux = Faux::new();
        let mut h3 = Http3::new();
        h3.on_established(&mut faux).expect("on peut ouvrir");
        let flux = qpack_du_client(&mut faux, 0, StreamKind::QpackDecoder);
        faux.le_pair_dit(flux.value(), &[octet]);

        let faute = h3
            .on_readable(&mut faux, &mut Echo::default(), flux)
            .expect_err("il n'y a rien à accuser");
        assert!(matches!(
            faute.reason(),
            Reason::H3(ams_proto_h3::Reason::UnexpectedDecoderInstruction)
        ));
        assert_eq!(
            faute.close_code(),
            ams_proto_h3::H3Error::QpackDecoderStreamError.value()
        );
    }
}

/// **§4.4.2 N'A PAS DE CONDITION D'ERREUR**, et une annulation de flux passe.
///
/// Elle dit qu'on peut relâcher ce qu'une section référençait. Sans table, il n'y
/// a rien à relâcher — et rien à refuser non plus : un pair qui abandonne un flux
/// n'a rien fait de mal.
#[test]
fn une_annulation_de_flux_ne_fait_rien_et_passe() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = qpack_du_client(&mut faux, 0, StreamKind::QpackDecoder);
    // §4.4.2 : `01xxxxxx`, le flux 4.
    faux.le_pair_dit(flux.value(), &[0b0100_0100]);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("§4.4.2 ne nomme aucune faute");
    assert_eq!(reste_a_lire(&faux, flux), 0, "et elle a été consommée");
}

/// **UNE INSTRUCTION À CHEVAL ATTEND SA SUITE**, et ce n'est pas une faute.
///
/// Un entier à préfixe s'étale sur plusieurs octets, et un flux QUIC les livre
/// par morceaux. Refuser ici serait refuser un pair qui n'a rien fait de mal.
#[test]
fn une_instruction_de_decodeur_coupee_en_deux_se_recolle() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = qpack_du_client(&mut faux, 0, StreamKind::QpackDecoder);
    // §4.4.2, le flux 64 : le préfixe de six bits déborde, et la suite est là.
    faux.le_pair_dit(flux.value(), &[0b0111_1111]);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("il en manque, et c'est tout");

    faux.le_pair_dit(flux.value(), &[0x01]);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("la voilà entière");
    assert_eq!(reste_a_lire(&faux, flux), 0, "et elle a été consommée");
}

/// **UN ENTIER QUI NE SE RECONSTRUIRA JAMAIS NE FIGE PAS LE FLUX.**
///
/// La lecture rend la même chose — « il en manque » — pour un tampon incomplet et
/// pour un entier qui déborde ce que la représentation porte. Sans la borne de
/// §4.4, on attendrait pour toujours une suite qui ne vient pas : un flux figé,
/// sans erreur et sans trace. C'est le défaut qu'avait eu le tampon de contrôle.
#[test]
fn un_entier_sans_fin_est_refuse_plutot_que_d_attendre() {
    for (genre, code) in [
        (
            StreamKind::QpackDecoder,
            ams_proto_h3::H3Error::QpackDecoderStreamError,
        ),
        (
            StreamKind::QpackEncoder,
            ams_proto_h3::H3Error::QpackEncoderStreamError,
        ),
    ] {
        let mut faux = Faux::new();
        let mut h3 = Http3::new();
        h3.on_established(&mut faux).expect("on peut ouvrir");
        let flux = qpack_du_client(&mut faux, 0, genre);
        // Un préfixe plein, puis six octets de continuation : le multiplicateur
        // déborde avant qu'un octet final n'arrive.
        faux.le_pair_dit(flux.value(), &[0b0011_1111, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let faute = h3
            .on_readable(&mut faux, &mut Echo::default(), flux)
            .expect_err("cet entier-là n'aboutira pas");
        assert_eq!(faute.close_code(), code.value());
    }
}

/// **UN PAIR QUI N'ANNULE QUE DES FLUX FINIT PAR EN FAIRE TROP.**
///
/// §4.2 fait des flux QPACK des flux critiques : comme le flux de contrôle, ils
/// doivent avoir de quoi ne jamais bloquer, et rien ne borne donc ce qu'on y
/// reçoit. Une annulation de §4.4.2 est licite et ne fait rien avancer — c'est le
/// même travail gratuit que *Rapid Reset*, par une autre porte.
#[test]
fn des_annulations_sans_fin_sont_une_charge_excessive() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = qpack_du_client(&mut faux, 0, StreamKind::QpackDecoder);
    let combien = usize::try_from(ams_proto_h3::SERVICE_FRAMES_MAX).expect("tient") + 1;
    faux.le_pair_dit(flux.value(), &vec![0b0100_0000; combien]);

    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("le pair n'envoie plus que ce qui n'avance rien");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::ExcessiveLoad.value()
    );
}

/// **UN FLUX SANS RIEN À DIRE N'AVANCE PAS**, et ce n'est pas une faute.
#[test]
fn un_flux_sans_rien_a_dire_n_avance_pas() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    // Le flux existe pour l'appelant, et rien n'est encore arrivé.
    h3.on_readable(&mut faux, &mut Echo::default(), du_client(0))
        .expect("il n'y a rien à lire, et rien à en conclure");
}

/// **UN TYPE DE TRAME RÉSERVÉ PAR §11.2.1 EST UNE FAUTE.**
///
/// Ces types-là existent pour qu'un pair qui croirait parler HTTP/2 se fasse
/// refuser tout de suite, plutôt que de tomber sur une trame qu'on aurait lue de
/// travers.
#[test]
fn un_type_de_trame_reserve_est_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = controle_du_client(&mut faux, 0);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("ses réglages passent");

    // 0x02 : `PRIORITY` d'HTTP/2, que §11.2.1 réserve.
    faux.le_pair_dit(flux.value(), &[0x02, 0x00]);
    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("§11.2.1 la refuse");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::FrameUnexpected.value()
    );
}

/// **LE CONDUCTEUR PAR DÉFAUT EST UN CONDUCTEUR NEUF.**
#[test]
fn le_conducteur_par_defaut_est_neuf() {
    let h3 = Http3::default();
    assert_eq!(h3.control_stream(), None);
    assert_eq!(h3.peer_settings(), None);
}

/// **CE QU'ON NE PEUT PAS ÉCRIRE NE SE TAIT PAS.**
///
/// Un transport qui refuse notre flux de contrôle laisserait la connexion sans
/// réglages ; le dire est ce qui permet à l'appelant de fermer proprement.
#[test]
fn ce_qu_on_ne_peut_pas_ecrire_ne_se_tait_pas() {
    let mut faux = Faux::new();
    faux.refuse_a_partir_de = Some(0);
    let mut h3 = Http3::new();
    let faute = h3.on_established(&mut faux).expect_err("il refuse");
    assert_eq!(faute.reason(), Reason::Transport);
    assert_eq!(h3.control_stream(), None, "et rien n'est retenu à moitié");

    // **ET UN FLUX QPACK QU'ON N'ÉCRIT PAS NE SE TAIT PAS DAVANTAGE** : le
    // contrôle passe, le suivant non. Servir avec un flux QPACK que le pair n'a
    // jamais vu s'ouvrir serait lui laisser attendre ce qui ne viendra pas.
    let mut faux = Faux::new();
    faux.refuse_a_partir_de = Some(1);
    let mut h3 = Http3::new();
    let faute = h3
        .on_established(&mut faux)
        .expect_err("il refuse le second");
    assert_eq!(faute.reason(), Reason::Transport);
    assert_eq!(
        h3.qpack_encoder_stream(),
        None,
        "rien n'est retenu à moitié"
    );
}

/// **UNE TRAME DE CONTRÔLE AUSSI GRANDE QU'ON L'ACCEPTE PASSE** (§7.2).
///
/// # C'EST L'ESSAI QUI MANQUAIT, ET QUI CACHAIT UN DÉFAUT
///
/// Le tampon d'un flux valait la taille de la charge seule : un `SETTINGS` de
/// cette taille exacte le remplissait sans jamais tenir son en-tête, et le flux
/// de contrôle se figeait pour toujours. Sans erreur, sans trace, et sans que le
/// pair ait rien fait de mal.
#[test]
fn une_trame_de_controle_aussi_grande_qu_on_l_accepte_passe() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = du_client(0);
    let mut tampon = [0_u8; 32];
    let ecrits = varints::encode(StreamKind::Control.value(), &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);

    // Des réglages complétés par des identifiants inconnus, jusqu'à la borne.
    // §7.2.4 : « An implementation MUST ignore any parameter with an identifier
    // it does not understand. »
    let mut charge = std::vec::Vec::new();
    let mut morceau = [0_u8; 16];
    let mut prochain = 0x21_u64;
    while charge.len() + 4 <= super::CHARGE_OCTETS_MAX {
        for valeur in [prochain, 0] {
            let mis = varints::encode(valeur, &mut morceau).expect("écrivable");
            charge.extend_from_slice(&morceau[..mis]);
        }
        prochain = prochain.saturating_add(1);
    }
    assert!(
        charge.len() > super::CHARGE_OCTETS_MAX - 4,
        "on frôle la borne"
    );

    let ecrits = write_header(
        FrameKind::Settings,
        u64::try_from(charge.len()).expect("tient"),
        &mut tampon,
    )
    .expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);
    faux.le_pair_dit(flux.value(), &charge);

    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("une trame à la borne passe");
    assert!(
        h3.peer_settings().is_some(),
        "ET SES RÉGLAGES SONT LUS : le flux ne s'est pas figé"
    );
}

/// **UN RÉGLAGE RÉSERVÉ PAR HTTP/2 EST UNE FAUTE** (§11.2.2).
///
/// Ces identifiants existent pour qu'un pair qui croirait parler HTTP/2 se fasse
/// refuser tout de suite, plutôt que de voir ses réglages lus de travers.
#[test]
fn un_reglage_reserve_par_http2_est_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = du_client(0);
    let mut tampon = [0_u8; 32];
    let ecrits = varints::encode(StreamKind::Control.value(), &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);
    let ecrits = write_header(FrameKind::Settings, 2, &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);
    // §11.2.2 réserve 0x02 pour écarter un pair qui croirait parler HTTP/2 :
    // « Setting identifiers … MUST NOT be sent, and their receipt MUST be
    // treated as a connection error of type H3_SETTINGS_ERROR. »
    faux.le_pair_dit(flux.value(), &[0x02, 0x00]);

    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("§7.2.4 la refuse");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::SettingsError.value()
    );
}

/// **UN `GOAWAY` SANS IDENTIFIANT EST MAL FORMÉ** (§7.2.6).
///
/// « The GOAWAY frame carries a QUIC stream ID. » Sans lui, on ne saurait pas
/// jusqu'où le pair promet d'avoir servi.
#[test]
fn un_goaway_sans_identifiant_est_mal_forme() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let flux = controle_du_client(&mut faux, 0);
    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("ses réglages passent");

    let mut tampon = [0_u8; 32];
    let ecrits = write_header(FrameKind::GoAway, 0, &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);

    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("elle est refusée");
    assert_eq!(faute.reason(), Reason::Malformee);
}

/// **UN ENTIER DE §16 PEUT S'ÉCRIRE PLUS LONG QU'IL NE FAUT.**
///
/// §16 de RFC 9000 n'impose pas la forme la plus courte : un pair a le droit
/// d'écrire `4` sur huit octets. Le refuser serait refuser un pair conforme —
/// et c'est ce cas qui remplit le tampon jusqu'à sa dernière place, là où une
/// borne trop juste se verrait.
#[test]
fn un_entier_de_seize_peut_s_ecrire_plus_long_qu_il_ne_faut() {
    /// Cet entier, écrit sur huit octets plutôt que sur le minimum.
    fn en_huit_octets(valeur: u64) -> [u8; 8] {
        let mut octets = valeur.to_be_bytes();
        // §16 : les deux bits de tête donnent la longueur, et `11` vaut huit.
        octets[0] |= 0xc0;
        octets
    }

    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = du_client(0);
    let mut tampon = [0_u8; 32];
    let ecrits = varints::encode(StreamKind::Control.value(), &mut tampon).expect("écrivable");
    faux.le_pair_dit(flux.value(), &tampon[..ecrits]);

    // Un en-tête de seize octets, et une charge à la borne : le tampon se
    // remplit exactement.
    let charge = std::vec![0_u8; super::CHARGE_OCTETS_MAX];
    faux.le_pair_dit(flux.value(), &en_huit_octets(FrameKind::Settings.value()));
    faux.le_pair_dit(
        flux.value(),
        &en_huit_octets(u64::try_from(charge.len()).expect("tient")),
    );
    faux.le_pair_dit(flux.value(), &charge);

    h3.on_readable(&mut faux, &mut Echo::default(), flux)
        .expect("des réglages de zéros s'ignorent (§7.2.4)");
    assert!(
        h3.peer_settings().is_some(),
        "LE TAMPON ÉTAIT PLEIN, et le flux n'a pas figé"
    );
}

/// Compose une section de champs de requête, avec la table statique de QPACK.
///
/// **À LA MAIN, ET NON PAR NOTRE ENCODEUR** : un essai qui bâtirait ses requêtes
/// avec notre propre écriture ne prouverait rien du fil — si l'ordre des champs
/// était faux DES DEUX CÔTÉS, il passerait quand même. §4.5.1 de RFC 9204 pose
/// le préfixe, et §4.5.2 les lignes indexées.
fn une_requete(chemin: &[u8]) -> std::vec::Vec<u8> {
    let mut section = std::vec::Vec::new();
    // §4.5.1 : deux octets nuls — aucune insertion requise, aucune base.
    section.extend_from_slice(&[0x00, 0x00]);
    // §4.5.2 : `1Tiiiiii` avec T=1 pour la table statique.
    // Annexe A de RFC 9204 : 17 vaut `:method: GET`, et 23 `:scheme: https`.
    // **PAS 22** : celui-là vaut `:scheme: http`, que ce serveur refuse (C4).
    for index in [17_u8, 23] {
        section.push(0xc0 | index);
    }
    // §4.5.4 : `01NTiiii` — un nom indexé, une valeur littérale.
    // 0 : `:authority`. 1 : `:path`.
    for (index, valeur) in [(0_u8, &b"exemple.test"[..]), (1, chemin)] {
        section.push(0x50 | index);
        // §4.1.2 : la longueur sur sept bits, sans codage de Huffman.
        section.push(u8::try_from(valeur.len()).expect("court"));
        section.extend_from_slice(valeur);
    }
    section
}

/// Le flux bidirectionnel de rang `rang`, ouvert par le client.
fn requete_du_client(rang: u64) -> StreamId {
    StreamId::from_index(rang, Initiator::Client, Directional::Bidirectional)
        .expect("un rang qui tient")
}

/// Pose une requête entière sur ce flux : les en-têtes, puis le corps.
fn poser_une_requete(faux: &mut Faux, flux: StreamId, chemin: &[u8], corps: &[u8]) {
    let section = une_requete(chemin);
    let mut entete = [0_u8; 16];
    let pose = write_header(
        FrameKind::Headers,
        u64::try_from(section.len()).expect("tient"),
        &mut entete,
    )
    .expect("écrivable");
    faux.le_pair_dit(flux.value(), &entete[..pose]);
    faux.le_pair_dit(flux.value(), &section);

    if !corps.is_empty() {
        let pose = write_header(
            FrameKind::Data,
            u64::try_from(corps.len()).expect("tient"),
            &mut entete,
        )
        .expect("écrivable");
        faux.le_pair_dit(flux.value(), &entete[..pose]);
        faux.le_pair_dit(flux.value(), corps);
    }
    // Le client a fini d'écrire (§4.1).
    faux.etats.insert(flux.value(), RecvState::DataRecvd);
}

/// **UNE REQUÊTE FAIT L'ALLER-RETOUR** (§4.1).
///
/// C'est ce que toute la pile sert à rendre possible : des champs comprimés
/// arrivent, une application décide, et une réponse repart comprimée.
#[test]
fn une_requete_fait_l_aller_retour() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    poser_une_requete(&mut faux, flux, b"/boites", b"une question");
    h3.on_readable(&mut faux, &mut echo, flux)
        .expect("la requête passe");

    assert_eq!(
        echo.servi,
        std::vec![(b"/boites".to_vec(), b"une question".to_vec())],
        "LE SERVICE A VU LA REQUÊTE ENTIÈRE, cible et corps"
    );

    // Et la réponse est partie : une section de champs, puis le corps.
    let dit = faux.ce_qu_on_a_dit(flux.value());
    let entete = ams_proto_h3::FrameHeader::parse(dit).expect("une trame");
    assert_eq!(
        entete.kind(),
        FrameKind::Headers,
        "§4.1 : les en-têtes d'abord"
    );
    let apres = usize::try_from(entete.total()).expect("tient");
    let suite = ams_proto_h3::FrameHeader::parse(&dit[apres..]).expect("une seconde trame");
    assert_eq!(suite.kind(), FrameKind::Data, "puis le corps");
    assert_eq!(
        &dit[apres + suite.header_len()..],
        b"une question",
        "et c'est bien ce que le service a rendu"
    );
}

/// **ON NE RÉPOND QU'UNE FOIS** (§4.1).
///
/// §4.1 ne prévoit qu'un message de réponse par flux. En écrire un second ferait
/// lire au client une réponse qui ne répond à rien.
#[test]
fn on_ne_repond_qu_une_fois() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    poser_une_requete(&mut faux, flux, b"/boites", b"");
    h3.on_readable(&mut faux, &mut echo, flux)
        .expect("elle passe");
    let combien = faux.ce_qu_on_a_dit(flux.value()).len();

    h3.on_readable(&mut faux, &mut echo, flux)
        .expect("le rappel ne fait rien");
    assert_eq!(echo.servi.len(), 1, "le service n'a été appelé qu'une fois");
    assert_eq!(
        faux.ce_qu_on_a_dit(flux.value()).len(),
        combien,
        "et rien de plus n'est parti"
    );
}

/// **UNE RÉPONSE SANS CORPS N'A PAS DE TRAME `DATA`.**
///
/// Une trame de zéro octet ne dit rien de plus que son absence, et coûte deux
/// octets à chaque réponse qui n'a rien à porter.
#[test]
fn une_reponse_sans_corps_n_a_pas_de_trame_data() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    poser_une_requete(&mut faux, flux, b"/vide", b"");
    h3.on_readable(&mut faux, &mut echo, flux)
        .expect("elle passe");

    let dit = faux.ce_qu_on_a_dit(flux.value());
    let entete = ams_proto_h3::FrameHeader::parse(dit).expect("une trame");
    assert_eq!(entete.kind(), FrameKind::Headers);
    assert_eq!(
        usize::try_from(entete.total()).expect("tient"),
        dit.len(),
        "et rien après"
    );
}

/// **ON N'ATTEND PAS LA FIN POUR RIEN** (§4.1).
///
/// Répondre avant que le client ait fini d'écrire servirait une requête
/// tronquée — et l'application ne saurait pas qu'elle l'était.
#[test]
fn on_n_attend_pas_la_fin_pour_rien() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    let section = une_requete(b"/boites");
    let mut entete = [0_u8; 16];
    let pose = write_header(
        FrameKind::Headers,
        u64::try_from(section.len()).expect("tient"),
        &mut entete,
    )
    .expect("écrivable");
    faux.le_pair_dit(flux.value(), &entete[..pose]);
    faux.le_pair_dit(flux.value(), &section);
    // **PAS DE SECTION TERMINALE** : le client peut encore écrire un corps.

    h3.on_readable(&mut faux, &mut echo, flux)
        .expect("rien à conclure");
    assert!(echo.servi.is_empty(), "le service n'a pas été appelé");
    assert!(faux.ce_qu_on_a_dit(flux.value()).is_empty());
}

/// **UN `DATA` AVANT LES EN-TÊTES EST UNE FAUTE DE CONNEXION** (§4.1).
///
/// Ce n'est pas un pair qui s'est trompé sur une requête, c'est un pair qui ne
/// sait pas ce qu'il fait — et §4.1 le range parmi les fautes de connexion pour
/// cette raison.
#[test]
fn un_data_avant_les_en_tetes_est_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    let mut entete = [0_u8; 16];
    let pose = write_header(FrameKind::Data, 3, &mut entete).expect("écrivable");
    faux.le_pair_dit(flux.value(), &entete[..pose]);
    faux.le_pair_dit(flux.value(), b"abc");

    let faute = h3
        .on_readable(&mut faux, &mut echo, flux)
        .expect_err("§4.1 la refuse");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::FrameUnexpected.value()
    );
}

/// **UN FLUX QUI FINIT SANS EN-TÊTES N'EST PAS UNE REQUÊTE** (§4.1).
#[test]
fn un_flux_qui_finit_sans_en_tetes_n_est_pas_une_requete() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    faux.le_pair_dit(flux.value(), &[]);
    faux.etats.insert(flux.value(), RecvState::DataRecvd);

    let faute = h3
        .on_readable(&mut faux, &mut echo, flux)
        .expect_err("§4.1 la refuse");
    // §8.1 : `H3_REQUEST_INCOMPLETE` — « the stream terminated before completing
    // a request ». Ce n'est ni une trame déplacée ni un message mal formé : il
    // n'y a pas eu de requête du tout.
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::RequestIncomplete.value()
    );
}

/// **AU-DELÀ DE CE QU'ON A ANNONCÉ, C'EST UNE CHARGE EXCESSIVE** (§4.2.2, §8.1).
///
/// Le client le SAIT : nos réglages le lui ont dit. `H3_EXCESSIVE_LOAD` nomme
/// exactement cela.
#[test]
fn au_dela_de_ce_qu_on_a_annonce_c_est_une_charge_excessive() {
    for (kind, borne) in [
        (FrameKind::Headers, super::CHAMPS_OCTETS_MAX),
        (FrameKind::Data, super::CORPS_OCTETS_MAX),
    ] {
        let mut faux = Faux::new();
        let mut h3 = Http3::new();
        let mut echo = Echo::default();
        h3.on_established(&mut faux).expect("on peut ouvrir");
        let flux = requete_du_client(0);

        // Pour un `DATA`, il faut des en-têtes d'abord (§4.1).
        if matches!(kind, FrameKind::Data) {
            let section = une_requete(b"/gros");
            let mut entete = [0_u8; 16];
            let pose = write_header(
                FrameKind::Headers,
                u64::try_from(section.len()).expect("tient"),
                &mut entete,
            )
            .expect("écrivable");
            faux.le_pair_dit(flux.value(), &entete[..pose]);
            faux.le_pair_dit(flux.value(), &section);
        }

        let trop = borne.saturating_add(1);
        let mut entete = [0_u8; 16];
        let pose = write_header(kind, u64::try_from(trop).expect("tient"), &mut entete)
            .expect("écrivable");
        faux.le_pair_dit(flux.value(), &entete[..pose]);
        faux.le_pair_dit(flux.value(), &std::vec![0x61_u8; trop]);

        let faute = h3
            .on_readable(&mut faux, &mut echo, flux)
            .expect_err("§8.1 la refuse");
        assert_eq!(
            faute.close_code(),
            ams_proto_h3::H3Error::ExcessiveLoad.value(),
            "pour {kind:?}"
        );
        assert!(echo.servi.is_empty());
    }
}

/// **UNE TRAME INCONNUE SUR UNE REQUÊTE SE SAUTE** (§9).
#[test]
fn une_trame_inconnue_sur_une_requete_se_saute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    let section = une_requete(b"/boites");
    let mut entete = [0_u8; 16];
    // §4.1 : « Frames of unknown types MAY be sent before, after, or interleaved
    // with other frames. » Celle-ci vient AVANT les en-têtes, et ne rompt rien.
    let pose = write_header(FrameKind::Unknown(0x21), 4, &mut entete).expect("écrivable");
    faux.le_pair_dit(flux.value(), &entete[..pose]);
    faux.le_pair_dit(flux.value(), b"zzzz");
    let pose = write_header(
        FrameKind::Headers,
        u64::try_from(section.len()).expect("tient"),
        &mut entete,
    )
    .expect("écrivable");
    faux.le_pair_dit(flux.value(), &entete[..pose]);
    faux.le_pair_dit(flux.value(), &section);
    faux.etats.insert(flux.value(), RecvState::DataRecvd);

    h3.on_readable(&mut faux, &mut echo, flux)
        .expect("§9 : on saute, et l'on reprend");
    assert_eq!(echo.servi.len(), 1, "la requête a bien été servie");
}

/// **UNE SECTION DE CHAMPS QUI NE SE DÉCOMPRIME PAS EST UNE FAUTE** (§4.5 de
/// RFC 9204).
///
/// Nous annonçons une table dynamique nulle : un index dynamique ne désigne
/// rien, et le pair n'avait pas le droit d'en écrire un.
#[test]
fn une_section_qui_ne_se_decomprime_pas_est_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    // Le préfixe, puis une ligne indexée sur la table DYNAMIQUE (T=0).
    let section = [0x00_u8, 0x00, 0x80];
    let mut entete = [0_u8; 16];
    let pose = write_header(
        FrameKind::Headers,
        u64::try_from(section.len()).expect("tient"),
        &mut entete,
    )
    .expect("écrivable");
    faux.le_pair_dit(flux.value(), &entete[..pose]);
    faux.le_pair_dit(flux.value(), &section);
    faux.etats.insert(flux.value(), RecvState::DataRecvd);

    let faute = h3
        .on_readable(&mut faux, &mut echo, flux)
        .expect_err("elle est refusée");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::QpackDecompressionFailed.value()
    );
    assert!(echo.servi.is_empty());
}

/// **UN CHAMP QUE §4.2 INTERDIT NE S'ÉCRIT PAS.**
///
/// Les champs propres à la connexion n'existent pas en HTTP/3 : en écrire un
/// ferait douter un client de tout le reste de la réponse. **C'EST NOTRE FAUTE,
/// et non la sienne** — le service a demandé quelque chose d'impossible.
#[test]
fn un_champ_interdit_ne_s_ecrit_pas() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo {
        champ_interdit: true,
        ..Echo::default()
    };
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    poser_une_requete(&mut faux, flux, b"/boites", b"");
    let faute = h3
        .on_readable(&mut faux, &mut echo, flux)
        .expect_err("§4.2 le refuse");
    // §8.1 : `H3_INTERNAL_ERROR`. **LE PAIR N'Y EST POUR RIEN** — c'est notre
    // service qui a demandé l'impossible, et le lui imputer rendrait son journal
    // mensonger.
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::InternalError.value()
    );
}

/// **UN TRANSPORT QUI REFUSE NOTRE RÉPONSE NE SE TAIT PAS.**
#[test]
fn un_transport_qui_refuse_notre_reponse_ne_se_tait_pas() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    poser_une_requete(&mut faux, flux, b"/boites", b"");
    // Il a laissé ouvrir le flux de contrôle, puis il se ferme.
    faux.refuse_a_partir_de = Some(0);
    let faute = h3
        .on_readable(&mut faux, &mut echo, flux)
        .expect_err("il refuse");
    assert_eq!(faute.reason(), Reason::Transport);
}

/// **UN TYPE DE TRAME RÉSERVÉ PAR HTTP/2 EST UNE FAUTE, SUR UNE REQUÊTE AUSSI**
/// (§11.2.1).
#[test]
fn un_type_reserve_sur_une_requete_est_une_faute() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    // 0x06 : `PING` d'HTTP/2, que §11.2.1 réserve.
    faux.le_pair_dit(flux.value(), &[0x06, 0x00]);
    let faute = h3
        .on_readable(&mut faux, &mut echo, flux)
        .expect_err("§11.2.1 la refuse");
    assert_eq!(
        faute.close_code(),
        ams_proto_h3::H3Error::FrameUnexpected.value()
    );
}

/// **UN CORPS COUPÉ EN DEUX SE RECOLLE.**
///
/// Un flux QUIC livre par morceaux : une trame `DATA` peut arriver en plusieurs
/// fois, et refuser ici serait refuser un pair qui n'a rien fait de mal.
#[test]
fn un_corps_coupe_en_deux_se_recolle() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");

    let flux = requete_du_client(0);
    let section = une_requete(b"/boites");
    let mut entete = [0_u8; 16];
    let pose = write_header(
        FrameKind::Headers,
        u64::try_from(section.len()).expect("tient"),
        &mut entete,
    )
    .expect("écrivable");
    faux.le_pair_dit(flux.value(), &entete[..pose]);
    faux.le_pair_dit(flux.value(), &section);

    let pose = write_header(FrameKind::Data, 8, &mut entete).expect("écrivable");
    faux.le_pair_dit(flux.value(), &entete[..pose]);
    faux.le_pair_dit(flux.value(), b"quatre");
    h3.on_readable(&mut faux, &mut echo, flux)
        .expect("il en manque, et l'on attend");
    assert!(echo.servi.is_empty(), "la trame n'est pas finie");

    faux.le_pair_dit(flux.value(), b"re");
    faux.etats.insert(flux.value(), RecvState::DataRecvd);
    h3.on_readable(&mut faux, &mut echo, flux)
        .expect("et voilà la fin");
    assert_eq!(
        echo.servi,
        std::vec![(b"/boites".to_vec(), b"quatrere".to_vec())],
        "LE CORPS S'EST RECOLLÉ"
    );
}

/// La dernière trame écrite sur ce flux, après `depuis` octets.
fn derniere_trame(faux: &Faux, flux: StreamId, depuis: usize) -> (FrameKind, u64) {
    let dit = faux.ce_qu_on_a_dit(flux.value());
    let suite = dit.get(depuis..).expect("ce qui vient d'être écrit");
    let entete = ams_proto_h3::FrameHeader::parse(suite).expect("une trame entière");
    let charge = suite.get(entete.header_len()..).unwrap_or_default();
    let (identifiant, _) = varints::decode(charge).expect("un identifiant de §16");
    (entete.kind(), identifiant)
}

/// **§5.2 : L'EXTINCTION SE DIT EN DEUX TEMPS, ET LE SECOND NE MONTE PAS.**
///
/// D'abord l'identifiant maximal — « n'ouvre plus rien », sans condamner ce qui
/// est en vol. Puis, les requêtes en vol arrivées, le rang qui suit la dernière
/// qu'on ait servie : « au-delà, rien n'a été fait, rejoue ailleurs ».
#[test]
fn l_extinction_se_dit_en_deux_temps() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    let controle = h3.control_stream().expect("il est ouvert");
    assert_eq!(h3.goaway_sent(), None, "rien n'a encore été dit");

    // Deux requêtes servies : c'est la PLUS GRANDE qui donne son rang au second
    // temps, et non la dernière arrivée — les flux d'HTTP/3 n'arrivent pas dans
    // l'ordre, c'est même tout l'intérêt du transport.
    // `requete_du_client` prend un RANG, que §2.1 de RFC 9000 multiplie par
    // quatre : les rangs 1 et 0 sont les flux 4 et 0.
    for rang in [1, 0] {
        let flux = requete_du_client(rang);
        poser_une_requete(&mut faux, flux, b"/boites", b"");
        h3.on_readable(&mut faux, &mut echo, flux).expect("servie");
    }
    assert_eq!(echo.servi.len(), 2, "elles ont bien été servies");

    let avant = faux.ce_qu_on_a_dit(controle.value()).len();
    h3.shutdown(&mut faux).expect("le premier temps");
    assert_eq!(
        derniere_trame(&faux, controle, avant),
        (FrameKind::GoAway, ams_proto_h3::GOAWAY_MAX),
        "§5.2 : « a value set to the maximum possible value »"
    );

    let avant = faux.ce_qu_on_a_dit(controle.value()).len();
    h3.drain(&mut faux).expect("le second temps");
    assert_eq!(
        derniere_trame(&faux, controle, avant),
        (FrameKind::GoAway, 8),
        "§2.1 de RFC 9000 numérote de quatre en quatre : après le flux 4 vient le 8"
    );
    assert_eq!(h3.goaway_sent(), Some(8), "et c'est ce qu'on retient");
}

/// **SANS FLUX DE CONTRÔLE, IL N'Y A PERSONNE À QUI FAIRE SES ADIEUX.**
///
/// Une connexion dont la poignée de main n'a jamais abouti n'a pas de pair. Ce
/// n'est pas une faute — c'est une extinction qui n'a rien à dire.
#[test]
fn une_extinction_sans_flux_de_controle_ne_dit_rien() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.shutdown(&mut faux)
        .expect("rien à dire n'est pas une faute");
    h3.drain(&mut faux).expect("de même");
    assert_eq!(h3.goaway_sent(), None, "et rien n'a été retenu");
    assert!(
        faux.sortant.is_empty(),
        "ni écrit : il n'y a pas de flux où écrire"
    );
}

/// **UN `GOAWAY` QU'ON NE PEUT PAS ÉCRIRE NE SE TAIT PAS.**
///
/// Un transport qui refuse laisserait le pair croire qu'on sert encore ; le dire
/// est ce qui permet à l'appelant de fermer plutôt que d'attendre.
#[test]
fn un_goaway_que_le_transport_refuse_ne_se_tait_pas() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    faux.refuse_a_partir_de = Some(faux.ecritures);
    let faute = h3.shutdown(&mut faux).expect_err("il refuse");
    assert_eq!(faute.reason(), Reason::Transport);
}

/// **§5.2 : AU-DELÀ DE L'IDENTIFIANT, LA REQUÊTE EST REFUSÉE — ET NON LUE.**
///
/// « Requests [...] with the indicated identifier or greater are rejected by the
/// sender of the GOAWAY. » Le refus est un `RESET_STREAM` portant
/// `H3_REQUEST_REJECTED`, qui PROMET que rien n'a été fait : c'est cette promesse
/// qui permet au client de rejouer ailleurs sans exécuter deux fois.
///
/// **ET L'ON N'AVALE PAS SES OCTETS** : retenir de la mémoire pour une requête
/// qu'on ne servira pas, au moment même où l'on s'éteint, serait absurde.
#[test]
fn une_requete_au_dela_du_goaway_est_refusee() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    let mut echo = Echo::default();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    // Rien n'a été servi : le second temps désigne donc le flux zéro, et tout
    // est à rejouer.
    h3.drain(&mut faux).expect("le second temps");
    assert_eq!(h3.goaway_sent(), Some(0));

    let flux = requete_du_client(0);
    poser_une_requete(&mut faux, flux, b"/boites", b"");
    h3.on_readable(&mut faux, &mut echo, flux)
        .expect("un refus n'est pas une faute de connexion");

    assert!(echo.servi.is_empty(), "elle n'a PAS été servie");
    assert_eq!(
        faux.annules,
        std::vec![(flux.value(), ams_proto_h3::H3Error::RequestRejected.value())],
        "§8.1 : `H3_REQUEST_REJECTED`, et rien d'autre"
    );

    // **UNE FOIS, ET UNE SEULE** : un second `RESET_STREAM` ne dirait rien de
    // plus, et le pair qui continue d'écrire se fait seulement consommer.
    faux.le_pair_dit(flux.value(), b"la suite de ce qu'il disait");
    h3.on_readable(&mut faux, &mut echo, flux)
        .expect("on consomme, sans rien redire");
    assert_eq!(faux.annules.len(), 1, "un seul refus");
    assert_eq!(reste_a_lire(&faux, flux), 0, "et sa fenêtre se rouvre");
}

/// **UN REFUS QU'ON NE PEUT PAS ÉMETTRE NE SE TAIT PAS.**
///
/// Sans `RESET_STREAM`, le client attendrait une réponse qui ne viendra jamais —
/// et ne saurait pas qu'il peut rejouer ailleurs. Le taire ferait pendre son
/// flux jusqu'au délai d'inactivité de la connexion.
#[test]
fn un_refus_que_le_transport_n_emet_pas_ne_se_tait_pas() {
    let mut faux = Faux::new();
    let mut h3 = Http3::new();
    h3.on_established(&mut faux).expect("on peut ouvrir");
    h3.drain(&mut faux).expect("le second temps");

    faux.refuse_a_partir_de = Some(faux.ecritures);
    let flux = requete_du_client(0);
    poser_une_requete(&mut faux, flux, b"/boites", b"");
    let faute = h3
        .on_readable(&mut faux, &mut Echo::default(), flux)
        .expect_err("le transport refuse l'annulation");
    assert_eq!(faute.reason(), Reason::Transport);
}
