// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **LES DEUX CONDUCTEURS, FACE À FACE.**
//!
//! # POURQUOI PAS UN FAUX SERVEUR
//!
//! Un faux serveur dirait ce que NOUS croyons qu'un serveur dit. Celui d'en
//! face est [`crate::Http3`], le vrai : il refuse une trame hors de son flux,
//! une section qui ne fait pas une requête, un flux critique qui se ferme.
//!
//! **C'est exactement l'ensemble des fautes que ce conducteur-ci peut
//! commettre**, et aucune ne se verrait dans un aller-retour avec soi-même.

use std::collections::HashMap;

use ams_proto_http::StatusCode;
use ams_proto_quic::{Directional, Initiator, StreamId};
use ams_quic::RecvState;

use super::Http3Client;
use crate::{Error, Http3, Reponse, Service, Transport};

/// Un fil entre deux conducteurs : ce que l'un écrit, l'autre le lit.
///
/// **IL NE DÉCIDE RIEN.** Il range des octets par flux, et rend l'état de
/// réception qu'on lui pose. Tout ce qui ressemble à une décision — quel flux
/// ouvrir, quoi y écrire — appartient aux deux conducteurs qu'il relie.
#[derive(Debug)]
struct Fil {
    /// Ce qu'on a écrit et pas encore transmis, par flux.
    sortant: HashMap<u64, Vec<u8>>,
    /// Ce que le pair a écrit et qu'on n'a pas encore lu, par flux.
    entrant: HashMap<u64, Vec<u8>>,
    /// L'état de réception de chaque flux.
    etats: HashMap<u64, RecvState>,
    /// Le prochain rang de flux unidirectionnel à distribuer.
    prochain_uni: u64,
    /// Le prochain rang de flux bidirectionnel à distribuer.
    prochain_bi: u64,
    /// De quel côté ce fil est.
    cote: Initiator,
    /// Refuse-t-il d'ouvrir un flux unidirectionnel ?
    refuse_uni: bool,
    /// Refuse-t-il d'ouvrir un flux bidirectionnel ?
    refuse_bi: bool,
    /// Refuse-t-il d'écrire ?
    refuse_ecriture: bool,
    /// Refuse-t-il de conclure un flux ?
    refuse_fin: bool,
    /// N'accepte-t-il qu'une partie de ce qu'on lui écrit ?
    plafond: Option<usize>,
}

impl Fil {
    fn neuf(cote: Initiator) -> Self {
        Self {
            sortant: HashMap::new(),
            entrant: HashMap::new(),
            etats: HashMap::new(),
            prochain_uni: 0,
            prochain_bi: 0,
            cote,
            refuse_uni: false,
            refuse_bi: false,
            refuse_ecriture: false,
            refuse_fin: false,
            plafond: None,
        }
    }

    /// Le pair a écrit ceci sur ce flux.
    fn recevoir(&mut self, flux: u64, octets: &[u8]) {
        self.entrant
            .entry(flux)
            .or_default()
            .extend_from_slice(octets);
        self.etats.entry(flux).or_insert(RecvState::Recv);
    }

    /// Le pair a fini d'écrire ce flux.
    fn fin_recue(&mut self, flux: u64) {
        self.etats.insert(flux, RecvState::DataRecvd);
    }

    /// Ce qu'on a écrit et pas encore transmis, puis on l'oublie.
    fn vider(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut tout: Vec<(u64, Vec<u8>)> = self.sortant.drain().collect();
        tout.sort_by_key(|(flux, _)| *flux);
        tout
    }
}

impl Transport for Fil {
    fn open_uni(&mut self) -> Result<StreamId, Error> {
        if self.refuse_uni {
            return Err(Error::transport());
        }
        let flux = StreamId::from_index(self.prochain_uni, self.cote, Directional::Unidirectional)
            .expect("un rang qui tient");
        self.prochain_uni = self.prochain_uni.saturating_add(1);
        Ok(flux)
    }

    fn open_bi(&mut self) -> Result<StreamId, Error> {
        if self.refuse_bi {
            return Err(Error::transport());
        }
        let flux = StreamId::from_index(self.prochain_bi, self.cote, Directional::Bidirectional)
            .expect("un rang qui tient");
        self.prochain_bi = self.prochain_bi.saturating_add(1);
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
        if self.refuse_ecriture {
            return Err(Error::transport());
        }
        if let Some(plafond) = self.plafond {
            return Ok(octets.len().min(plafond));
        }
        self.sortant
            .entry(flux.value())
            .or_default()
            .extend_from_slice(octets);
        Ok(octets.len())
    }

    fn reset(&mut self, _flux: StreamId, _code: u64) -> Result<(), Error> {
        Ok(())
    }

    fn finish(&mut self, _flux: StreamId) -> Result<(), Error> {
        if self.refuse_fin {
            return Err(Error::transport());
        }
        Ok(())
    }

    fn recv_state(&self, flux: StreamId) -> Option<RecvState> {
        self.etats.get(&flux.value()).copied()
    }
}

/// Un service qui rend le chemin et le corps qu'on lui a donnés.
struct Echo;

impl Service for Echo {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Reponse<'o> {
        let chemin = tete.path();
        let combien = chemin.len().min(sortie.len());
        sortie
            .get_mut(..combien)
            .expect("la borne vient d'être prise")
            .copy_from_slice(chemin.get(..combien).unwrap_or_default());
        let fin = combien.saturating_add(corps.len()).min(sortie.len());
        let place = sortie.get_mut(combien..fin).unwrap_or_default();
        let pris = place.len();
        place.copy_from_slice(corps.get(..pris).unwrap_or_default());
        Reponse::new(StatusCode::OK, sortie.get(..fin).unwrap_or_default())
            .avec_champ(b"content-type", b"text/plain")
    }
}

/// Fait circuler ce que chaque camp a écrit, et laisse les deux avancer.
fn un_tour(
    client: &mut Http3Client,
    cote_client: &mut Fil,
    serveur: &mut Http3,
    cote_serveur: &mut Fil,
    service: &mut Echo,
    fin_de_requete: Option<u64>,
) {
    for (flux, octets) in cote_client.vider() {
        cote_serveur.recevoir(flux, &octets);
        if fin_de_requete == Some(flux) {
            cote_serveur.fin_recue(flux);
        }
    }

    let a_lire: Vec<u64> = cote_serveur.entrant.keys().copied().collect();
    for flux in a_lire {
        let flux = StreamId::new(flux).expect("un flux valide");
        serveur
            .on_readable(cote_serveur, service, flux)
            .expect("le serveur accepte ce que le client dit");
    }

    for (flux, octets) in cote_serveur.vider() {
        cote_client.recevoir(flux, &octets);
        // Le serveur conclut le flux de réponse dès qu'il a répondu.
        if matches!(
            StreamId::new(flux).expect("un flux valide").directional(),
            Directional::Bidirectional
        ) {
            cote_client.fin_recue(flux);
        }
    }

    let a_lire: Vec<u64> = cote_client.entrant.keys().copied().collect();
    for flux in a_lire {
        let flux = StreamId::new(flux).expect("un flux valide");
        client
            .on_readable(cote_client, flux)
            .expect("le client accepte ce que le serveur dit");
    }
}

#[test]
fn une_requete_va_au_serveur_et_la_reponse_revient() {
    let mut client = Http3Client::new();
    let mut serveur = Http3::new();
    let mut cote_client = Fil::neuf(Initiator::Client);
    let mut cote_serveur = Fil::neuf(Initiator::Server);
    let mut service = Echo;

    client
        .on_established(&mut cote_client)
        .expect("le client ouvre ses trois flux");
    serveur
        .on_established(&mut cote_serveur)
        .expect("le serveur ouvre les siens");

    let flux = client
        .request(
            &mut cote_client,
            b"POST",
            b"/v1/annonce",
            b"annuaire.example",
            &[(b"content-type", b"application/json")],
            b"{}",
        )
        .expect("la requête s'écrit");

    for _ in 0..4_u32 {
        un_tour(
            &mut client,
            &mut cote_client,
            &mut serveur,
            &mut cote_serveur,
            &mut service,
            Some(flux.value()),
        );
    }

    // **LES RÉGLAGES DU SERVEUR SONT ARRIVÉS**, et §6.2.1 en fait une obligation
    // des deux côtés : sans eux, le client devrait supposer les valeurs par
    // défaut et refuserait des réponses que le serveur juge acceptables.
    assert!(
        client.peer_settings().is_some(),
        "le client doit avoir lu les réglages du serveur"
    );

    let reponse = client.take_response(flux).expect("la réponse est entière");
    assert_eq!(reponse.statut, StatusCode::OK);
    assert_eq!(
        reponse.corps,
        b"/v1/annonce{}".to_vec(),
        "le serveur a bien reçu le chemin ET le corps"
    );

    // **ELLE SE PREND UNE FOIS** : la redemander rend `None`, ce qui est exact.
    assert!(client.take_response(flux).is_none());
}

#[test]
fn une_requete_sans_corps_ne_porte_pas_de_trame_data() {
    let mut client = Http3Client::new();
    let mut cote_client = Fil::neuf(Initiator::Client);
    client
        .on_established(&mut cote_client)
        .expect("le client ouvre ses trois flux");

    let flux = client
        .request(
            &mut cote_client,
            b"GET",
            b"/v1/defi",
            b"annuaire.example",
            &[],
            b"",
        )
        .expect("la requête s'écrit");

    let ecrit = cote_client
        .sortant
        .get(&flux.value())
        .expect("quelque chose a été écrit");
    let entete = ams_proto_h3::FrameHeader::parse(ecrit).expect("un en-tête lisible");
    assert_eq!(entete.kind(), ams_proto_h3::FrameKind::Headers);
    assert_eq!(
        usize::try_from(entete.total()).expect("tient"),
        ecrit.len(),
        "rien ne suit la section : pas de trame `DATA` vide"
    );
}

#[test]
fn le_client_n_ouvre_pas_deux_fois_ses_flux() {
    // §6.2.1 : « a single control stream ». Un second dirait au serveur qu'il y
    // a deux états à croire.
    let mut client = Http3Client::new();
    let mut fil = Fil::neuf(Initiator::Client);
    client.on_established(&mut fil).expect("la première fois");
    let controle = client.control_stream();
    client
        .on_established(&mut fil)
        .expect("la seconde ne fait rien");
    assert_eq!(client.control_stream(), controle);
}

// ── CE QUE LE CONDUCTEUR REFUSE, ET CE QU'IL SAUTE ──────────────────────────

#[test]
fn une_requete_qui_ne_passe_pas_entiere_est_notre_faute() {
    // **TOUT OU RIEN.** Un flux qui n'aurait pris qu'une partie de la requête
    // laisserait le serveur attendre une section incomplète, et rien dans ce
    // qu'il verrait ne lui dirait qu'elle ne viendra pas.
    let mut client = Http3Client::default();
    let mut fil = Fil::neuf(Initiator::Client);
    fil.plafond = Some(4);
    let issue = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect_err("le flux n'a pas tout pris");
    assert_eq!(issue.reason(), crate::Reason::Interne);
}

/// Le début d'une réponse : la section d'en-têtes d'un `200`.
fn section_de_reponse() -> Vec<u8> {
    let mut section = [0_u8; 256];
    let combien = ams_proto_h3::qpack::write_section(StatusCode::OK, &[], &mut section)
        .expect("elle s'écrit");
    let mut entete = [0_u8; 16];
    let pose = ams_proto_h3::write_header(
        ams_proto_h3::FrameKind::Headers,
        u64::try_from(combien).expect("tient"),
        &mut entete,
    )
    .expect("l'en-tête s'écrit");
    let mut sortie = Vec::new();
    sortie.extend_from_slice(entete.get(..pose).unwrap_or_default());
    sortie.extend_from_slice(section.get(..combien).unwrap_or_default());
    sortie
}

/// Une trame quelconque, écrite à la main.
fn trame(kind: ams_proto_h3::FrameKind, charge: &[u8]) -> Vec<u8> {
    let mut entete = [0_u8; 16];
    let pose = ams_proto_h3::write_header(
        kind,
        u64::try_from(charge.len()).expect("tient"),
        &mut entete,
    )
    .expect("l'en-tête s'écrit");
    let mut sortie = Vec::new();
    sortie.extend_from_slice(entete.get(..pose).unwrap_or_default());
    sortie.extend_from_slice(charge);
    sortie
}

/// Un client dont les flux sont ouverts, et le fil qui le porte.
fn un_client() -> (Http3Client, Fil) {
    let mut client = Http3Client::new();
    let mut fil = Fil::neuf(Initiator::Client);
    client.on_established(&mut fil).expect("les trois flux");
    (client, fil)
}

#[test]
fn nos_propres_flux_unidirectionnels_ne_se_lisent_pas() {
    // §6.1 : ce qu'on a écrit sur son propre flux de contrôle n'est pas à lire.
    let (mut client, mut fil) = un_client();
    let notre = client.control_stream().expect("il est ouvert");
    client
        .on_readable(&mut fil, notre)
        .expect("il n'y a rien à y faire");
}

#[test]
fn un_flux_de_controle_du_serveur_qui_se_ferme_condamne_la_connexion() {
    // §6.2.1 : « Closure of the control stream […] MUST be treated as a
    // connection error of type H3_CLOSED_CRITICAL_STREAM. »
    let (mut client, mut fil) = un_client();
    let du_serveur = StreamId::from_index(0, Initiator::Server, Directional::Unidirectional)
        .expect("un rang qui tient");
    // Le type du flux, puis ses réglages, puis la fin.
    let mut octets = std::vec![0x00_u8];
    octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::Settings, &[]));
    fil.recevoir(du_serveur.value(), &octets);
    client
        .on_readable(&mut fil, du_serveur)
        .expect("les réglages passent");

    fil.fin_recue(du_serveur.value());
    let issue = client
        .on_readable(&mut fil, du_serveur)
        .expect_err("un flux critique ne se ferme pas");
    assert_eq!(
        issue.reason(),
        crate::Reason::H3(ams_proto_h3::Reason::CriticalStreamClosed)
    );
}

#[test]
fn un_type_de_flux_qui_arrive_par_morceaux_attend() {
    // §6.2 : « a stream type can be spread across eight bytes », et un flux QUIC
    // les livre par morceaux. Refuser tant qu'ils ne sont pas tous là serait
    // refuser un pair qui n'a rien fait de mal.
    let (mut client, mut fil) = un_client();
    let du_serveur = StreamId::from_index(0, Initiator::Server, Directional::Unidirectional)
        .expect("un rang qui tient");
    // Le premier octet d'un entier de §16 sur huit octets, et rien de plus.
    fil.recevoir(du_serveur.value(), &[0xC0]);
    client
        .on_readable(&mut fil, du_serveur)
        .expect("on attend la suite");
    assert!(
        client.peer_settings().is_none(),
        "rien n'a encore été compris"
    );
}

#[test]
fn un_flux_d_un_type_inconnu_se_jette() {
    // §6.2 : « Recipients of unknown stream types MUST either abort reading of
    // the stream or discard incoming data without further processing. »
    let (mut client, mut fil) = un_client();
    let du_serveur = StreamId::from_index(3, Initiator::Server, Directional::Unidirectional)
        .expect("un rang qui tient");
    // Type `0x21` : réservé à l'extensibilité (§6.2.3), et inconnu de nous.
    fil.recevoir(du_serveur.value(), &[0x21, 0xAA, 0xBB]);
    client
        .on_readable(&mut fil, du_serveur)
        .expect("on jette, et rien ne condamne");
}

#[test]
fn une_trame_de_controle_plus_longue_que_notre_borne_est_refusee() {
    // **C'EST NOTRE BORNE, PAS CELLE DU PAIR** (C3) : §7.2 rend ces trames
    // courtes, et une qui dépasse donnerait au serveur le moyen de choisir
    // combien nous retenons. L'attendre entière serait attendre pour toujours.
    let (mut client, mut fil) = un_client();
    let du_serveur = StreamId::from_index(0, Initiator::Server, Directional::Unidirectional)
        .expect("un rang qui tient");
    let mut octets = std::vec![0x00_u8];
    octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::Settings, &[]));
    // Puis une trame dont l'en-tête annonce une charge démesurée.
    let mut entete = [0_u8; 16];
    let pose = ams_proto_h3::write_header(ams_proto_h3::FrameKind::MaxPushId, 100_000, &mut entete)
        .expect("l'en-tête s'écrit");
    octets.extend_from_slice(entete.get(..pose).unwrap_or_default());
    fil.recevoir(du_serveur.value(), &octets);

    let issue = client
        .on_readable(&mut fil, du_serveur)
        .expect_err("cette charge ne viendra jamais entière");
    assert_eq!(
        issue.reason(),
        crate::Reason::H3(ams_proto_h3::Reason::MalformedFrame)
    );
}

#[test]
fn une_trame_de_controle_incomplete_attend() {
    let (mut client, mut fil) = un_client();
    let du_serveur = StreamId::from_index(0, Initiator::Server, Directional::Unidirectional)
        .expect("un rang qui tient");
    let mut octets = std::vec![0x00_u8];
    octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::Settings, &[]));
    // Un en-tête de `GOAWAY` sans sa charge : on attend, on ne condamne pas.
    let mut entete = [0_u8; 16];
    let pose = ams_proto_h3::write_header(ams_proto_h3::FrameKind::GoAway, 1, &mut entete)
        .expect("l'en-tête s'écrit");
    octets.extend_from_slice(entete.get(..pose).unwrap_or_default());
    fil.recevoir(du_serveur.value(), &octets);
    client.on_readable(&mut fil, du_serveur).expect("on attend");

    // Et quand la charge arrive, le `GOAWAY` se lit.
    fil.recevoir(du_serveur.value(), &[0x00]);
    client
        .on_readable(&mut fil, du_serveur)
        .expect("le GOAWAY se lit");
}

#[test]
fn une_trame_inconnue_sur_un_flux_de_reponse_se_saute() {
    // §9 : « Frames of unknown types […] MUST be ignored », charge comprise.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");

    let mut octets = trame(ams_proto_h3::FrameKind::Unknown(0x21), &[0xAA; 40]);
    octets.extend_from_slice(&section_de_reponse());
    octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::Data, b"bonjour"));
    fil.recevoir(flux.value(), &octets);
    fil.fin_recue(flux.value());
    client.on_readable(&mut fil, flux).expect("elle se lit");

    let reponse = client.take_response(flux).expect("la réponse est entière");
    assert_eq!(reponse.statut, StatusCode::OK);
    assert_eq!(reponse.corps, b"bonjour".to_vec());
}

#[test]
fn un_corps_plus_long_que_notre_borne_est_refuse() {
    // **NOTRE BORNE, PAS CELLE DU PAIR** : sans elle, un serveur choisirait
    // combien nous retenons.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");

    let mut octets = section_de_reponse();
    let enorme = std::vec![0x41_u8; crate::CORPS_OCTETS_MAX.saturating_add(1)];
    octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::Data, &enorme));
    fil.recevoir(flux.value(), &octets);

    let issue = client
        .on_readable(&mut fil, flux)
        .expect_err("ce corps dépasse ce qu'on retient");
    assert_eq!(issue.reason(), crate::Reason::Excessive);
}

#[test]
fn une_section_plus_longue_que_notre_borne_est_refusee() {
    // §4.2.2 : c'est le `SETTINGS_MAX_FIELD_SECTION_SIZE` qu'on a annoncé.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");

    let mut entete = [0_u8; 16];
    let pose = ams_proto_h3::write_header(
        ams_proto_h3::FrameKind::Headers,
        u64::try_from(crate::CHAMPS_OCTETS_MAX)
            .expect("tient")
            .saturating_add(1),
        &mut entete,
    )
    .expect("l'en-tête s'écrit");
    fil.recevoir(flux.value(), entete.get(..pose).unwrap_or_default());

    let issue = client
        .on_readable(&mut fil, flux)
        .expect_err("cette section dépasse ce qu'on a annoncé");
    assert_eq!(issue.reason(), crate::Reason::Excessive);
}

#[test]
fn une_section_incomplete_attend_la_suite() {
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");

    let entiere = section_de_reponse();
    let (debut, fin) = entiere.split_at(2);
    fil.recevoir(flux.value(), debut);
    client.on_readable(&mut fil, flux).expect("on attend");
    assert!(client.take_response(flux).is_none(), "rien n'est entier");

    fil.recevoir(flux.value(), fin);
    fil.fin_recue(flux.value());
    client.on_readable(&mut fil, flux).expect("elle se lit");
    assert_eq!(
        client.take_response(flux).expect("entière").statut,
        StatusCode::OK
    );
}

#[test]
fn un_corps_qui_arrive_apres_coup_se_recolle() {
    // Le cas où le tampon se vide au milieu d'une trame `DATA` : on attend, et
    // le flux n'est pas fini pour autant.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");

    let mut octets = section_de_reponse();
    octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::Data, b"bonjour"));
    let (debut, fin) = octets.split_at(octets.len().saturating_sub(3));
    fil.recevoir(flux.value(), debut);
    client.on_readable(&mut fil, flux).expect("on attend");
    assert!(client.take_response(flux).is_none());

    fil.recevoir(flux.value(), fin);
    fil.fin_recue(flux.value());
    client.on_readable(&mut fil, flux).expect("elle se lit");
    assert_eq!(
        client.take_response(flux).expect("entière").corps,
        b"bonjour".to_vec()
    );
}

#[test]
fn la_charge_d_une_trame_inconnue_se_saute_meme_en_plusieurs_fois() {
    // **`a_sauter` EXISTE POUR CE CAS-LÀ**, et pour lui seul : la charge d'une
    // trame qu'on ignore n'est pas encore arrivée, et elle ne doit pas entrer
    // dans le tampon quand elle arrivera.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");

    // L'en-tête seul : la charge suivra.
    let entiere = trame(ams_proto_h3::FrameKind::Unknown(0x21), &[0xAA; 40]);
    fil.recevoir(flux.value(), entiere.get(..2).unwrap_or_default());
    client.on_readable(&mut fil, flux).expect("on attend");

    // La charge, en deux morceaux.
    fil.recevoir(flux.value(), entiere.get(2..20).unwrap_or_default());
    client.on_readable(&mut fil, flux).expect("on saute");
    fil.recevoir(flux.value(), entiere.get(20..).unwrap_or_default());
    client.on_readable(&mut fil, flux).expect("on saute encore");

    // Et la réponse qui suit se lit normalement : rien de la trame ignorée n'a
    // été pris pour elle.
    let mut octets = section_de_reponse();
    octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::Data, b"bonjour"));
    fil.recevoir(flux.value(), &octets);
    fil.fin_recue(flux.value());
    client.on_readable(&mut fil, flux).expect("elle se lit");

    let reponse = client.take_response(flux).expect("la réponse est entière");
    assert_eq!(reponse.corps, b"bonjour".to_vec());
}

#[test]
fn un_flux_de_reponse_qui_n_est_pas_fini_n_est_pas_une_reponse() {
    // **LE TAMPON EST VIDE ET LE FLUX EST OUVERT** : il n'y a rien à décider, et
    // surtout rien à conclure. Prendre cet état pour une fin ferait rendre une
    // réponse tronquée comme si elle était entière.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");

    fil.recevoir(flux.value(), &section_de_reponse());
    client.on_readable(&mut fil, flux).expect("elle se lit");
    assert!(
        client.take_response(flux).is_none(),
        "le serveur n'a pas fini d'écrire"
    );

    fil.fin_recue(flux.value());
    client
        .on_readable(&mut fil, flux)
        .expect("et maintenant si");
    assert_eq!(
        client.take_response(flux).expect("entière").statut,
        StatusCode::OK
    );
}

#[test]
fn un_pair_qui_n_ouvre_pas_trois_flux_unidirectionnels_arrete_tout() {
    // §6.2 de RFC 9114 demande au pair d'en donner assez pour nos trois flux.
    // Un pair qui n'en donne pas ne verra pas la connexion s'ouvrir, et il faut
    // le dire plutôt que de servir à moitié.
    let mut client = Http3Client::new();
    let mut fil = Fil::neuf(Initiator::Client);
    fil.refuse_uni = true;
    assert_eq!(
        client
            .on_established(&mut fil)
            .expect_err("le pair n'a rien ouvert")
            .reason(),
        crate::Reason::Transport
    );
}

#[test]
fn ce_que_le_transport_refuse_a_la_requete_remonte() {
    // Trois refus, trois endroits : ouvrir le flux, y écrire, le conclure.
    // **AUCUN NE DOIT ÊTRE AVALÉ** — un appelant qui croirait sa requête partie
    // attendrait une réponse qui ne viendra jamais.
    for (bi, ecriture, fin) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let mut client = Http3Client::new();
        let mut fil = Fil::neuf(Initiator::Client);
        fil.refuse_bi = bi;
        fil.refuse_ecriture = ecriture;
        fil.refuse_fin = fin;
        // L'ouverture des trois flux passe : c'est la requête qu'on éprouve.
        if !ecriture {
            client.on_established(&mut fil).expect("les trois flux");
        }
        assert_eq!(
            client
                .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
                .expect_err("le transport refuse")
                .reason(),
            crate::Reason::Transport,
            "bi={bi} ecriture={ecriture} fin={fin}"
        );
    }
}

#[test]
fn une_requete_dont_les_champs_ne_tiennent_pas_est_refusee() {
    // §4.2.2 : c'est notre propre borne de section, et une requête qui la
    // dépasse ne partira pas — il vaut mieux le dire ici qu'après un
    // aller-retour.
    let (mut client, mut fil) = un_client();
    let enorme = std::vec![b'a'; crate::CHAMPS_OCTETS_MAX.saturating_mul(4)];
    let issue = client
        .request(
            &mut fil,
            b"GET",
            b"/x",
            b"a.example",
            &[(b"x-trop-long", &enorme)],
            b"",
        )
        .expect_err("cette section ne tient pas");
    assert_eq!(
        issue.reason(),
        crate::Reason::H3(ams_proto_h3::Reason::BufferTooSmall)
    );
}

#[test]
fn deux_flux_de_controle_du_serveur_condamnent_la_connexion() {
    // §6.2.1 : « Only one control stream per peer is permitted. » Deux
    // prétendraient décrire le même état, et rien ne dirait lequel croire.
    let (mut client, mut fil) = un_client();
    for rang in [0_u64, 4] {
        let flux = StreamId::from_index(rang, Initiator::Server, Directional::Unidirectional)
            .expect("un rang qui tient");
        let mut octets = std::vec![0x00_u8];
        octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::Settings, &[]));
        fil.recevoir(flux.value(), &octets);
        let issue = client.on_readable(&mut fil, flux);
        if rang == 0 {
            issue.expect("le premier passe");
        } else {
            assert_eq!(
                issue.expect_err("le second, non").reason(),
                crate::Reason::H3(ams_proto_h3::Reason::DuplicateCriticalStream)
            );
        }
    }
}

#[test]
fn un_flux_de_poussee_du_serveur_est_refuse() {
    // §4.6 : nous n'avons annoncé aucune poussée, donc le serveur n'a pas le
    // droit d'ouvrir un flux de ce type. `accept_stream` le dit.
    let (mut client, mut fil) = un_client();
    let du_serveur = StreamId::from_index(0, Initiator::Server, Directional::Unidirectional)
        .expect("un rang qui tient");
    // §4.6 : le type d'un flux de poussée vaut `0x01`.
    fil.recevoir(du_serveur.value(), &[0x01]);
    assert_eq!(
        client
            .on_readable(&mut fil, du_serveur)
            .expect_err("aucune poussée n'a été annoncée")
            .reason(),
        crate::Reason::H3(ams_proto_h3::Reason::PushRefused)
    );
}

#[test]
fn deux_flux_qpack_du_meme_type_condamnent_la_connexion() {
    // §4.2 de RFC 9204 : « at most one », et deux prétendraient tenir le même
    // état de table.
    let (mut client, mut fil) = un_client();
    for rang in [0_u64, 4] {
        let flux = StreamId::from_index(rang, Initiator::Server, Directional::Unidirectional)
            .expect("un rang qui tient");
        // `0x02` : le flux d'encodeur QPACK.
        fil.recevoir(flux.value(), &[0x02]);
        let issue = client.on_readable(&mut fil, flux);
        if rang == 0 {
            issue.expect("le premier passe");
        } else {
            assert_eq!(
                issue.expect_err("le second, non").reason(),
                crate::Reason::H3(ams_proto_h3::Reason::DuplicateCriticalStream)
            );
        }
    }
}

#[test]
fn une_trame_de_requete_sur_le_flux_de_controle_est_refusee() {
    // §7.2 : `DATA` n'a rien à faire sur un flux de contrôle, et §12.4 en fait
    // une faute de connexion.
    let (mut client, mut fil) = un_client();
    let du_serveur = StreamId::from_index(0, Initiator::Server, Directional::Unidirectional)
        .expect("un rang qui tient");
    let mut octets = std::vec![0x00_u8];
    octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::Data, b"x"));
    fil.recevoir(du_serveur.value(), &octets);
    assert_eq!(
        client
            .on_readable(&mut fil, du_serveur)
            .expect_err("DATA n'est pas une trame de contrôle")
            .reason(),
        crate::Reason::H3(ams_proto_h3::Reason::FrameOnWrongStream)
    );
}

#[test]
fn des_reglages_illisibles_condamnent_la_connexion() {
    // §7.2.4 : une charge de réglages qui ne se lit pas n'est pas une charge de
    // réglages, et il n'y a pas de valeur par défaut à supposer.
    let (mut client, mut fil) = un_client();
    let du_serveur = StreamId::from_index(0, Initiator::Server, Directional::Unidirectional)
        .expect("un rang qui tient");
    let mut octets = std::vec![0x00_u8];
    // Un identifiant de réglage sans sa valeur.
    octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::Settings, &[0x06]));
    fil.recevoir(du_serveur.value(), &octets);
    assert!(
        client.on_readable(&mut fil, du_serveur).is_err(),
        "ces réglages ne se lisent pas"
    );
}

#[test]
fn une_trame_de_controle_avant_les_reglages_est_refusee() {
    // §6.2.1 : « If the first frame of the control stream is any other frame
    // type, this MUST be treated as a connection error of type
    // H3_MISSING_SETTINGS. »
    let (mut client, mut fil) = un_client();
    let du_serveur = StreamId::from_index(0, Initiator::Server, Directional::Unidirectional)
        .expect("un rang qui tient");
    let mut octets = std::vec![0x00_u8];
    octets.extend_from_slice(&trame(ams_proto_h3::FrameKind::GoAway, &[0x00]));
    fil.recevoir(du_serveur.value(), &octets);
    assert_eq!(
        client
            .on_readable(&mut fil, du_serveur)
            .expect_err("les réglages doivent venir en premier")
            .reason(),
        crate::Reason::H3(ams_proto_h3::Reason::MissingSettings)
    );
}

#[test]
fn une_trame_de_controle_sur_un_flux_de_reponse_est_refusee() {
    // §7.2.4 : `SETTINGS` ne voyage que sur le flux de contrôle.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");
    fil.recevoir(flux.value(), &trame(ams_proto_h3::FrameKind::Settings, &[]));
    assert_eq!(
        client
            .on_readable(&mut fil, flux)
            .expect_err("SETTINGS n'est pas une trame de requête")
            .reason(),
        crate::Reason::H3(ams_proto_h3::Reason::FrameOnWrongStream)
    );
}

#[test]
fn un_corps_avant_les_en_tetes_n_est_pas_un_message() {
    // §4.1 : la séquence est en-têtes, puis corps. Un `DATA` d'abord ne
    // condamne que son flux, mais il le condamne.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");
    fil.recevoir(
        flux.value(),
        &trame(ams_proto_h3::FrameKind::Data, b"bonjour"),
    );
    assert_eq!(
        client
            .on_readable(&mut fil, flux)
            .expect_err("le corps précède les en-têtes")
            .reason(),
        crate::Reason::H3(ams_proto_h3::Reason::FrameOutOfOrder)
    );
}

#[test]
fn une_section_de_reponse_qui_ne_se_decode_pas_condamne_le_flux() {
    // §4.1.2 : une section bien reçue mais qui ne fait pas un message. Elle
    // remonte telle quelle — l'appelant doit savoir que c'est le SERVEUR qui a
    // mal parlé, et non son transport qui a failli.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");
    // Un préfixe nul, puis rien : pas de `:status`.
    fil.recevoir(
        flux.value(),
        &trame(ams_proto_h3::FrameKind::Headers, &[0x00, 0x00]),
    );
    assert_eq!(
        client
            .on_readable(&mut fil, flux)
            .expect_err("une réponse sans statut n'en est pas une")
            .reason(),
        crate::Reason::H3(ams_proto_h3::Reason::MalformedResponse)
    );
}

#[test]
fn un_flux_qui_se_ferme_sans_reponse_est_une_faute() {
    // §4.1 : « A message that ends without a complete field section is
    // malformed. » Le pair a conclu, et il n'a rien dit.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");
    fil.fin_recue(flux.value());
    assert_eq!(
        client
            .on_readable(&mut fil, flux)
            .expect_err("rien n'est arrivé")
            .reason(),
        crate::Reason::H3(ams_proto_h3::Reason::IncompleteRequest)
    );
}

#[test]
fn un_flux_de_controle_du_serveur_qui_se_dit_deux_fois_est_refuse_a_l_acceptation() {
    // `accept_stream` refuse ce qu'on ne conduit pas : c'est le premier des deux
    // contrôles, avant même l'état de connexion.
    let (mut client, mut fil) = un_client();
    let du_serveur = StreamId::from_index(8, Initiator::Server, Directional::Unidirectional)
        .expect("un rang qui tient");
    // `0x01` : une poussée. `accept_stream` la nomme, et c'est ce chemin-là.
    fil.recevoir(du_serveur.value(), &[0x01]);
    assert!(client.on_readable(&mut fil, du_serveur).is_err());
}

#[test]
fn des_octets_orphelins_a_la_fin_ne_font_pas_une_reponse() {
    // Le pair a conclu son flux, et il reste dans le tampon de quoi ne pas faire
    // une trame. **CE N'EST PAS UNE FIN** : conclure ici rendrait une réponse
    // dont on sait qu'il manque quelque chose.
    let (mut client, mut fil) = un_client();
    let flux = client
        .request(&mut fil, b"GET", b"/x", b"a.example", &[], b"")
        .expect("la requête s'écrit");

    let mut octets = section_de_reponse();
    // Un premier octet de trame, et rien derrière.
    octets.push(0x00);
    fil.recevoir(flux.value(), &octets);
    fil.fin_recue(flux.value());
    client
        .on_readable(&mut fil, flux)
        .expect("on lit ce qu'on peut");
    assert!(
        client.take_response(flux).is_none(),
        "il reste des octets qui ne font pas une trame"
    );
}
