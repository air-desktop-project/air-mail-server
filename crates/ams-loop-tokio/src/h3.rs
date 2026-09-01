// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTTP/3 sur l'écoute QUIC : les deux pièces qui assemblent.
//!
//! # C'EST ICI, ET NULLE PART AILLEURS, QUE LES ÉTAGES SE TOUCHENT
//!
//! `ams-h3` conduit HTTP/3 sans connaître QUIC autrement que par son interface
//! [`Transport`] ; `ams-quic-tls` conduit une connexion sans savoir ce qu'un
//! octet veut dire ; `ams-session::http` décide des requêtes sans rien émettre.
//! **Aucun des trois ne connaît les deux autres**, et c'est ce module qui les
//! relie — comme `serve_http_connection` le fait déjà pour HTTP/2.
//!
//! Deux pièces, et rien de plus : un pont vers le transport, et un service qui
//! enchaîne la session et l'API.

use std::collections::HashMap;

use ams_api::{JSON_MEDIA_TYPE, PROBLEM_MEDIA_TYPE, Scope};
use ams_guard::{Event as GuardEvent, Source};
use ams_h3::{Http3, Reponse, Transport};
use ams_proto_http::{Method, RequestHead, StatusCode};
use ams_proto_quic::{Directional, StreamId};
use ams_quic::RecvState;
use ams_quic_tls::Connection;
use ams_session::http::{Http, Next};

use crate::guard::SharedGuard;
use crate::http::Api;

/// Ce qu'un tampon de travail de la session doit faire.
///
/// La session écrit là ses refus et ses jetons ; §3 de RFC 9457 borne déjà ce
/// qu'un « problem detail » raconte, et huit kibioctets couvrent largement.
const TRAVAIL_OCTETS: usize = 8 * 1024;

/// Ce qu'une réponse servie par l'API peut faire.
const RENDU_OCTETS: usize = 64 * 1024;

/// Le pont entre HTTP/3 et une connexion QUIC.
///
/// # POURQUOI UN TYPE À NOUS PLUTÔT QU'UNE IMPLÉMENTATION DIRECTE
///
/// [`ams_h3::Transport`] appartient à `ams-h3`, [`Connection`] à
/// `ams-quic-tls` : aucun des deux n'est à nous, et la règle de l'orphelin
/// interdit de les marier ailleurs que chez l'un d'eux. **Ce n'est pas une gêne,
/// c'est le bon endroit** : l'assemblage demande une vraie connexion pour être
/// éprouvé, et sa place est donc à l'étage qui en tient une.
struct Pont<'a>(&'a mut Connection);

impl Transport for Pont<'_> {
    fn open_uni(&mut self) -> Result<StreamId, ams_h3::Error> {
        self.0
            .open_stream(Directional::Unidirectional)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn read(&mut self, flux: StreamId, vers: &mut [u8]) -> usize {
        self.0.read(flux, vers)
    }

    fn write(&mut self, flux: StreamId, octets: &[u8]) -> Result<usize, ams_h3::Error> {
        self.0
            .write(flux, octets)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn reset(&mut self, flux: StreamId, code: u64) -> Result<(), ams_h3::Error> {
        self.0
            .reset(flux, code)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn finish(&mut self, flux: StreamId) -> Result<(), ams_h3::Error> {
        self.0.finish(flux).map_err(|_| ams_h3::Error::transport())
    }

    fn recv_state(&self, flux: StreamId) -> Option<RecvState> {
        self.0.recv_state(flux)
    }
}

/// Ce qui sert les requêtes HTTP/3 : la session décide, l'API sert.
///
/// C'est le même enchaînement que pour HTTP/2, et il n'y en a qu'un — une
/// seconde façon de décider ferait diverger les deux versions du protocole sur
/// des règles qui n'ont rien à voir avec le transport.
pub struct ServiceH3<'a, A: Api> {
    /// La session qui décide.
    session: &'a Http,
    /// Ce qui sert les ressources.
    api: &'a A,
    /// Le videur (C8).
    guard: &'a SharedGuard,
    /// D'où le pair parle. **Posée à chaque requête** : un service sert
    /// plusieurs connexions, et la retenir à la construction ferait compter tous
    /// les refus contre la première adresse qui a parlé.
    source: Source,
    /// Le tampon de la session.
    travail: Vec<u8>,
    /// Celui de l'échange d'identifiants.
    ///
    /// **UN SECOND, ET C'EST NÉCESSAIRE** : le premier tour emprunte `travail`
    /// tant qu'on lit ce qu'il a décidé, et `on_credentials` écrit pendant ce
    /// temps-là.
    echange: Vec<u8>,
    /// Celui de l'API.
    rendu: Vec<u8>,
    /// Combien de requêtes ont été servies.
    servies: u64,
    /// Combien ont reçu un refus (§15.5 de RFC 9110 : les codes 4xx et 5xx).
    refusees: u64,
}

impl<'a, A: Api> ServiceH3<'a, A> {
    /// Un service qui enchaîne cette session et cette API.
    ///
    /// La source du pair se pose à chaque requête par [`ServiceH3::pour`].
    pub fn new(session: &'a Http, api: &'a A, guard: &'a SharedGuard) -> Self {
        Self {
            session,
            api,
            guard,
            source: Source::V4([0, 0, 0, 0]),
            travail: vec![0_u8; TRAVAIL_OCTETS],
            echange: vec![0_u8; TRAVAIL_OCTETS],
            rendu: vec![0_u8; RENDU_OCTETS],
            servies: 0,
            refusees: 0,
        }
    }
}

impl<A: Api> ServiceH3<'_, A> {
    /// Les requêtes qui suivent viennent de cette source.
    pub const fn pour(&mut self, source: Source) {
        self.source = source;
    }
}

impl<A: Api> ams_h3::Service for ServiceH3<'_, A> {
    fn serve<'o>(
        &mut self,
        tete: &RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Reponse<'o> {
        self.guard.observe(self.source, GuardEvent::Command);
        let maintenant = crate::http::maintenant();

        // La session décide, et ne touche à rien.
        let tour = self
            .session
            .request(tete, corps, maintenant, &mut self.travail);
        let (status, media, a_ecrire) = match tour.next() {
            Next::Respond => (tour.status(), PROBLEM_MEDIA_TYPE, tour.body()),
            Next::CheckCredentials { login, password } => {
                let accorde = self.api.authenticate(login, password);
                let suite = self.session.on_credentials(
                    accorde.is_some(),
                    login,
                    accorde.unwrap_or_else(Scope::none),
                    self.api.nonce(),
                    maintenant,
                    &mut self.echange,
                );
                if accorde.is_none() {
                    // **UN REFUS D'IDENTIFIANTS EST UNE TRAME INVALIDE** pour le
                    // videur : c'est ce qui borne une attaque par essais.
                    self.guard.observe(self.source, GuardEvent::InvalidFrame);
                }
                (suite.status(), JSON_MEDIA_TYPE, suite.body())
            }
            Next::Serve {
                resource,
                method,
                account,
                body,
            } => {
                let servi = self
                    .api
                    .serve(resource, method, account, body, &mut self.rendu);
                (servi.status, servi.media, servi.body)
            }
        };

        self.servies = self.servies.saturating_add(1);
        if status.class() >= 4 {
            self.refusees = self.refusees.saturating_add(1);
        }

        // **`HEAD` REND LES MÊMES CHAMPS, ET PAS DE CORPS** (§9.3.2 de
        // RFC 9110). Le rendre plus court ferait deviner la taille de ce qu'on
        // refusait de rendre ; le rendre entier serait un envoi pour rien.
        let sans_corps = matches!(tete.method(), Method::Head);
        composer(status, media, a_ecrire, sans_corps, sortie)
    }
}

/// Recopie la réponse dans le tampon de sortie, et la décrit.
///
/// # POURQUOI RECOPIER
///
/// Ce qu'on vient de décider vit dans les tampons du service, que le conducteur
/// ne voit pas. `sortie` est le seul endroit dont la durée de vie convienne à la
/// réponse qu'on rend — et l'y écrire est ce qui permet de la référencer sans
/// la tenir deux fois.
fn composer<'o>(
    status: StatusCode,
    media: &'static str,
    corps: &[u8],
    sans_corps: bool,
    sortie: &'o mut [u8],
) -> Reponse<'o> {
    // §8.6 de RFC 9110 : `content-length` décrit ce que le corps AURAIT, même
    // pour une réponse à `HEAD` qui n'en porte pas.
    let annonce = corps.len();
    let combien = match sans_corps {
        true => 0,
        false => corps.len().min(sortie.len()),
    };
    sortie
        .get_mut(..combien)
        .unwrap_or_default()
        .copy_from_slice(corps.get(..combien).unwrap_or_default());

    // Les chiffres de la longueur vont derrière le corps, dans le même tampon :
    // ils doivent vivre aussi longtemps que la réponse.
    let mut chiffres = [0_u8; 20];
    let ecrits = ecrire_un_nombre(annonce, &mut chiffres);
    let apres = combien.saturating_add(ecrits);
    if apres <= sortie.len() {
        sortie
            .get_mut(combien..apres)
            .unwrap_or_default()
            .copy_from_slice(chiffres.get(..ecrits).unwrap_or_default());
    }

    let (corps_rendu, reste) = sortie.split_at_mut(combien);
    let longueur = reste.get(..ecrits).unwrap_or_default();
    Reponse::new(status, corps_rendu)
        .avec_champ(b"content-type", media.as_bytes())
        .avec_champ(b"content-length", longueur)
}

/// Écrit ce nombre en chiffres décimaux, et rend combien.
fn ecrire_un_nombre(mut valeur: usize, out: &mut [u8; 20]) -> usize {
    if valeur == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut chiffres = [0_u8; 20];
    let mut combien = 0_usize;
    while valeur > 0 {
        chiffres[combien] = b'0'.saturating_add(u8::try_from(valeur % 10).unwrap_or(0));
        valeur /= 10;
        combien = combien.saturating_add(1);
    }
    for rang in 0..combien {
        out[rang] = chiffres[combien.saturating_sub(rang).saturating_sub(1)];
    }
    combien
}

/// HTTP/3 branché sur l'écoute QUIC.
///
/// # UN CONDUCTEUR PAR CONNEXION, ET UNE SEULE APPLICATION
///
/// L'écoute ne tient qu'une application pour toutes ses connexions : c'est donc
/// à celle-ci de savoir laquelle parle. Elle les range par l'identifiant que NOUS
/// avons distribué — le seul qui ne change pas tant que la connexion vit, et le
/// seul qu'un pair ne choisit pas.
pub struct Http3Application<'a, A: Api> {
    /// Ce qui sert les requêtes.
    service: ServiceH3<'a, A>,
    /// Un conducteur par connexion vivante.
    conducteurs: HashMap<Vec<u8>, Http3>,
    /// Combien de connexions ont parlé HTTP/3.
    pub connexions: u64,
}

impl<'a, A: Api> Http3Application<'a, A> {
    /// Une application qui sert HTTP/3 avec cette session et cette API.
    pub fn new(session: &'a Http, api: &'a A, guard: &'a SharedGuard) -> Self {
        Self {
            service: ServiceH3::new(session, api, guard),
            conducteurs: HashMap::new(),
            connexions: 0,
        }
    }

    /// Combien de requêtes ont été servies, et combien refusées.
    #[must_use]
    pub const fn comptes(&self) -> (u64, u64) {
        (self.service.servies, self.service.refusees)
    }

    /// Ferme cette connexion sur une faute d'HTTP/3.
    ///
    /// §8.1 : le code applicatif dit au pair ce qu'il a fait de travers. Sans
    /// lui, il attendrait son délai d'inactivité sans savoir pourquoi.
    fn condamner(connexion: &mut Connection, faute: &ams_h3::Error) {
        connexion.close_with(faute.close_code(), crate::http::maintenant());
    }
}

impl<A: Api> crate::quic::Application for Http3Application<'_, A> {
    fn on_established(&mut self, connexion: &mut Connection, _pair: Source) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let conducteur = self.conducteurs.entry(clef).or_default();
        self.connexions = self.connexions.saturating_add(1);
        // §6.2.1 : notre flux de contrôle et nos réglages, tout de suite — puis
        // les deux flux QPACK de §4.2 de RFC 9204.
        if let Err(faute) = conducteur.on_established(&mut Pont(connexion)) {
            Self::condamner(connexion, &faute);
        }
    }

    fn on_readable(&mut self, connexion: &mut Connection, flux: StreamId, pair: Source) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let Some(conducteur) = self.conducteurs.get_mut(&clef) else {
            return;
        };
        // **C'EST ICI QUE LA SOURCE ENTRE**, et à chaque requête : un service
        // sert plusieurs connexions, et la poser une fois pour toutes ferait
        // compter tous les refus contre la première adresse qui a parlé.
        self.service.pour(pair);
        if let Err(faute) = conducteur.on_readable(&mut Pont(connexion), &mut self.service, flux) {
            Self::condamner(connexion, &faute);
        }
    }

    fn on_shutdown(&mut self, connexion: &mut Connection, _pair: Source) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let Some(conducteur) = self.conducteurs.get_mut(&clef) else {
            return;
        };
        // §5.2, premier temps : l'identifiant maximal. Il dit « n'ouvre plus
        // rien » sans condamner une seule requête déjà en vol.
        if let Err(faute) = conducteur.shutdown(&mut Pont(connexion)) {
            Self::condamner(connexion, &faute);
        }
    }

    fn on_drained(&mut self, connexion: &mut Connection, _pair: Source) {
        let clef = connexion.local_id().as_bytes().to_vec();
        let Some(conducteur) = self.conducteurs.get_mut(&clef) else {
            return;
        };
        // §5.2, second temps : le rang qui suit la dernière requête servie. Au-delà,
        // le client sait que rien n'a été fait, et peut rejouer ailleurs.
        if let Err(faute) = conducteur.drain(&mut Pont(connexion)) {
            Self::condamner(connexion, &faute);
        }
    }

    /// §5.2 : « H3_NO_ERROR » — on s'en va, et tout s'est bien passé. Fermer avec
    /// autre chose ferait chercher au client une faute qui n'existe pas.
    fn closing_code(&self) -> u64 {
        ams_h3::NO_ERROR
    }

    fn on_closed(&mut self, connexion: &Connection, _pair: Source) {
        // Ce qu'on tenait pour cette connexion ne sert plus : les tampons de ses
        // flux, et son état HTTP/3.
        self.conducteurs.remove(connexion.local_id().as_bytes());
    }
}
