// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'écoute HTTP/2 : **la seule pièce de l'API qui touche au réseau**.
//!
//! # IL N'Y A PAS DE HTTP EN CLAIR ICI, ET CE N'EST PAS UN RÉGLAGE
//!
//! SMTP, POP3 et IMAP montent en TLS par `STARTTLS`, et servent en clair quand
//! aucun certificat n'est nommé. Cette écoute-ci ne le peut pas : elle porte des
//! jetons porteurs, et un jeton qui traverse un réseau en clair est un jeton
//! volé. La configuration TLS n'est donc **pas** un `Option` — sans certificat,
//! il n'y a pas d'écoute HTTP du tout (C4).
//!
//! # ET L'ALPN N'EST PAS UNE COMMODITÉ
//!
//! §3.4 de RFC 9113 : un client qui veut parler HTTP/2 sur TLS l'annonce par
//! ALPN. Ce serveur n'annonce que `h2` — un client qui n'offre que `http/1.1`
//! voit sa poignée de main échouer, plutôt que d'être accepté puis refusé.
//!
//! **C'est le bon endroit pour dire non.** Refuser après la poignée de main
//! obligerait à répondre quelque chose, et ce quelque chose serait de
//! l'HTTP/1.1 — c'est-à-dire le cadrage qu'on refuse justement de lire (C6).
//!
//! # UNE REQUÊTE À LA FOIS, ET C'EST ANNONCÉ
//!
//! Nos réglages disent `SETTINGS_MAX_CONCURRENT_STREAMS = 1`. HTTP/2 permet
//! d'entrelacer, et un serveur qui en tire parti sert plus vite ; mais entrelacer
//! demande de retenir autant de requêtes à demi lues que de flux ouverts, donc de
//! laisser le pair décider combien de mémoire on garde.
//!
//! C7 tranche : la sécurité avant la vitesse. **Le pair sait à quoi s'en tenir**,
//! puisqu'il reçoit le réglage avant sa première requête.
//!
//! # CE QUE CETTE ÉCOUTE NE FAIT PAS
//!
//! Elle ne sait rien des boîtes. Le contenu des réponses vient d'un [`Api`] que
//! l'appelant fournit : c'est lui qui lit le magasin et qui met en forme. La
//! boucle conduit HTTP/2, vérifie qui parle, et écoule des octets.

use core::future::Future;
use std::sync::Arc;

use ams_api::{JSON_MEDIA_TYPE, PROBLEM_MEDIA_TYPE, Resource, Scope};
use ams_guard::{Event as GuardEvent, Source, Verdict};
use ams_proto_h2::{
    Connection, ErrorCode, Event, FRAME_HEADER_OCTETS, FrameReader, Handshake, Need, PREFACE,
    Settings as H2Settings,
};
use ams_proto_http::{Limits, Method, RequestHead, StatusCode};
use ams_session::http::{BODY_OCTETS_MAX, Http, Next, SCRATCH_OCTETS_MIN};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

use crate::connection::Timeouts;
use crate::error::Error;
use crate::guard::SharedGuard;

/// Ce que le tampon de lecture peut retenir.
///
/// Il doit porter le plus grand cadre qu'on accepte, en-tête compris, plus ce
/// qui suit. Nos réglages bornent la taille d'un cadre à seize kibioctets.
const LECTURE_OCTETS: usize = 64 * 1024;

/// Ce que le tampon d'écriture peut porter.
const ECRITURE_OCTETS: usize = 128 * 1024;

/// Ce que le tampon de travail de la session peut porter.
const TRAVAIL_OCTETS: usize = SCRATCH_OCTETS_MIN + 64 * 1024;

/// Ce qu'un bloc d'en-têtes décomprimé peut occuper.
const ENTETES_OCTETS: usize = 16 * 1024;

/// Ce qu'une réponse servie peut porter.
const RENDU_OCTETS: usize = 256 * 1024;

/// Combien de champs une réponse porte au plus, `content-type` compris.
const CHAMPS_MAX: usize = ams_session::http::FIELDS_MAX + 1;

/// Assemble la configuration TLS d'une écoute HTTP/2.
///
/// C'est [`ams_tls::server_config`], plus la seule liste ALPN qu'`ams-tls`
/// sanctionne.
///
/// # POURQUOI L'ASSEMBLAGE VIT ICI ET NON DANS `ams-tls`
///
/// Poser cette liste demande une configuration, donc un certificat — que
/// `ams-tls` ne peut pas fabriquer sans matériel, et qu'on ne versionne pas. Le
/// seuil de couverture ne lançant que les essais des crates du périmètre, une
/// ligne d'assemblage posée là-bas ne serait couverte que par un essai qui n'y
/// compte pas.
///
/// Ici, en revanche, un essai d'intégration fabrique un certificat à la volée et
/// s'en sert vraiment.
///
/// # Errors
///
/// Les mêmes que [`ams_tls::server_config`] : chaîne illisible ou vide, clé
/// illisible, ou clé qui ne correspond pas au certificat de tête.
pub fn http_server_config(
    chain_pem: &[u8],
    key_pem: &[u8],
) -> Result<ServerConfig, ams_tls::MaterialError> {
    let mut config = ams_tls::server_config(chain_pem, key_pem)?;
    config.alpn_protocols = ams_tls::alpn();
    Ok(config)
}

/// Ce qu'une réponse servie porte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Served<'o> {
    /// Le code d'état.
    pub status: StatusCode,
    /// Le type de média du corps.
    pub media: &'static str,
    /// Le corps.
    pub body: &'o [u8],
    /// Cette ressource se lit-elle par morceaux (§14.3 de RFC 9110) ?
    ///
    /// **C'EST UNE INVITATION, PAS UN ÉTAT** : elle fait écrire
    /// `Accept-Ranges: bytes`, qui dit au client qu'il PEUT demander une portée.
    /// Sans elle, un client devant une représentation trop grande n'aurait aucun
    /// moyen de savoir qu'une porte existe.
    pub ranges: bool,
    /// Ce que ce corps couvre, s'il n'est qu'un morceau (§14.4).
    ///
    /// Sa présence fait écrire `Content-Range` — **et c'est ce champ, et lui
    /// seul, qui dit quels octets partent**. Un `206` sans lui laisserait le
    /// client deviner, et deviner faux d'un octet ne se voit qu'à la fin.
    pub range: Option<ContentRange>,
}

/// Ce qu'un corps partiel couvre de la représentation (§14.4 de RFC 9110).
///
/// # POURQUOI C'EST TYPÉ, ET NON UN CHAMP DE PLUS À ÉCRIRE
///
/// Ouvrir cette interface à des champs de réponse quelconques laisserait une API
/// poser ce qui contredit ce que la boucle garantit — `cache-control: no-store`,
/// `nosniff`. Le contrat gagne donc le CONCEPT dont il a besoin, et chaque boucle
/// l'écrit à sa façon : aucune n'apprend un en-tête nouveau.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange {
    /// Les octets que ce corps couvre, bornes comprises.
    ///
    /// **`None` EST LA FORME `*` DE §14.4**, et elle a son emploi : un `416` doit
    /// dire la taille de la représentation SANS désigner de portée — c'est
    /// exactement ce qui permet au client de recommencer sans deviner.
    pub part: Option<(u64, u64)>,
    /// La taille de la représentation entière.
    pub complete: u64,
}

impl ContentRange {
    /// Écrit `bytes <first>-<last>/<complete>`, ou `bytes */<complete>` (§14.4).
    ///
    /// Rend ce que cela occupe.
    ///
    /// # LES TROIS NOMBRES TIENNENT, ET LE TAMPON EST LE NÔTRE
    ///
    /// Trois entiers de soixante-quatre bits font au plus vingt chiffres chacun ;
    /// avec `bytes `, deux séparateurs, cela tient dans [`CONTENT_RANGE_MAX`].
    /// C'est notre tampon, pas celui d'un pair : un `expect` ici dirait une faute
    /// de notre code, et il n'y en a pas.
    #[must_use]
    pub fn write(&self, out: &mut [u8; CONTENT_RANGE_MAX]) -> usize {
        use core::fmt::Write as _;
        let mut plume = Plume { out, ecrits: 0 };
        let _ = match self.part {
            Some((first, last)) => write!(plume, "bytes {first}-{last}/{}", self.complete),
            None => write!(plume, "bytes */{}", self.complete),
        };
        plume.ecrits
    }
}

/// Ce que `bytes <u64>-<u64>/<u64>` peut occuper.
pub const CONTENT_RANGE_MAX: usize = 6 + 20 + 1 + 20 + 1 + 20;

/// De quoi écrire dans un tableau de taille fixe.
struct Plume<'a> {
    /// Où l'on écrit.
    out: &'a mut [u8; CONTENT_RANGE_MAX],
    /// Combien on a écrit.
    ecrits: usize,
}

impl core::fmt::Write for Plume<'_> {
    fn write_str(&mut self, texte: &str) -> core::fmt::Result {
        for octet in texte.as_bytes() {
            let place = self.out.get_mut(self.ecrits).ok_or(core::fmt::Error)?;
            *place = *octet;
            self.ecrits = self.ecrits.saturating_add(1);
        }
        Ok(())
    }
}

impl Default for Served<'_> {
    fn default() -> Self {
        Self {
            status: StatusCode::OK,
            media: JSON_MEDIA_TYPE,
            body: &[],
            ranges: false,
            range: None,
        }
    }
}

/// Ce qui sait servir les ressources de l'API.
///
/// # LA BOUCLE CONDUIT, CETTE INTERFACE RÉPOND
///
/// Tout ce qui touche au magasin vit derrière ceci : la boucle n'ouvre aucune
/// boîte et ne connaît aucun compte. C'est la même séparation qu'entre une
/// session et sa politique, et pour la même raison — ce qui décide et ce qui
/// exécute ne se vérifient pas de la même façon.
pub trait Api {
    /// Sert cette ressource, et écrit la réponse dans `sortie`.
    ///
    /// `range` porte le champ `Range` **tel que le client l'a écrit** (§14.2 de
    /// RFC 9110), sans analyse : ce qu'une portée a le droit d'être dépend de la
    /// RESSOURCE — de sa taille, et de si elle se lit par morceaux —, et la
    /// boucle ne sait ni l'un ni l'autre.
    ///
    /// L'autorisation est **déjà faite** : recevoir cet appel veut dire qu'un
    /// jeton scellé par notre clé, non expiré, ouvrait la portée que la route
    /// exige. Cette interface n'a donc rien à revérifier, et rien à décider sur
    /// l'identité de qui appelle.
    fn serve<'o>(
        &self,
        resource: Resource<'_>,
        method: Method,
        account: &str,
        body: &[u8],
        range: Option<&[u8]>,
        sortie: &'o mut [u8],
    ) -> Served<'o>;

    /// Ces identifiants ouvrent-ils une session, et sur quelle portée ?
    ///
    /// `None` refuse. **LE TEMPS QUE PREND UN REFUS NE DOIT PAS DIRE POURQUOI IL
    /// REFUSE** : un compte absent doit coûter le même travail qu'un mot de passe
    /// faux, comme `ams_auth::authenticate` le fait déjà pour SMTP.
    fn authenticate(&self, login: &str, password: &[u8]) -> Option<Scope>;

    /// Un identifiant qui distingue ce jeton des autres du même compte.
    ///
    /// **SANS LUI, RÉVOQUER UN JETON REVIENDRAIT À RÉVOQUER LE COMPTE.** Il doit
    /// être imprévisible : la boucle ne le fabrique pas, parce qu'une source
    /// d'aléa est une dépendance, et que les dépendances entrent par l'appelant.
    fn nonce(&self) -> u64;
}

/// Ce qu'une connexion a fait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HttpSummary {
    /// Combien de requêtes ont été servies.
    pub requests: u64,
    /// Combien ont reçu un refus.
    pub refused: u64,
    /// La poignée de main TLS a-t-elle abouti ?
    pub tls: bool,
}

/// Ce qu'il faut pour conduire une connexion.
pub struct HttpService<'a> {
    /// Les bornes de la sémantique HTTP.
    pub limits: Limits,
    /// Le videur (C8).
    pub guard: &'a SharedGuard,
    /// Les délais.
    pub timeouts: Timeouts,
    /// La configuration TLS. **Elle n'est pas facultative.**
    pub tls: Arc<ServerConfig>,
    /// La session qui décide.
    pub session: Http,
}

/// Conduit une connexion HTTP/2 de bout en bout.
///
/// # Errors
///
/// Toute faute d'entrée-sortie, la poignée de main TLS qui échoue, un pair qui
/// n'annonce pas `h2`, ou un pair qui parle mal.
pub async fn serve_http_connection<S, A>(
    flux: S,
    service: &HttpService<'_>,
    api: &A,
    source: Source,
    maintenant: u64,
) -> Result<HttpSummary, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Api,
{
    let mut resume = HttpSummary::default();
    // **LE VIDEUR PARLE AVANT LA POIGNÉE DE MAIN** (C8) : chiffrer pour une
    // source bannie coûte un échange de clés, ce qu'un attaquant obtiendrait
    // gratuitement.
    if matches!(service.guard.verdict(source), Verdict::Banned { .. }) {
        return Err(Error::Refused);
    }
    let _ = service.guard.observe(source, GuardEvent::Connection);

    let accepteur = TlsAcceptor::from(Arc::clone(&service.tls));
    let mut chiffre = tokio::time::timeout(service.timeouts.handshake, accepteur.accept(flux))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)?;
    resume.tls = true;

    // **L'ALPN SE VÉRIFIE, MÊME QUAND ON N'ANNONCE QUE `h2`.** Un client qui
    // n'envoie aucune extension ALPN négocie « rien » sans que la poignée de main
    // échoue, et §3.4 de RFC 9113 en fait une faute.
    let parle_h2 = chiffre
        .get_ref()
        .1
        .alpn_protocol()
        .is_some_and(|dit| dit == b"h2");
    if !parle_h2 {
        service.guard.observe(source, GuardEvent::InvalidFrame);
        let _ = chiffre.shutdown().await;
        return Err(Error::Alpn);
    }

    let issue = conduire(&mut chiffre, service, api, source, maintenant, &mut resume).await;
    // On ferme proprement quoi qu'il arrive : un `close_notify` manquant fait
    // croire au pair à une troncature.
    let _ = chiffre.shutdown().await;
    issue.map(|()| resume)
}

/// La boucle d'une connexion déjà chiffrée.
async fn conduire<S, A>(
    flux: &mut S,
    service: &HttpService<'_>,
    api: &A,
    source: Source,
    maintenant: u64,
    resume: &mut HttpSummary,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Api,
{
    let mut lecture = std::vec![0_u8; LECTURE_OCTETS];
    let mut remplis = 0_usize;
    let mut ecriture = std::vec![0_u8; ECRITURE_OCTETS];
    let mut entetes = std::vec![0_u8; ENTETES_OCTETS];
    let mut tete_place = std::vec![0_u8; ENTETES_OCTETS];
    let mut corps = std::vec![0_u8; BODY_OCTETS_MAX];
    let mut travail = std::vec![0_u8; TRAVAIL_OCTETS];
    let mut echange = std::vec![0_u8; TRAVAIL_OCTETS];
    let mut rendu = std::vec![0_u8; RENDU_OCTETS];

    let mut connexion = ouvrir(
        flux,
        service,
        source,
        &mut lecture,
        &mut remplis,
        &mut ecriture,
    )
    .await?;

    loop {
        let lue = lire_une_requete(
            flux,
            &mut connexion,
            service,
            source,
            &mut lecture,
            &mut remplis,
            &mut entetes,
            &mut tete_place,
            &mut corps,
            &mut ecriture,
        )
        .await?;
        let Some(demande) = lue else {
            return Ok(());
        };
        service.guard.observe(source, GuardEvent::Command);
        let corps_lu = corps.get(..demande.corps).unwrap_or_default();

        // La session décide, et ne touche à rien.
        let tour = service
            .session
            .request(&demande.tete, corps_lu, maintenant, &mut travail);
        // Ce que la ressource dit de sa divisibilité (§14 de RFC 9110). Une
        // ressource qui ne se lit pas par morceaux n'en dit rien, et c'est le cas
        // de toutes sauf deux.
        let mut portee: (bool, Option<ContentRange>) = (false, None);
        let (status, media, corps_a_ecrire) = match tour.next() {
            Next::Respond => (tour.status(), PROBLEM_MEDIA_TYPE, tour.body()),
            Next::CheckCredentials { login, password } => {
                let accorde = api.authenticate(login, password);
                let suite = service.session.on_credentials(
                    accorde.is_some(),
                    login,
                    accorde.unwrap_or_else(Scope::none),
                    api.nonce(),
                    maintenant,
                    &mut echange,
                );
                if accorde.is_none() {
                    // **UN REFUS D'IDENTIFIANTS EST UNE TRAME INVALIDE** pour le
                    // videur : c'est ce qui borne une attaque par essais.
                    service.guard.observe(source, GuardEvent::InvalidFrame);
                }
                (suite.status(), JSON_MEDIA_TYPE, suite.body())
            }
            Next::Serve {
                resource,
                method,
                account,
                body,
            } => {
                let servi = api.serve(
                    resource,
                    method,
                    account,
                    body,
                    demande.tete.field(b"range"),
                    &mut rendu,
                );
                portee = (servi.ranges, servi.range);
                (servi.status, servi.media, servi.body)
            }
        };
        if status.class() >= 4 {
            resume.refused = resume.refused.saturating_add(1);
        }
        resume.requests = resume.requests.saturating_add(1);

        // **`HEAD` REND LES MÊMES EN-TÊTES, ET PAS DE CORPS** (§9.3.2 de
        // RFC 9110). Le rendre plus court ferait deviner la taille de ce qu'on
        // refusait de rendre — mais le rendre entier serait un envoi pour rien.
        let sans_corps = matches!(demande.tete.method(), Method::Head);
        repondre(
            flux,
            &mut connexion,
            service,
            portee,
            demande.stream,
            status,
            media,
            corps_a_ecrire,
            sans_corps,
            &mut ecriture,
        )
        .await?;
    }
}

/// Une requête complète, prête à servir.
struct Demande<'t> {
    /// Le flux qui la porte.
    stream: u32,
    /// Sa tête.
    tete: RequestHead<'t>,
    /// Combien d'octets de corps sont arrivés.
    corps: usize,
}

/// Lit le préambule, envoie nos réglages, et rend la connexion.
async fn ouvrir<S>(
    flux: &mut S,
    service: &HttpService<'_>,
    source: Source,
    lecture: &mut [u8],
    remplis: &mut usize,
    ecriture: &mut [u8],
) -> Result<Connection, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let poignee = Handshake::new(reglages());
    loop {
        // **UN PRÉAMBULE QUI N'EN EST PAS UN EST UNE TRAME INVALIDE.**
        //
        // C'était la seule faute du pair que cette écoute ne comptait pas, et
        // c'est la PREMIÈRE qu'un hostile peut commettre : l'ALPN, les cadres
        // malformés, les identifiants refusés et un en-tête illisible sont tous
        // rapportés au videur, celle-ci ne l'était pas. Une source pouvait donc
        // ouvrir des connexions et envoyer n'importe quoi sans jamais franchir le
        // seuil — alors que chacune coûte une poignée de main TLS, ce que le
        // videur existe précisément pour ne pas offrir.
        //
        // **LA SOURCE EST VÉRIFIÉE ICI**, et c'est ce qui rend le décompte sûr :
        // le pair a terminé un `TCP` en trois temps puis un `TLS`. Sur QUIC,
        // compter avant la validation d'adresse laisserait usurper une source
        // pour faire bannir un tiers.
        let (peut_etre, ecrits) = poignee
            .open(lecture.get(..*remplis).unwrap_or_default(), ecriture)
            .map_err(|_| {
                service.guard.observe(source, GuardEvent::InvalidFrame);
                Error::Http
            })?;
        if let Some(connexion) = peut_etre {
            let sortie = ecriture.get(..ecrits).unwrap_or_default().to_vec();
            ecrire(flux, &sortie, service).await?;
            // Le préambule est consommé ; ce qui suit reste dans le tampon.
            consommer(lecture, remplis, PREFACE.len());
            return Ok(connexion);
        }
        let avant = *remplis;
        *remplis = remplir(flux, lecture, *remplis, service).await?;
        if *remplis == avant {
            return Err(Error::Http);
        }
    }
}

/// Lit des cadres jusqu'à ce qu'une requête soit entière.
///
/// Rend `None` quand le pair s'en va.
#[expect(
    clippy::too_many_arguments,
    reason = "chaque tampon a une durée de vie distincte, et les regrouper dans \
              une structure ne ferait que déplacer les emprunts sans les réduire."
)]
async fn lire_une_requete<'t, S>(
    flux: &mut S,
    connexion: &mut Connection,
    service: &HttpService<'_>,
    source: Source,
    lecture: &mut [u8],
    remplis: &mut usize,
    entetes: &mut [u8],
    tete_place: &'t mut [u8],
    corps: &mut [u8],
    ecriture: &mut [u8],
) -> Result<Option<Demande<'t>>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ouverte: Option<(u32, usize)> = None;
    let mut tete_lue: Option<(u32, usize)> = None;

    loop {
        let besoin = FrameReader::poll(
            lecture.get(..*remplis).unwrap_or_default(),
            connexion.settings().max_frame_size,
        );
        let entete = match besoin {
            Ok(Need::Complete(entete)) => entete,
            Ok(Need::More) => {
                let avant = *remplis;
                *remplis = remplir(flux, lecture, *remplis, service).await?;
                if *remplis == avant {
                    return Ok(None);
                }
                continue;
            }
            Err(faute) => {
                service.guard.observe(source, GuardEvent::InvalidFrame);
                return fermer(flux, connexion, ecriture, service, faute.code()).await;
            }
        };
        let total = entete.total();
        let charge = lecture
            .get(FRAME_HEADER_OCTETS..total)
            .unwrap_or_default()
            .to_vec();

        let issue = connexion.receive(entete, &charge, entetes, ecriture);
        let (evenement, ecrits) = match issue {
            Ok(rendu) => rendu,
            Err(faute) => {
                service.guard.observe(source, GuardEvent::InvalidFrame);
                return fermer(flux, connexion, ecriture, service, faute.code()).await;
            }
        };
        if ecrits > 0 {
            let sortie = ecriture.get(..ecrits).unwrap_or_default().to_vec();
            ecrire(flux, &sortie, service).await?;
        }

        let mut fini = false;
        match evenement {
            Event::Nothing => {}
            Event::Head {
                stream,
                octets,
                end_stream,
                refused,
            } => {
                // **LE BLOC SE DÉCODE MÊME QUAND LE FLUX EST REFUSÉ** : la table
                // HPACK est commune à la connexion, et sauter un bloc décalerait
                // tous les blocs suivants — le pair et nous ne liraient plus les
                // mêmes en-têtes, sans qu'un seul cadre soit fautif.
                match refused {
                    Some(_) => tete_lue = None,
                    None => {
                        tete_lue = Some((stream, octets));
                        ouverte = Some((stream, 0));
                        fini = end_stream;
                    }
                }
            }
            Event::Data {
                stream,
                payload,
                end_stream,
            } => {
                if let Some((ouvert, lu)) = ouverte.filter(|(ouvert, _)| *ouvert == stream) {
                    let apres = pousser(corps, lu, payload);
                    ouverte = Some((ouvert, apres));
                    fini = end_stream;
                }
            }
            Event::Reset { stream, .. } => {
                if ouverte.is_some_and(|(ouvert, _)| ouvert == stream) {
                    ouverte = None;
                    tete_lue = None;
                }
            }
            // §6.8 : le pair s'en va. On finit ce qui est commencé, et l'on
            // n'accepte plus rien — ici, il n'y a rien de commencé.
            Event::GoAway { .. } => return Ok(None),
        }

        consommer(lecture, remplis, total);

        if !fini {
            continue;
        }
        let (Some((stream, octets)), Some((_, lu))) = (tete_lue, ouverte) else {
            continue;
        };
        // Le bloc est encore dans `entetes` : rien ne l'a écrasé depuis, puisque
        // seul un `HEADERS` y écrit et qu'on n'en a pas relu.
        let bloc = entetes.get(..octets).unwrap_or_default().to_vec();
        let Ok(tete) = connexion.read_head(&bloc, tete_place, &service.limits) else {
            service.guard.observe(source, GuardEvent::InvalidFrame);
            // §8.1.1 : une requête malformée ne condamne que son flux.
            let ecrits = connexion
                .write_reset(stream, ErrorCode::ProtocolError, ecriture)
                .map_err(|_| Error::Http)?;
            let sortie = ecriture.get(..ecrits).unwrap_or_default().to_vec();
            ecrire(flux, &sortie, service).await?;
            return Ok(None);
        };
        return Ok(Some(Demande {
            stream,
            tete,
            corps: lu,
        }));
    }
}

/// Écrit une réponse.
#[expect(
    clippy::too_many_arguments,
    reason = "une réponse HTTP/2 demande le flux, la connexion, le service, la \
              portée, le flux visé, le code, le type, le corps, et de savoir s'il \
              faut l'écrire. Les regrouper masquerait ce que chacun décide."
)]
async fn repondre<S>(
    flux: &mut S,
    connexion: &mut Connection,
    service: &HttpService<'_>,
    portee: (bool, Option<ContentRange>),
    stream: u32,
    status: StatusCode,
    media: &str,
    corps: &[u8],
    sans_corps: bool,
    ecriture: &mut [u8],
) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    let vide = corps.is_empty() || sans_corps;
    let mut champs: std::vec::Vec<(&[u8], &[u8])> = std::vec::Vec::with_capacity(CHAMPS_MAX);
    champs.push((b"content-type", media.as_bytes()));
    // **CE QUE TOUTE RÉPONSE PORTE VIENT DE LA SESSION**, et non d'une liste
    // écrite ici. Deux listes pour une même API en ont donné deux le jour où
    // l'une a bougé : celle d'HTTP/3 ne portait ni `no-store` ni `nosniff`.
    champs.extend(
        ams_session::http::champs_de_toute_reponse(status, service.session.alt_svc())
            .into_iter()
            .flatten(),
    );
    // §14.3 : l'invitation D'ABORD — un client qui reçoit un refus doit savoir
    // qu'une porte existe, et c'est sur le refus qu'il en a le plus besoin.
    let (divisible, morceau) = portee;
    if divisible {
        champs.push((b"accept-ranges", b"bytes"));
    }
    let mut dit = [0_u8; CONTENT_RANGE_MAX];
    let dits = morceau.map_or(0, |quoi| quoi.write(&mut dit));
    if morceau.is_some() {
        champs.push((b"content-range", dit.get(..dits).unwrap_or_default()));
    }

    let ecrits = connexion
        .write_head(stream, status, &champs, vide, ecriture)
        .map_err(|_| Error::Http)?;
    let sortie = ecriture.get(..ecrits).unwrap_or_default().to_vec();
    ecrire(flux, &sortie, service).await?;
    if vide {
        connexion.response_sent();
        return Ok(());
    }

    // Le corps part par morceaux : la fenêtre du pair et la taille de cadre
    // qu'il a annoncée décident, pas nous.
    let mut reste = corps;
    while !reste.is_empty() {
        let combien = reste
            .len()
            .min(usize::try_from(connexion.peer_settings().max_frame_size).unwrap_or(usize::MAX));
        let (morceau, suite) = reste.split_at(combien);
        let dernier = suite.is_empty();
        let ecrits = connexion
            .write_data(stream, morceau, dernier, ecriture)
            .map_err(|_| Error::Http)?;
        let sortie = ecriture.get(..ecrits.0).unwrap_or_default().to_vec();
        ecrire(flux, &sortie, service).await?;
        reste = suite;
    }
    connexion.response_sent();
    Ok(())
}

/// Ajoute un morceau de corps, et rend la nouvelle longueur.
///
/// **UN CORPS QUI DÉBORDE NE SE TRONQUE PAS** : on cesse d'écrire, et la session
/// verra un corps plus court que ce que `content-length` annonçait — ce qu'elle
/// refuse. Tronquer en silence ferait agir sur ce que le client n'a pas demandé.
fn pousser(corps: &mut [u8], lu: usize, morceau: &[u8]) -> usize {
    let fin = lu.saturating_add(morceau.len());
    match corps.get_mut(lu..fin) {
        Some(place) => {
            for (ou, octet) in place.iter_mut().zip(morceau) {
                *ou = *octet;
            }
            fin
        }
        None => lu,
    }
}

/// Ôte les `combien` premiers octets du tampon.
fn consommer(tampon: &mut [u8], remplis: &mut usize, combien: usize) {
    let combien = combien.min(*remplis);
    tampon.copy_within(combien..*remplis, 0);
    *remplis = remplis.saturating_sub(combien);
}

/// Nos réglages : ce qu'on annonce au pair.
///
/// **UN SEUL FLUX À LA FOIS** : voir la documentation du module.
///
/// **ET L'ON PART DE CE QU'UN SERVEUR A LE DROIT D'ANNONCER**, non des valeurs
/// par défaut du protocole : celles-ci donnent un à `SETTINGS_ENABLE_PUSH`, qui
/// est la valeur initiale d'un CLIENT. Les reprendre telles quelles faisait
/// annoncer la poussée par ce serveur, ce que §6.5.2 interdit et qu'un client
/// conforme traite en `PROTOCOL_ERROR` — l'API n'était joignable par aucun.
fn reglages() -> H2Settings {
    let mut nous = H2Settings::DEFAULT.pour_un_serveur();
    nous.max_concurrent_streams = Some(1);
    nous
}

/// Lit davantage dans le tampon.
async fn remplir<S>(
    flux: &mut S,
    tampon: &mut [u8],
    remplis: usize,
    service: &HttpService<'_>,
) -> Result<usize, Error>
where
    S: AsyncRead + Unpin,
{
    let place = tampon.get_mut(remplis..).unwrap_or_default();
    if place.is_empty() {
        // **UN CADRE PLUS GRAND QUE LE TAMPON N'ARRIVERA JAMAIS** : nos réglages
        // bornent la taille, et le pair les a reçus avant sa première requête.
        // S'il déborde quand même, il ne parle pas le protocole qu'il a accepté.
        return Err(Error::Http);
    }
    let lus = tokio::time::timeout(service.timeouts.command, flux.read(place))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)?;
    Ok(remplis.saturating_add(lus))
}

/// Écrit tout, ou échoue.
async fn ecrire<S>(flux: &mut S, octets: &[u8], service: &HttpService<'_>) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    tokio::time::timeout(service.timeouts.data, flux.write_all(octets))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)
}

/// Dit au pair pourquoi l'on s'en va, puis s'en va.
async fn fermer<S, T>(
    flux: &mut S,
    connexion: &mut Connection,
    ecriture: &mut [u8],
    service: &HttpService<'_>,
    code: ErrorCode,
) -> Result<Option<T>, Error>
where
    S: AsyncWrite + Unpin,
{
    // §6.8 : le lui taire le laisserait chercher la faute chez lui.
    if let Ok(ecrits) = connexion.write_goaway(code, ecriture) {
        let sortie = ecriture.get(..ecrits).unwrap_or_default().to_vec();
        let _ = ecrire(flux, &sortie, service).await;
    }
    Err(Error::Http)
}

/// Sert HTTP/2 sur ce port, jusqu'à l'arrêt.
///
/// # Errors
///
/// Toute faute d'acceptation qui n'est pas propre à une connexion.
#[expect(
    clippy::too_many_arguments,
    reason = "une écoute demande son port, ses bornes, ce qui sert, le videur, \
              la session, TLS, les options et l'arrêt — chacun vient d'un \
              endroit différent de la configuration."
)]
pub async fn serve_http<A, Arret>(
    listener: tokio::net::TcpListener,
    limits: Limits,
    api: Arc<A>,
    guard: Arc<SharedGuard>,
    session: Http,
    tls: Arc<ServerConfig>,
    options: crate::ServeOptions,
    shutdown: Arret,
) -> Result<crate::Stats, Error>
where
    A: Api + Send + Sync + 'static,
    Arret: Future<Output = ()>,
{
    let places = Arc::new(tokio::sync::Semaphore::new(options.max_connections));
    let mut stats = crate::Stats::default();
    let mut arret = core::pin::pin!(shutdown);

    loop {
        let acceptee = tokio::select! {
            // `biased` : l'arrêt est examiné EN PREMIER, comme partout ailleurs
            // dans cette crate. Un serveur qu'on ne peut pas arrêter sous charge
            // est un serveur qu'on finit par tuer.
            biased;
            () = &mut arret => return Ok(stats),
            acceptee = listener.accept() => acceptee,
        };
        let (flux, pair) = match acceptee {
            Ok(connexion) => connexion,
            Err(_) => {
                stats.failed = stats.failed.saturating_add(1);
                continue;
            }
        };
        stats.accepted = stats.accepted.saturating_add(1);

        let Ok(place) = Arc::clone(&places).acquire_owned().await else {
            return Ok(stats);
        };
        let api = Arc::clone(&api);
        let guard = Arc::clone(&guard);
        let tls = Arc::clone(&tls);
        let timeouts = options.timeouts;
        let session = session.clone();

        tokio::spawn(async move {
            let service = HttpService {
                limits,
                guard: &guard,
                timeouts,
                tls,
                session,
            };
            // Le résultat n'est pas remonté : une connexion qui échoue ne regarde
            // qu'elle. Le journal viendra avec `air-log`.
            let _ =
                serve_http_connection(flux, &service, &*api, crate::source_de(pair), maintenant())
                    .await;
            drop(place);
        });
    }
}

/// L'instant présent, en microsecondes depuis l'époque.
///
/// **C'EST LE SEUL ENDROIT DE LA CHAÎNE HTTP QUI LIT UNE HORLOGE.** Tout ce qui
/// décide — la session, les jetons, l'API — le reçoit en paramètre (C1).
pub(crate) fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |depuis| {
            u64::try_from(depuis.as_micros()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    /// **CE QUE CETTE ÉCOUTE-CI MET SUR LE FIL**, et non ce qu'un décor d'essai
    /// lui souffle.
    ///
    /// L'essai qui existait pour cela vivait dans `ams-proto-h2` et relisait des
    /// réglages qu'il avait lui-même fabriqués avec `enable_push` à faux : il
    /// prouvait la fidélité de l'aller-retour, jamais la valeur que ce serveur
    /// annonce. Celle-ci était à UN, et §6.5.2 ordonne alors au client de
    /// raccrocher — l'API REST n'était joignable par aucun client conforme.
    #[test]
    fn nos_reglages_n_annoncent_pas_la_poussee() {
        let nous = super::reglages();

        assert!(
            !nous.enable_push,
            "§6.5.2 : un serveur ne dit jamais un, et tout client conforme \
             raccrocherait s'il l'entendait"
        );
        assert_eq!(
            nous.max_concurrent_streams,
            Some(1),
            "et l'on continue de n'accepter qu'un flux à la fois"
        );
    }
}
