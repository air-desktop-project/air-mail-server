//! MTA-STS (RFC 8461) : aller chercher la politique, et la garder.
//!
//! # CE QUE CE MODULE FAIT, ET CE QU'IL NE DÉCIDE PAS
//!
//! Il résout, il ouvre une connexion, il écrit et il lit des fichiers — c'est
//! l'étage 3. Ce qu'il ne décide pas : ce qu'une politique dit, ce qu'un joker
//! couvre, et jusqu'à quand un cache vaut. Tout cela vit dans `ams-mtasts`, qui
//! est couvert à 100 % parce qu'une lecture qui se trompe ici FAIT PARTIR DU
//! COURRIER EN CLAIR — ou l'empêche de partir.
//!
//! # TROIS REFUS QUI FONT TOUTE LA VALEUR DE CE MODULE
//!
//! 1. **Aucune redirection n'est suivie** (§3.3). Un `301` vers un autre hôte
//!    ferait chercher la politique ailleurs que là où le domaine l'a publiée —
//!    c'est-à-dire là où l'attaquant l'aura mise.
//! 2. **Le certificat de `mta-sts.<domaine>` est vérifié ORDINAIREMENT**, contre
//!    les autorités que l'exploitant a nommées. C'est toute la chaîne de
//!    confiance de MTA-STS : sans elle, la politique n'est qu'un texte que
//!    n'importe qui aurait écrit.
//! 3. **Le cache ne se périme QUE par le temps.** Ni un `TXT` disparu, ni un
//!    `https://` injoignable ne le retirent : §5 en fait la protection contre le
//!    déclassement, et un attaquant qui peut couper le réseau obtiendrait sinon
//!    une remise sans politique.
//!
//! # UNE LIMITE ASSUMÉE : TLS 1.3 SEUL (C4, C6)
//!
//! L'hôte de politique est joint en TLS 1.3, comme tout le reste de ce serveur.
//! **Un domaine dont cet hôte ne sait faire que TLS 1.2 ne sera donc pas lu**,
//! et sa remise retombera sur le chiffrement opportuniste. Ce n'est pas une
//! faille — on ne prétend rien qu'on n'a pas — mais c'est une protection qu'on
//! n'obtient pas, et cela vaut d'être écrit plutôt que découvert.

use core::time::Duration;
use std::path::{Path, PathBuf};
use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use ams_mtasts::{
    Entry, HOST_PREFIX, NAME_MAX, POLICY_PATH, TXT_PREFIX, parse_id, parse_name, write_name,
};
use ams_proto_http::{Body, StatusCode, parse_response};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::resolver::{Resolver, Txt};

/// Le port de l'hôte de politique.
const HTTPS_PORT: u16 = 443;

/// Ce qu'une tête de réponse peut peser.
const HEAD_MAX: usize = 8 * 1024;

/// Ce qu'une politique peut peser.
///
/// **C'EST UNE BORNE DE C3.** Le fichier vient d'un serveur qu'on ne choisit
/// pas ; sans borne, il dicterait combien de mémoire on lui consacre. Les plus
/// bavardes des politiques réelles tiennent en quelques centaines d'octets.
const POLICY_MAX: usize = 64 * 1024;

/// Une politique retrouvée dans le cache, et encore fraîche.
///
/// **LES DEUX CHAÎNES SE POSSÈDENT.** `ams_mtasts::Entry` emprunte le nom de
/// fichier, qui ne survit pas au parcours du répertoire ; le faire durer
/// demanderait de faire fuir la mémoire à chaque lecture du cache — c'est-à-dire
/// à chaque remise.
#[derive(Debug, Clone)]
struct EnCache {
    /// L'identifiant que le `TXT` portait quand on l'a récupérée.
    id: String,
    /// La politique, telle qu'elle a été servie.
    texte: String,
}

/// Ce que MTA-STS sait faire pour un domaine.
#[derive(Debug, Clone)]
pub struct Sts {
    resolveur: Resolver,
    /// De quoi vérifier `mta-sts.<domaine>` ET le serveur qu'elle désigne.
    tls: Arc<rustls::ClientConfig>,
    /// Où les politiques récupérées sont gardées.
    cache: PathBuf,
    /// Le temps accordé à chaque lecture.
    delai: Duration,
}

impl Sts {
    /// Prépare l'évaluation de MTA-STS.
    #[must_use]
    pub fn new(
        resolveur: Resolver,
        tls: Arc<rustls::ClientConfig>,
        cache: PathBuf,
        delai: Duration,
    ) -> Self {
        Self {
            resolveur,
            tls,
            cache,
            delai,
        }
    }

    /// La configuration TLS qui vérifie ORDINAIREMENT le pair.
    ///
    /// C'est celle qui sert à remettre le courrier au serveur qu'une politique
    /// `enforce` désigne : chaîne, nom et dates, comme un navigateur.
    #[must_use]
    pub fn tls(&self) -> &Arc<rustls::ClientConfig> {
        &self.tls
    }

    /// Le dossier du cache.
    #[must_use]
    pub fn cache(&self) -> &Path {
        &self.cache
    }

    /// La politique de ce domaine, telle qu'elle doit s'appliquer maintenant.
    ///
    /// Rend le TEXTE de la politique ; c'est à l'appelant de la lire, parce que
    /// `ams_mtasts::Policy` emprunte ce texte et ne peut donc pas le traverser.
    ///
    /// `None` veut dire « aucune politique » : la remise est alors ce qu'elle
    /// était — DANE si le domaine publie un `TLSA`, opportuniste sinon.
    pub async fn policy_for(&self, domaine: &str, now: u64) -> Option<String> {
        // ── Ce qu'on a déjà, et jusqu'à quand ───────────────────────────────
        let en_cache = self.relire(domaine, now).await;

        // ── Ce que le DNS dit de la version ─────────────────────────────────
        //
        // **ON NE DEMANDE PAS LE BIT `AD`.** Cet identifiant ne dit pas ce
        // qu'EST la politique — cela, c'est le `https://` vérifié qui le dit —
        // il dit seulement qu'elle a CHANGÉ.
        let nom = std::format!("{TXT_PREFIX}{domaine}");
        let identifiant = match self.resolveur.txt(nom.as_bytes()).await {
            Txt::Trouves(chaines) => chaines
                .iter()
                .filter_map(|octets| core::str::from_utf8(octets).ok())
                .find_map(parse_id)
                .map(String::from),
            Txt::Absent | Txt::Panne => None,
        };

        // **UNE POLITIQUE EN CACHE ET ENCORE FRAÎCHE SUFFIT**, si le `TXT` ne
        // dit pas qu'elle a changé. Il dit « rien » quand il a disparu ou qu'on
        // n'a pas su le lire : §5 veut alors qu'on garde ce qu'on a.
        if let Some(deja) = &en_cache
            && identifiant.as_deref().is_none_or(|neuf| neuf == deja.id)
        {
            return Some(deja.texte.clone());
        }

        // ── Aller la chercher ───────────────────────────────────────────────
        let neuve = self.recuperer(domaine).await;
        match (neuve, en_cache) {
            (Some(texte), _) => {
                // Sans identifiant, on garde tout de même : la politique porte
                // sa propre durée, et la reprendre à chaque remise coûterait
                // une connexion HTTPS par message.
                let id = identifiant.as_deref().unwrap_or("0");
                self.garder(domaine, id, &texte, now).await;
                Some(texte)
            }
            // **L'ÉCHEC DE RÉCUPÉRATION NE DÉCLASSE PAS.** On garde ce qu'on
            // avait tant qu'il est frais, même si le `TXT` annonçait autre
            // chose : un attaquant qui bloque le `https://` obtiendrait sinon
            // exactement ce que MTA-STS existe pour empêcher.
            (None, Some(deja)) => Some(deja.texte),
            (None, None) => None,
        }
    }

    /// Va chercher la politique en HTTPS.
    async fn recuperer(&self, domaine: &str) -> Option<String> {
        let hote = std::format!("{HOST_PREFIX}{domaine}");
        let nom = ServerName::try_from(hote.clone()).ok()?;
        let adresse = self
            .resolveur
            .addresses(hote.as_bytes())
            .await
            .into_iter()
            .next()?;

        let flux = timeout(
            self.delai,
            TcpStream::connect(std::net::SocketAddr::new(adresse, HTTPS_PORT)),
        )
        .await
        .ok()?
        .ok()?;
        let connecteur = TlsConnector::from(Arc::clone(&self.tls));
        // **C'EST ICI QUE TOUTE LA CONFIANCE SE JOUE.** Le certificat est
        // vérifié contre les autorités que l'exploitant a nommées, et pour CE
        // nom-là : sans cela, la politique n'est qu'un texte que n'importe qui
        // aurait écrit.
        let mut chiffre = timeout(self.delai, connecteur.connect(nom, flux))
            .await
            .ok()?
            .ok()?;

        let requete = std::format!(
            "GET {POLICY_PATH} HTTP/1.1\r\nHost: {hote}\r\nConnection: close\r\n\
             User-Agent: air-mail-server\r\n\r\n"
        );
        timeout(self.delai, chiffre.write_all(requete.as_bytes()))
            .await
            .ok()?
            .ok()?;
        timeout(self.delai, chiffre.flush()).await.ok()?.ok()?;

        let recu = self.lire_tout(&mut chiffre).await?;
        let tete = parse_response(&recu, HEAD_MAX).ok()??;
        // **AUCUNE REDIRECTION N'EST SUIVIE** (§3.3), et rien d'autre qu'un
        // `200` ne porte une politique. Un `301` vers un autre hôte ferait
        // chercher la politique là où l'attaquant l'aura mise.
        if tete.status() != StatusCode::OK {
            return None;
        }
        let corps = recu.get(tete.length()..).unwrap_or_default();
        let corps = match tete.body() {
            Body::Length(combien) => {
                let combien = usize::try_from(combien).unwrap_or(usize::MAX);
                // **UN CORPS PLUS COURT QUE SA LONGUEUR EST TRONQUÉ**, et une
                // politique tronquée dirait autre chose que ce que le domaine a
                // publié.
                corps.get(..combien)?
            }
            Body::UntilClose => corps,
            // On a demandé `Connection: close` ; un serveur qui découpe tout de
            // même n'est pas lu, faute d'un défaiseur qu'on n'exercerait qu'ici.
            // C'est écrit dans le registre, et la remise retombe alors sur ce
            // qu'elle était.
            Body::Chunked => return None,
        };
        String::from_utf8(corps.to_vec()).ok()
    }

    /// Lit jusqu'à la fermeture, en bornant.
    async fn lire_tout<S>(&self, flux: &mut S) -> Option<Vec<u8>>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut recu = Vec::new();
        let mut morceau = [0_u8; 4096];
        loop {
            let lus = timeout(self.delai, flux.read(&mut morceau))
                .await
                .ok()?
                .ok()?;
            if lus == 0 {
                return Some(recu);
            }
            recu.extend_from_slice(morceau.get(..lus).unwrap_or_default());
            // **ON REFUSE AU LIEU DE TRONQUER.** Une politique tronquée dirait
            // autre chose que ce que le domaine a publié, et pourrait par
            // exemple perdre un `mx`.
            if recu.len() > HEAD_MAX.saturating_add(POLICY_MAX) {
                return None;
            }
        }
    }

    /// Ce que le cache porte pour ce domaine, s'il est encore frais.
    ///
    /// **La fraîcheur se juge sur le `max_age` de la politique elle-même**, et
    /// non sur une durée qu'on aurait choisie : c'est le domaine qui dit combien
    /// de temps sa parole vaut.
    async fn relire(&self, domaine: &str, now: u64) -> Option<EnCache> {
        let mut dossier = tokio::fs::read_dir(&self.cache).await.ok()?;
        let mut trouvee = None;
        while let Ok(Some(entree)) = dossier.next_entry().await {
            let nom = entree.file_name();
            let Some(nom) = nom.to_str() else {
                continue;
            };
            let Some(part) = parse_name(nom) else {
                continue;
            };
            if part.domain != domaine {
                continue;
            }
            let Ok(texte) = tokio::fs::read_to_string(entree.path()).await else {
                continue;
            };
            let mut place = [""; ams_mtasts::MX_MAX];
            let Ok(politique) = ams_mtasts::parse_policy(&texte, &mut place) else {
                // Une politique en cache qu'on ne sait plus lire ne vaut rien.
                let _ = tokio::fs::remove_file(entree.path()).await;
                continue;
            };
            if !part.fresh(politique.max_age(), now) {
                // **PÉRIMÉE, DONC EFFACÉE** : la garder ferait croître le cache
                // sans fin, et §5 ne lui accorde rien au-delà de `max_age`.
                let _ = tokio::fs::remove_file(entree.path()).await;
                continue;
            }
            trouvee = Some(EnCache {
                id: String::from(part.id),
                texte,
            });
        }
        trouvee
    }

    /// Garde cette politique, et retire celle qu'elle remplace.
    async fn garder(&self, domaine: &str, id: &str, texte: &str, now: u64) {
        // On efface d'abord : deux politiques d'un même domaine dans le cache
        // laisseraient la relecture prendre celle qui traîne.
        self.oublier(domaine).await;
        let entree = Entry {
            fetched: now,
            id,
            domain: domaine,
        };
        let mut place = [0_u8; NAME_MAX];
        let Ok(nom) = write_name(&entree, &mut place) else {
            return;
        };
        let _ = poser(&self.cache.join(nom), texte.as_bytes());
    }

    /// Retire du cache tout ce qui concerne ce domaine.
    async fn oublier(&self, domaine: &str) {
        let Ok(mut dossier) = tokio::fs::read_dir(&self.cache).await else {
            return;
        };
        while let Ok(Some(entree)) = dossier.next_entry().await {
            let nom = entree.file_name();
            if let Some(nom) = nom.to_str()
                && let Some(part) = parse_name(nom)
                && part.domain == domaine
            {
                let _ = tokio::fs::remove_file(entree.path()).await;
            }
        }
    }
}

/// Écrit `contenu` dans `chemin`, ATOMIQUEMENT.
///
/// La même discipline que la file : un temporaire dans LE MÊME dossier, puis
/// `sync_all`, puis le renommage. Un lecteur ne voit jamais un fichier à moitié
/// écrit.
fn poser(chemin: &Path, contenu: &[u8]) -> Result<(), ()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut temporaire = chemin.to_path_buf().into_os_string();
    temporaire.push(".tmp");
    let temporaire = PathBuf::from(temporaire);
    let ecriture = (|| -> std::io::Result<()> {
        let mut fichier = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporaire)?;
        fichier.write_all(contenu)?;
        fichier.sync_all()?;
        drop(fichier);
        std::fs::rename(&temporaire, chemin)?;
        if let Some(parent) = chemin.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if ecriture.is_err() {
        let _ = std::fs::remove_file(&temporaire);
        return Err(());
    }
    Ok(())
}
