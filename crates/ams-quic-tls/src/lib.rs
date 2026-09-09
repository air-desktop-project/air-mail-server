// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La poignée de main TLS d'une connexion QUIC — RFC 9001 §4.
//!
//! # POURQUOI UNE CRATE À ELLE SEULE
//!
//! Deux moitiés existaient déjà, et ni l'une ni l'autre ne pouvait accueillir
//! celle-ci :
//!
//! - `ams-quic` tient les règles de §4 — quels octets vont à quel niveau, ce qui
//!   se refuse entre eux. **Elle n'alloue pas**, et `rustls::quic::write_hs`
//!   demande un `Vec`.
//! - `ams-tls` rend un fournisseur capable de chiffrer un paquet QUIC. Elle
//!   décrit « TLS 1.3 : établissement et chiffrement d'enregistrements » — y
//!   loger une machine de connexion QUIC ferait mentir son manifeste.
//!
//! RFC 9001 est elle-même un document séparé de RFC 8446 et de RFC 9000, pour la
//! même raison : ce qui relie deux choses n'appartient à aucune des deux.
//!
//! # CE QUE CETTE CRATE DÉCIDE, ET QU'AUCUNE BOUCLE NE DOIT REDÉCIDER
//!
//! Elle ne fait pas d'entrée-sortie (C1). Elle décide :
//!
//! 1. **À QUEL NIVEAU CHAQUE OCTET PART.** C'est le piège de `write_hs` :
//!    les octets d'un appel partent au niveau COURANT, et le changement de clés
//!    qu'il rend ne vaut que pour les SUIVANTS. Un `ServerHello` envoyé au
//!    niveau `Handshake` serait illisible pour le client.
//! 2. **QU'UNE POIGNÉE DE MAIN SANS `h3` N'EN EST PAS UNE.** §3.1 de RFC 9114 :
//!    le protocole applicatif se choisit par ALPN, et nous n'en offrons qu'un.
//! 3. **QU'UNE ALERTE TLS DEVIENT UN CODE DE FERMETURE QUIC** (§4.8), et non une
//!    erreur qu'on avale.

#![forbid(unsafe_code)]

use std::sync::Arc;

use ams_quic::{CRYPTO_OCTETS_MAX, Handshake, Level, crypto_error};
use ams_quic_crypto::Role;
use rustls::pki_types::ServerName;
use rustls::quic::{
    ClientConnection, Connection as ConnexionTls, KeyChange, ServerConnection, Version,
};
use rustls::{ClientConfig, ServerConfig};

mod connection;
mod error;
mod keys;

pub use connection::{ACQUITTEMENT_MAX_MS, Connection, INACTIVITE_US};
pub use error::{Error, Reason};
pub use keys::Clefs;

/// La version de QUIC qu'on sert.
///
/// **UNE SEULE, ET C'EST LA 1** (RFC 9000). Les brouillons ont leur propre sel
/// initial et leurs propres étiquettes ; les servir demanderait de tenir deux
/// dérivations à jour, pour des pairs qui n'existent plus.
const VERSION: Version = Version::V1;

/// La taille d'une valeur exportée, en octets.
///
/// **Trente-deux, et ce n'est pas un réglage.** C'est la taille d'un condensat
/// SHA-256, celle qu'attend tout ce qui se sert d'un exportateur comme d'une
/// liaison de canal. Un exportateur de longueur variable ferait dépendre la
/// valeur d'un paramètre de plus, que les deux camps devraient tenir d'accord.
pub const EXPORT_OCTETS: usize = 32;

/// Ce que TLS veut émettre, et à quel niveau.
///
/// # LE NIVEAU EST CELUI DES OCTETS, PAS CELUI D'APRÈS
///
/// C'est toute la subtilité de `write_hs`, et la faute qu'elle invite. `rustls`
/// écrit : « When this returns `Some(_)`, the new keys must be used for future
/// handshake data. » **Pour les SUIVANTS.** Les octets de cet envoi-ci partent
/// au niveau où ils ont été produits.
///
/// Concrètement, côté serveur : le `ServerHello` sort en même temps que les clés
/// de `Handshake` apparaissent — et il doit partir en `Initial`, sans quoi le
/// client ne peut pas le lire, puisqu'il n'a pas encore ces clés-là.
///
/// # POURQUOI CELA MARCHE POUR UN SERVEUR, ET CE QU'IL FAUDRAIT SAVOIR AILLEURS
///
/// `rustls` vide sa file de messages et **s'arrête avant le premier message à
/// chiffrer** quand de nouvelles clés attendent — c'est ce qui coupe le vol en
/// deux au bon endroit. Cette coupure ne se produit que s'il reste quelque chose
/// à émettre en clair devant : côté serveur, c'est toujours le cas, puisque le
/// `ServerHello` précède tout le reste.
///
/// **Côté client, non** : son `Finished` est seul dans la file, et `write_hs` le
/// rend DANS LE MÊME APPEL que les clés de `Handshake` — alors qu'il appartient
/// au niveau `Handshake`. C'est ce qu'a montré une sonde écrite pour comprendre
/// un refus, et c'est la raison pour laquelle cette crate ne fait pas de côté
/// client : la règle simple qui suffit ici ne suffirait pas là.
pub struct Flight {
    /// Le niveau auquel ces octets doivent partir.
    level: Level,
    /// Les octets de poignée de main.
    octets: Vec<u8>,
    /// Les clés que TLS installe APRÈS cet envoi.
    change: Option<KeyChange>,
}

impl Flight {
    /// Le niveau auquel ces octets doivent partir.
    #[must_use]
    pub const fn level(&self) -> Level {
        self.level
    }

    /// Les octets de poignée de main, à mettre en trames `CRYPTO`.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.octets
    }

    /// Les clés que cet envoi installe — pour ce qui vient APRÈS lui.
    #[must_use]
    pub const fn change(&self) -> Option<&KeyChange> {
        self.change.as_ref()
    }

    /// Reprend les clés, pour les remettre à la protection de paquet.
    #[must_use]
    pub fn take_change(&mut self) -> Option<KeyChange> {
        self.change.take()
    }
}

impl core::fmt::Debug for Flight {
    /// **LES CLÉS NE S'IMPRIMENT PAS.**
    ///
    /// `KeyChange` porte de quoi chiffrer et déchiffrer toute la suite de la
    /// connexion. `rustls` ne lui donne pas de `Debug`, et c'est heureux : en
    /// dériver un ici ferait entrer des clés dans le premier message de
    /// diagnostic venu, puis dans un journal, puis dans un ticket.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Flight")
            .field("level", &self.level)
            .field("octets", &self.octets.len())
            .field("change", &self.change.is_some())
            .finish()
    }
}

/// La poignée de main d'une connexion QUIC, côté serveur.
///
/// # POURQUOI PAS DE CÔTÉ CLIENT
///
/// Nous servons du courrier ; nous n'allons pas en chercher en HTTP/3. Un côté
/// client serait du code que rien n'appelle, donc que rien n'éprouve — et une
/// poignée de main que personne n'a jamais fait tourner n'est pas une poignée de
/// main, c'est une intention.
pub struct Poignee {
    /// Celui qui conduit vraiment TLS.
    ///
    /// # POURQUOI L'ÉNUMÉRÉ, ET NON `ServerConnection`
    ///
    /// Parce que `rustls::quic` porte DEUX types nommés `ConnectionCommon` — le
    /// sien et celui de `rustls` tout court —, et que **seul l'énuméré
    /// `quic::Connection` expose l'exportateur de RFC 8446 §7.5**. Le
    /// `ServerConnection` déréférence vers le `ConnectionCommon` du module
    /// `quic`, dont le champ interne est privé : l'exportateur y est
    /// inatteignable.
    ///
    /// L'énuméré ne coûte rien — un `match` à deux bras dont un seul existe chez
    /// nous — et il donne accès à tout ce que la poignée de main employait
    /// déjà : `write_hs`, `read_hs`, `alert`, `quic_transport_parameters`, et
    /// `alpn_protocol` par déréférencement.
    tls: ConnexionTls,
    /// Les règles de §4 : niveaux, flux `CRYPTO`, refus.
    regles: Handshake,
    /// Les trois fenêtres de réassemblage, une par flux.
    ///
    /// **C'EST ICI QU'ELLES VIVENT, ET NON DANS `ams-quic`** : cette crate-là
    /// n'alloue pas, et une machine sans allocation n'a pas à décider seule de
    /// réserver douze kibioctets par connexion.
    fenetres: [Vec<u8>; 3],
    /// De quel côté on est.
    ///
    /// # UN SEUL ENDROIT S'EN SERT, ET C'EST §4.1.2
    ///
    /// « The TLS handshake is considered confirmed at the server when the
    /// handshake completes. At the client, the handshake is considered confirmed
    /// when a HANDSHAKE_DONE frame is received. »
    ///
    /// Tout le reste — les niveaux, les fenêtres, les refus de §4.1.3 — ne
    /// dépend pas du côté. **C'est pour cela qu'il y a un champ plutôt que deux
    /// types** : deux types auraient dupliqué cent vingt lignes pour une seule
    /// différence, et c'est la copie qu'on oublie de corriger qui diverge.
    role: Role,
}

impl Poignee {
    /// Une poignée de main qui commence.
    ///
    /// `params` porte les paramètres de transport encodés (§8.2 de RFC 9001).
    /// Ils voyagent dans une extension TLS, et c'est ce qui les AUTHENTIFIE :
    /// un pair ne peut pas les changer en chemin sans casser la poignée de main.
    ///
    /// # Errors
    ///
    /// [`Reason::NoQuicSuite`] si le fournisseur ne sait pas chiffrer un paquet
    /// QUIC, [`Reason::Tls`] pour tout autre refus de `rustls`.
    pub fn serveur(config: Arc<ServerConfig>, params: Vec<u8>) -> Result<Self, Error> {
        // **ON POSE LA QUESTION NOUS-MÊMES, PLUTÔT QUE DE LIRE UN MESSAGE.**
        //
        // `rustls` refuse une configuration sans suite capable de QUIC par un
        // `Error::General` portant « at least one ciphersuite must support
        // QUIC » — une phrase, sans variante dédiée. La première version la
        // cherchait dans le texte : un refus qui dépend d'une chaîne de
        // caractères d'amont se tait le jour où l'amont la reformule, et il ne
        // se tait pas bruyamment.
        //
        // La question, elle, se pose en trois lignes, et sa réponse ne change
        // pas de formulation.
        if !sait_chiffrer_quic(&config) {
            return Err(Error::new(Reason::NoQuicSuite));
        }
        let tls = ConnexionTls::from(
            ServerConnection::new(config, VERSION, params)
                .map_err(|_| Error::new(Reason::TlsSansAlerte))?,
        );
        Ok(Self::montee(tls, Role::Server))
    }

    /// Une poignée de main CLIENTE qui commence.
    ///
    /// `nom` est le nom que le client exige du certificat présenté. **C'est la
    /// seule chose qui distingue une connexion vérifiée d'une connexion
    /// chiffrée** : sans lui, `rustls` chiffrerait aussi bien avec un
    /// intermédiaire.
    ///
    /// `params` porte nos paramètres de transport encodés (§8.2). Contrairement
    /// au serveur, un client n'y met **pas** `original_destination_connection_id`
    /// — ce champ-là est la preuve que le SERVEUR a vu le premier paquet, et
    /// c'est le client qui la vérifie.
    ///
    /// # Errors
    ///
    /// [`Reason::NoQuicSuite`] si le fournisseur ne sait pas chiffrer un paquet
    /// QUIC, [`Reason::TlsSansAlerte`] pour tout autre refus de `rustls`.
    pub fn client(
        config: Arc<ClientConfig>,
        params: Vec<u8>,
        nom: ServerName<'static>,
    ) -> Result<Self, Error> {
        // Le fournisseur du client doit savoir chiffrer QUIC comme celui du
        // serveur, et pour la même raison. La question se pose ici aussi.
        if !suites_savent_chiffrer_quic(&config.crypto_provider().cipher_suites) {
            return Err(Error::new(Reason::NoQuicSuite));
        }
        let tls = ConnexionTls::from(
            ClientConnection::new(config, VERSION, nom, params)
                .map_err(|_| Error::new(Reason::TlsSansAlerte))?,
        );
        Ok(Self::montee(tls, Role::Client))
    }

    /// Le corps commun des deux constructeurs.
    fn montee(tls: ConnexionTls, role: Role) -> Self {
        Self {
            tls,
            regles: Handshake::new(),
            fenetres: [
                vec![0_u8; CRYPTO_OCTETS_MAX],
                vec![0_u8; CRYPTO_OCTETS_MAX],
                vec![0_u8; CRYPTO_OCTETS_MAX],
            ],
            role,
        }
    }

    /// §4.1.2 : la poignée de main est confirmée par un `HANDSHAKE_DONE`.
    ///
    /// **N'A DE SENS QUE POUR UN CLIENT.** Au serveur, terminer c'est confirmer,
    /// et [`Poignee::next_flight`] s'en charge. Appeler ceci côté serveur ne
    /// casse rien — la confirmation est idempotente — mais ne sert à rien.
    pub const fn confirmee_par_le_pair(&mut self) {
        self.regles.confirm();
    }

    /// Range les octets d'une trame `CRYPTO`.
    ///
    /// # Errors
    ///
    /// [`Reason::Quic`] pour ce que §4.1.3, §8.3 et §7.5 refusent.
    pub fn on_crypto(&mut self, level: Level, offset: u64, octets: &[u8]) -> Result<(), Error> {
        let fenetre = match Self::rang(level) {
            Some(rang) => &mut self.fenetres[rang],
            // `0-RTT` n'a pas de flux, donc pas de fenêtre. On passe quand même
            // par les règles : c'est LÀ que §8.3 est écrit, et un refus doit
            // venir de la règle plutôt que d'un manque de place ici.
            None => &mut self.fenetres[0],
        };
        self.regles
            .on_crypto(level, offset, octets, fenetre)
            .map_err(Error::depuis_quic)
    }

    /// Remet à TLS ce qui est prêt, puis rend ce que TLS veut dire en retour.
    ///
    /// Rend `None` quand TLS n'a plus rien à envoyer. **L'APPELANT BOUCLE
    /// JUSQUE-LÀ** : un seul appel ne suffit pas, parce qu'un changement de clés
    /// coupe l'envoi en deux.
    ///
    /// # Errors
    ///
    /// [`Reason::Tls`] si TLS refuse ce qu'il a lu — le code de fermeture est
    /// alors celui de son alerte (§4.8) —, [`Reason::Quic`] pour ce que §4.1.3
    /// refuse entre les niveaux.
    pub fn next_flight(&mut self) -> Result<Option<Flight>, Error> {
        self.nourrir()?;
        if !self.tls.is_handshaking() && self.regles.read_level() < Level::OneRtt {
            // §4.1.2 : **CÔTÉ SERVEUR, TERMINER C'EST CONFIRMER** — c'est le
            // `Finished` du client qui vient d'être vérifié.
            //
            // **CÔTÉ CLIENT, NON.** La confirmation attend un `HANDSHAKE_DONE`,
            // que le serveur n'envoie qu'en `1-RTT` — il faut donc pouvoir y
            // lire AVANT d'être confirmé, sans quoi le message qui confirme ne
            // serait jamais lu. Les deux moments se séparent ici, et nulle part
            // ailleurs.
            // §4.1.1 : la poignée est TERMINÉE des deux côtés dès que TLS a
            // fini. §4.1.2 : elle n'est CONFIRMÉE côté serveur qu'à cet instant
            // aussi, et côté client qu'à l'arrivée d'un `HANDSHAKE_DONE`.
            match self.role {
                Role::Server => self.regles.confirm(),
                Role::Client => self.regles.complete(),
            }
            // La lecture passe en `1-RTT` dans les deux cas : ce qui vient
            // ensuite — tickets de session, `HANDSHAKE_DONE` — voyage là
            // (§4.6.1).
            self.regles
                .install_read(Level::OneRtt)
                .map_err(Error::depuis_quic)?;
        }

        let mut octets = Vec::new();
        let niveau = self.regles.write_level();
        let change = self.tls.write_hs(&mut octets);
        if octets.is_empty() && change.is_none() {
            return Ok(None);
        }

        // **LE NIVEAU DES OCTETS EST CELUI D'AVANT LE CHANGEMENT**, et c'est
        // seulement maintenant qu'on le fait avancer.
        if let Some(change) = change.as_ref() {
            self.avancer(change)?;
        }
        Ok(Some(Flight {
            level: niveau,
            octets,
            change,
        }))
    }

    /// Fait avancer les niveaux qu'un changement de clés installe.
    ///
    /// # LIRE ET ÉCRIRE N'AVANCENT PAS ENSEMBLE, ET C'EST LE PIÈGE
    ///
    /// La première version installait le même niveau des deux côtés, et **un
    /// vrai client `rustls` l'a fait tomber tout de suite** : le serveur reçoit
    /// ses clés de `1-RTT` en même temps qu'il envoie son `Finished`, mais le
    /// `Finished` DU CLIENT arrive encore en `Handshake`. Passer la lecture en
    /// `1-RTT` à ce moment-là faisait refuser ce `Finished` comme « du neuf à un
    /// niveau déjà dépassé » (§4.1.3) — c'est-à-dire refuser la seule chose qui
    /// termine la poignée de main.
    ///
    /// Aucun essai avec soi-même n'aurait vu cela : il aurait fait la même faute
    /// des deux côtés.
    fn avancer(&mut self, change: &KeyChange) -> Result<(), Error> {
        match change {
            KeyChange::Handshake { .. } => {
                // §4.1.3 : des clés plus hautes alors qu'un niveau inférieur a
                // encore des octets non lus est une faute de protocole. C'est
                // ici que la règle se paie.
                self.regles
                    .install_read(Level::Handshake)
                    .map_err(Error::depuis_quic)?;
                self.regles.install_write(Level::Handshake);
            }
            // **PAS DE `install_read` ICI.** Le serveur écrit en `1-RTT` dès
            // qu'il a les clés (§4.9 : « new data MUST be sent at the highest
            // currently available encryption level »), et il lit encore en
            // `Handshake`.
            KeyChange::OneRtt { .. } => self.regles.install_write(Level::OneRtt),
        }
        Ok(())
    }

    /// Le protocole applicatif négocié — `None` tant que la poignée de main
    /// n'est pas terminée.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.alpn_protocol()
    }

    /// Dérive une valeur propre à CETTE connexion TLS — RFC 8446 §7.5.
    ///
    /// # CE QUE CETTE FONCTION FERME, ET QU'AUCUNE AUTRE NE FERMAIT
    ///
    /// Une signature d'application qu'on lie à la connexion doit être liée à
    /// **CETTE** connexion, et non au serveur. Une empreinte de certificat ne
    /// distingue pas deux connexions au même serveur : un intermédiaire qui
    /// transmet un défi au vrai serveur, puis la signature en retour,
    /// s'authentifie à la place du pair. C'est le RELAIS, et c'est ce que
    /// l'exportateur ferme — sa valeur est dérivée du secret maître, que
    /// l'intermédiaire n'a pas.
    ///
    /// # ELLE ÉCHOUE AVANT LA FIN DE LA POIGNÉE DE MAIN, ET C'EST JUSTE
    ///
    /// `rustls` refuse tant que la poignée de main n'est pas terminée, et il a
    /// raison : le secret maître n'existe pas encore. Rendre des octets de repli
    /// serait pire que d'échouer — deux pairs dériveraient la même valeur pour
    /// deux connexions différentes, et le relais se rouvrirait sans qu'on le
    /// voie.
    ///
    /// L'étiquette et le contexte appartiennent à l'APPELANT : c'est lui qui
    /// sait pour quel usage il dérive, et deux usages ne doivent jamais tomber
    /// sur la même valeur.
    ///
    /// # Errors
    ///
    /// [`Reason::ExportImpossible`] si la poignée de main n'est pas terminée.
    pub fn export(
        &self,
        etiquette: &[u8],
        contexte: Option<&[u8]>,
    ) -> Result<[u8; EXPORT_OCTETS], Error> {
        self.tls
            .export_keying_material([0_u8; EXPORT_OCTETS], etiquette, contexte)
            .map_err(|_| Error::new(Reason::ExportImpossible))
    }

    /// Les paramètres de transport du pair (§8.2).
    ///
    /// **ILS NE VALENT QU'UNE FOIS LA POIGNÉE DE MAIN TERMINÉE** : avant, rien
    /// ne les authentifie, et §4.1.3 le dit — « Once the TLS handshake is
    /// complete […] the transport parameters that the peer advertised during the
    /// handshake are authenticated. »
    #[must_use]
    pub fn peer_parameters(&self) -> Option<&[u8]> {
        self.tls.quic_transport_parameters()
    }

    /// La poignée de main est-elle terminée (§4.1.1) ?
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.regles.is_complete()
    }

    /// Le niveau où TLS écrit — celui où partent les données neuves (§4.9).
    #[must_use]
    pub const fn write_level(&self) -> Level {
        self.regles.write_level()
    }

    /// Le niveau où TLS lit.
    #[must_use]
    pub const fn read_level(&self) -> Level {
        self.regles.read_level()
    }

    /// Le protocole négocié est-il celui qu'on sert ?
    ///
    /// # POURQUOI CETTE QUESTION EST POSÉE ICI, ET PAS DANS LA BOUCLE
    ///
    /// `rustls` refuse déjà une poignée de main dont l'ALPN ne recouvre pas le
    /// nôtre : il envoie `no_application_protocol` tout seul. Ce contrôle-ci est
    /// donc une CEINTURE, et il dit pourquoi elle existe — le jour où quelqu'un
    /// monterait cette poignée de main sur une configuration dont
    /// `alpn_protocols` est vide, `rustls` n'aurait plus rien à faire respecter,
    /// et la connexion parlerait un protocole que nous ne servons pas.
    ///
    /// # Errors
    ///
    /// [`Reason::WrongAlpn`], dont le code de fermeture est celui de l'alerte
    /// `no_application_protocol` (§4.8).
    pub fn check_alpn(&self) -> Result<(), Error> {
        match self.alpn() {
            Some(dit) if dit == ams_tls::ALPN_H3 => Ok(()),
            _ => Err(Error::new(Reason::WrongAlpn)),
        }
    }

    /// Remet à TLS tout ce qui est contigu, au niveau où il lit.
    fn nourrir(&mut self) -> Result<(), Error> {
        let niveau = self.regles.read_level();
        // **PAS DE GARDE POUR `0-RTT` ICI, ET C'EST DÉLIBÉRÉ.** TLS n'y lit
        // jamais : ce niveau ne porte pas de `CRYPTO` (§4.1.3), et rien
        // n'installe la lecture là. Écrire un `return` pour ce cas rendrait une
        // branche que nul essai ne pourrait atteindre — et une garde
        // inatteignable n'est pas une garde, c'est une affirmation non vérifiée.
        //
        // La boucle, elle, s'arrête d'elle-même : `take` rend zéro pour un
        // niveau sans flux.
        let rang = Self::rang(niveau).unwrap_or(0);
        let mut vers = [0_u8; CRYPTO_OCTETS_MAX];
        loop {
            let pris = self
                .regles
                .take(niveau, &mut self.fenetres[rang], &mut vers);
            if pris == 0 {
                return Ok(());
            }
            self.tls
                .read_hs(&vers[..pris])
                .map_err(|erreur| Error::depuis_alerte(&erreur, self.tls.alert()))?;
        }
    }

    /// Le rang du flux `CRYPTO` d'un niveau — `None` pour `0-RTT` (§4.1.3).
    const fn rang(level: Level) -> Option<usize> {
        match level {
            Level::Initial => Some(0),
            Level::ZeroRtt => None,
            Level::Handshake => Some(1),
            Level::OneRtt => Some(2),
        }
    }
}

impl core::fmt::Debug for Poignee {
    /// **RIEN DE CE QUI EST SECRET N'EST IMPRIMÉ.**
    ///
    /// Une connexion `rustls` porte des clés. `#[derive(Debug)]` les ferait
    /// entrer dans le premier message de diagnostic venu, puis dans un journal,
    /// puis dans un ticket.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Poignee")
            .field("role", &self.role)
            .field("read_level", &self.regles.read_level())
            .field("write_level", &self.regles.write_level())
            .field("complete", &self.regles.is_complete())
            .finish_non_exhaustive()
    }
}

/// Le code de fermeture QUIC que porte cette alerte TLS (§4.8).
///
/// Réexporté depuis `ams-quic`, où la règle est écrite : c'est ce que
/// l'appelant met dans un `CONNECTION_CLOSE` quand cette crate refuse.
pub use ams_quic::crypto_error as alert_code;

/// Ce que `crypto_error` rend pour une alerte absente.
///
/// §4.8 : « QUIC permits the use of a generic code in place of a specific error
/// code […] such as handshake_failure ». Quand `rustls` refuse sans produire
/// d'alerte, c'est celui-ci qu'on écrit — plutôt qu'un code inventé.
#[must_use]
pub fn generic_close_code() -> u64 {
    crypto_error(HANDSHAKE_FAILURE)
}

/// Cette configuration a-t-elle de quoi chiffrer un paquet QUIC ?
///
/// §5 de RFC 9001 : la protection de paquet n'est pas celle des enregistrements
/// TLS. Une suite peut savoir l'une sans savoir l'autre, et c'est exactement le
/// cas du fournisseur pur Rust monté sans [`ams_tls::provider_quic`].
fn sait_chiffrer_quic(config: &ServerConfig) -> bool {
    suites_savent_chiffrer_quic(&config.crypto_provider().cipher_suites)
}

/// La même question, posée à une liste de suites.
///
/// **Elle est écrite une fois pour les deux camps** : un client dont le
/// fournisseur ne sait pas chiffrer QUIC échoue exactement comme un serveur, et
/// deux copies de ce filtre finiraient par ne plus poser la même question.
fn suites_savent_chiffrer_quic(suites: &[rustls::SupportedCipherSuite]) -> bool {
    suites
        .iter()
        .filter_map(rustls::SupportedCipherSuite::tls13)
        .any(|suite| suite.quic.is_some())
}

/// `handshake_failure`, §6.2 de RFC 8446.
const HANDSHAKE_FAILURE: u8 = 40;

/// `no_application_protocol`, §6.2 de RFC 8446.
const NO_APPLICATION_PROTOCOL: u8 = 120;

#[cfg(test)]
mod tests;
