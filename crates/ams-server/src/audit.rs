// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le journal d'audit : ce qui a touché à la sécurité d'un compte (phase 6).
//!
//! # CE QUI S'Y ÉCRIT
//!
//! Les sessions ouvertes et les identifiants refusés, les appareils enrôlés,
//! appairés ou révoqués, les secrets changés, les mots de passe applicatifs,
//! les délégations, les abonnements aux réveils, les invitations. Chaque
//! entrée dit QUAND, QUOI, et D'OÙ — l'adresse de qui a agi.
//!
//! Jamais un secret, jamais un contenu : un nom d'appareil, un identifiant, un
//! canal, un compte délégué. **UN COMPTE INCONNU NE S'Y ÉCRIT PAS** — ce
//! serait écrire un nom qu'un inconnu a choisi, et laisser remplir le disque
//! avec des noms inventés.
//!
//! # UN FICHIER PAR COMPTE, OÙ L'ON AJOUTE
//!
//! Une ligne JSON par entrée, ajoutée à la fin : c'est la représentation même
//! que l'API rend, et un exploitant la lit avec `tail`. Réécrire un magasin
//! entier à chaque connexion ferait d'une rafale de refus une rafale de
//! réécritures. Au-delà de [`ROTATION_OCTETS`], le fichier devient `.1` — qui
//! remplace l'ancien — et un neuf commence : **le disque est borné par
//! compte**, à deux fichiers.
//!
//! # UN FIL À PART, ET POUR DEUX RAISONS
//!
//! **Le temps d'un refus ne doit pas dire si le compte existe.** Un refus
//! d'identifiants pour un compte existant s'écrit ; pour un inconnu, non. Si
//! l'écriture se faisait avant la réponse, sa durée la trahirait. L'entrée
//! part donc dans une file bornée, et un fil dédié l'écrit.
//!
//! Et **aucune écriture ne bloque la boucle asynchrone**. Une file pleine —
//! le disque ne suit pas — perd l'entrée plutôt que de ralentir le service ;
//! la perte se compte et se dit.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::string::String;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::vec::Vec;

/// Au-delà de cette taille, le fichier d'un compte tourne.
///
/// **256 KIO** : un millier d'entrées environ, soit des semaines de sessions
/// ordinaires. Deux fichiers au plus par compte.
pub const ROTATION_OCTETS: u64 = 256 * 1024;

/// Combien d'entrées une lecture rend par défaut, et au plus.
pub const LIMITE_PAR_DEFAUT: usize = 50;
/// Voir [`LIMITE_PAR_DEFAUT`].
pub const LIMITE_MAX: usize = 100;

/// Combien d'entrées peuvent attendre le fil d'écriture.
const FILE_MAX: usize = 1024;

/// Ce qu'une entrée dit au plus, par champ : de quoi garder une ligne courte.
const CHAMP_MAX: usize = 128;

/// Ce qui s'est passé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evenement<'a> {
    /// Une session s'est ouverte, par mot de passe (`None`) ou par la clef de
    /// cet appareil.
    SessionOuverte {
        /// L'appareil, s'il y en a un.
        appareil: Option<&'a str>,
    },
    /// Une session de courrier s'est ouverte — SMTP, IMAP ou POP3 (0.2.38).
    ConnexionCourrier {
        /// `smtp`, `imap` ou `pop3`.
        porte: &'static str,
        /// Le mot de passe applicatif qui l'a ouverte, s'il y en a un.
        applicatif: Option<&'a str>,
    },
    /// Des identifiants ont été refusés à cette porte.
    Refus {
        /// `password` ou `device` pour l'API ; `smtp`, `imap` ou `pop3` pour le
        /// courrier.
        porte: &'static str,
    },
    /// Un appareil a été enrôlé sur invitation.
    AppareilEnrole {
        /// Son identifiant.
        appareil: &'a str,
        /// Le nom que son propriétaire lui a donné.
        nom: &'a str,
    },
    /// Un appareil a été ajouté, approuvé par un autre.
    AppareilAppaire {
        /// Son identifiant.
        appareil: &'a str,
        /// Le nom que son propriétaire lui a donné.
        nom: &'a str,
    },
    /// Un appareil a été révoqué.
    AppareilRevoque {
        /// Son identifiant.
        appareil: &'a str,
    },
    /// Le secret du compte a changé — par son titulaire, ou par
    /// l'administration.
    SecretChange {
        /// `self` ou `admin`.
        par: &'static str,
    },
    /// Un mot de passe applicatif a été créé.
    ApplicatifCree {
        /// Son identifiant.
        id: &'a str,
        /// Son nom.
        nom: &'a str,
    },
    /// Un mot de passe applicatif a été révoqué.
    ApplicatifRevoque {
        /// Son identifiant.
        id: &'a str,
    },
    /// Une délégation a été posée : `delegue` atteint la boîte de `titulaire`.
    DelegationPosee {
        /// Le titulaire de la boîte.
        titulaire: &'a str,
        /// Le compte qui l'atteint.
        delegue: &'a str,
    },
    /// Une délégation a été retirée.
    DelegationRetiree {
        /// Le titulaire de la boîte.
        titulaire: &'a str,
        /// Le compte qui l'atteignait.
        delegue: &'a str,
    },
    /// Un appareil s'est abonné aux réveils.
    Abonnement {
        /// L'appareil.
        appareil: &'a str,
        /// Le canal : `webpush`, `apns`, `fcm`.
        canal: &'a str,
    },
    /// Un appareil s'est désabonné.
    Desabonnement {
        /// L'appareil.
        appareil: &'a str,
    },
    /// L'administration a émis une invitation pour ce compte.
    InvitationEmise,
}

impl Evenement<'_> {
    /// Son nom, tel que l'API le rend.
    const fn nom(self) -> &'static str {
        match self {
            Self::SessionOuverte { .. } | Self::ConnexionCourrier { .. } => "session.opened",
            Self::Refus { .. } => "auth.refused",
            Self::AppareilEnrole { .. } => "device.enrolled",
            Self::AppareilAppaire { .. } => "device.paired",
            Self::AppareilRevoque { .. } => "device.revoked",
            Self::SecretChange { .. } => "password.changed",
            Self::ApplicatifCree { .. } => "app-password.created",
            Self::ApplicatifRevoque { .. } => "app-password.revoked",
            Self::DelegationPosee { .. } => "delegation.granted",
            Self::DelegationRetiree { .. } => "delegation.removed",
            Self::Abonnement { .. } => "push.subscribed",
            Self::Desabonnement { .. } => "push.unsubscribed",
            Self::InvitationEmise => "invitation.issued",
        }
    }
}

/// Écrit une entrée — une ligne JSON, fin de ligne comprise.
///
/// `quand` est en secondes depuis l'époque, comme tout ce que l'API rend.
#[must_use]
pub fn ligne(evenement: Evenement<'_>, source: Option<&str>, quand: u64) -> Vec<u8> {
    let (appareil, detail): (Option<&str>, Option<&str>) = match evenement {
        Evenement::SessionOuverte { appareil } => (
            appareil,
            Some(match appareil {
                Some(_) => "device",
                None => "password",
            }),
        ),
        Evenement::Refus { porte } | Evenement::ConnexionCourrier { porte, .. } => {
            (None, Some(porte))
        }
        Evenement::AppareilEnrole { appareil, nom }
        | Evenement::AppareilAppaire { appareil, nom } => (Some(appareil), Some(nom)),
        Evenement::AppareilRevoque { appareil } | Evenement::Desabonnement { appareil } => {
            (Some(appareil), None)
        }
        Evenement::SecretChange { par } => (None, Some(par)),
        Evenement::ApplicatifCree { id, .. } | Evenement::ApplicatifRevoque { id } => {
            (None, Some(id))
        }
        Evenement::DelegationPosee { titulaire, delegue }
        | Evenement::DelegationRetiree { titulaire, delegue } => {
            return ligne_de_delegation(evenement.nom(), titulaire, delegue, source, quand);
        }
        Evenement::Abonnement { appareil, canal } => (Some(appareil), Some(canal)),
        Evenement::InvitationEmise => (None, None),
    };
    let nom = match evenement {
        Evenement::ApplicatifCree { nom, .. } => Some(nom),
        _ => None,
    };
    let applicatif = match evenement {
        Evenement::ConnexionCourrier { applicatif, .. } => applicatif,
        _ => None,
    };
    let mut place = std::vec![0_u8; 1024];
    let ecrit = {
        let mut json = ams_api::Json::new(&mut place);
        (|| {
            json.begin_object()?;
            json.field_u64("at", quand)?;
            json.field_str("event", evenement.nom())?;
            champ(&mut json, "source", source)?;
            champ(&mut json, "device", appareil)?;
            champ(&mut json, "detail", detail)?;
            if let Some(nom) = nom {
                json.field_str("name", borne(nom))?;
            }
            if let Some(id) = applicatif {
                json.field_str("appPassword", borne(id))?;
            }
            json.end_object()?;
            json.finish().map(<[u8]>::len)
        })()
    };
    fermer(place, ecrit)
}

/// Une délégation porte deux comptes, et c'est ce qui la distingue.
fn ligne_de_delegation(
    nom: &str,
    titulaire: &str,
    delegue: &str,
    source: Option<&str>,
    quand: u64,
) -> Vec<u8> {
    let mut place = std::vec![0_u8; 1024];
    let ecrit = {
        let mut json = ams_api::Json::new(&mut place);
        (|| {
            json.begin_object()?;
            json.field_u64("at", quand)?;
            json.field_str("event", nom)?;
            champ(&mut json, "source", source)?;
            json.field_str("owner", borne(titulaire))?;
            json.field_str("delegate", borne(delegue))?;
            json.end_object()?;
            json.finish().map(<[u8]>::len)
        })()
    };
    fermer(place, ecrit)
}

/// Un champ texte, ou `null`.
fn champ(
    json: &mut ams_api::Json<'_>,
    nom: &str,
    valeur: Option<&str>,
) -> Result<(), ams_api::Error> {
    json.key(nom)?;
    match valeur {
        Some(texte) => json.string(borne(texte)),
        None => json.null(),
    }
}

/// Coupe un texte à [`CHAMP_MAX`] octets, sur une frontière de caractère.
fn borne(texte: &str) -> &str {
    let mut fin = texte.len().min(CHAMP_MAX);
    while !texte.is_char_boundary(fin) {
        fin = fin.saturating_sub(1);
    }
    texte.get(..fin).unwrap_or_default()
}

/// La ligne écrite, fin de ligne comprise — ou rien, si elle n'a pas tenu.
fn fermer(mut place: Vec<u8>, ecrit: Result<usize, ams_api::Error>) -> Vec<u8> {
    match ecrit {
        Ok(longueur) => {
            place.truncate(longueur);
            place.push(b'\n');
            place
        }
        Err(_) => Vec::new(),
    }
}

/// Ce que le fil d'écriture reçoit.
enum Ordre {
    /// Ajouter cette ligne au fichier de ce compte.
    Ecrire { compte: String, ligne: Vec<u8> },
    /// Effacer le journal de ce compte — il vient d'être retiré.
    Oublier { compte: String },
}

/// Le journal d'audit.
#[derive(Debug)]
pub struct Audit {
    /// Le répertoire, un fichier par compte.
    racine: PathBuf,
    /// La file vers le fil d'écriture.
    envoi: SyncSender<Ordre>,
    /// Combien d'entrées ont été perdues, la file étant pleine.
    perdues: AtomicU64,
    /// Quand chaque entrée regroupée a été écrite pour la dernière fois — voir
    /// [`Audit::noter_au_plus`].
    recentes: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

/// Combien d'entrées regroupées se retiennent au plus.
///
/// **LA TABLE EST BORNÉE** : ses clefs portent l'adresse du pair, et un
/// attaquant qui dispose d'un `/64` en fabriquerait autant qu'il veut. Pleine,
/// elle oublie d'abord ce qui a plus d'une heure, puis tout : on écrit alors
/// une entrée de trop, jamais une de moins.
const RECENTES_MAX: usize = 4096;

impl Audit {
    /// Ouvre le journal sous cette racine, qui naît en `0700`, et lance son fil.
    ///
    /// # Errors
    ///
    /// Le répertoire qui ne se crée pas, ou le fil qui ne se lance pas.
    pub fn ouvrir(racine: PathBuf) -> std::io::Result<Arc<Self>> {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&racine)?;
        let (envoi, reception) = std::sync::mpsc::sync_channel(FILE_MAX);
        let ecrivain = racine.clone();
        std::thread::Builder::new()
            .name(String::from("air-mail-audit"))
            .spawn(move || ecrire_sans_fin(&ecrivain, &reception))?;
        Ok(Arc::new(Self {
            racine,
            envoi,
            perdues: AtomicU64::new(0),
            recentes: std::sync::Mutex::new(std::collections::HashMap::new()),
        }))
    }

    /// Note un événement — mais AU PLUS une fois par `intervalle` secondes pour
    /// ce compte, cet événement, ce détail et cette adresse (0.2.38).
    ///
    /// # POURQUOI REGROUPER
    ///
    /// Un client de courrier se reconnecte sans cesse : iOS Mail ouvre une
    /// session IMAP par dossier, Thunderbird toutes les quelques minutes. Une
    /// entrée par connexion noierait le journal — et avec lui la seule ligne
    /// qui compte, celle d'une adresse qu'on ne connaît pas. Ce que le titulaire
    /// veut savoir est « qui s'est connecté, d'où », et une entrée par heure le
    /// dit. Un refus se regroupe à la minute : une rafale d'essais se voit, sans
    /// écrire chacun.
    pub fn noter_au_plus(
        &self,
        compte: &str,
        evenement: Evenement<'_>,
        source: Option<&str>,
        quand: u64,
        intervalle: u64,
    ) {
        if ams_auth::check_login(compte).is_err() {
            return;
        }
        let detail = match evenement {
            Evenement::Refus { porte } | Evenement::ConnexionCourrier { porte, .. } => porte,
            _ => "",
        };
        let applicatif = match evenement {
            Evenement::ConnexionCourrier { applicatif, .. } => applicatif.unwrap_or_default(),
            _ => "",
        };
        let clef = format!(
            "{compte}\0{}\0{detail}\0{applicatif}\0{}",
            evenement.nom(),
            source.unwrap_or_default()
        );
        {
            let mut recentes = self
                .recentes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if recentes
                .get(&clef)
                .is_some_and(|derniere| derniere.saturating_add(intervalle) > quand)
            {
                return;
            }
            if recentes.len() >= RECENTES_MAX {
                recentes.retain(|_, derniere| derniere.saturating_add(3600) > quand);
                if recentes.len() >= RECENTES_MAX {
                    recentes.clear();
                }
            }
            recentes.insert(clef, quand);
        }
        self.noter(compte, evenement, source, quand);
    }

    /// Note un événement pour ce compte, depuis cette adresse, à cet instant
    /// (en secondes depuis l'époque).
    ///
    /// **NE BLOQUE JAMAIS** : l'entrée part dans la file, ou se perd — et la
    /// perte se compte.
    pub fn noter(&self, compte: &str, evenement: Evenement<'_>, source: Option<&str>, quand: u64) {
        if ams_auth::check_login(compte).is_err() {
            return;
        }
        let ligne = ligne(evenement, source, quand);
        if ligne.is_empty() {
            return;
        }
        let ordre = Ordre::Ecrire {
            compte: String::from(compte),
            ligne,
        };
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.envoi.try_send(ordre)
        {
            // **UNE PERTE SE DIT**, la première et une sur mille ensuite : un
            // journal d'audit qui perd sans le dire ferait croire qu'il n'y a
            // rien eu.
            let perdues = self
                .perdues
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1);
            if perdues == 1 || perdues.is_multiple_of(1000) {
                eprintln!(
                    "air-mail-server : journal d'audit — {perdues} entrée(s) PERDUE(S) depuis le \
                     démarrage : le disque ne suit pas"
                );
            }
        }
    }

    /// Efface le journal de ce compte, dans l'ordre des écritures qui le
    /// précèdent.
    ///
    /// **UN COMPTE RECRÉÉ SOUS CE NOM NE LIT PAS LE JOURNAL DE L'ANCIEN** :
    /// il y apprendrait d'où se connectait quelqu'un d'autre.
    pub fn oublier(&self, compte: &str) {
        if ams_auth::check_login(compte).is_err() {
            return;
        }
        // BLOQUANT, ET C'EST VOULU : un retrait de compte est rare, et
        // l'oubli ne doit pas se perdre sur une file pleine.
        let _ = self.envoi.send(Ordre::Oublier {
            compte: String::from(compte),
        });
    }

    /// Combien d'entrées ont été perdues depuis le démarrage.
    #[cfg(test)]
    #[must_use]
    pub fn perdues(&self) -> u64 {
        self.perdues.load(Ordering::Relaxed)
    }

    /// Les `limite` entrées les plus récentes de ce compte, de la plus récente
    /// à la plus ancienne. Chacune est une ligne JSON, sans sa fin de ligne.
    ///
    /// **UNE LIGNE INCOMPLÈTE NE SE REND PAS** : une écriture interrompue — un
    /// arrêt brutal — laisse une ligne sans fin, et ce qui la suit n'est pas un
    /// objet. On ne rend que ce qui a la forme exacte d'une entrée.
    #[must_use]
    pub fn lire(&self, compte: &str, limite: usize) -> Vec<Vec<u8>> {
        if ams_auth::check_login(compte).is_err() {
            return Vec::new();
        }
        let (courant, ancien) = chemins(&self.racine, compte);
        let mut lignes: Vec<Vec<u8>> = Vec::new();
        for chemin in [ancien, courant] {
            if let Ok(octets) = std::fs::read(&chemin) {
                lignes.extend(
                    octets
                        .split_inclusive(|octet| *octet == b'\n')
                        .filter_map(entree_valide)
                        .map(<[u8]>::to_vec),
                );
            }
        }
        lignes.into_iter().rev().take(limite).collect()
    }
}

/// Cette ligne est-elle une entrée entière ? Rend-la sans sa fin de ligne.
fn entree_valide(ligne: &[u8]) -> Option<&[u8]> {
    let corps = ligne.strip_suffix(b"\n")?;
    let debut = b"{\"at\":";
    let entiere = corps.starts_with(debut)
        && corps.ends_with(b"}")
        // Une ligne interrompue suivie d'une autre en contient deux débuts.
        && !corps
            .get(1..)
            .unwrap_or_default()
            .windows(debut.len())
            .any(|fenetre| fenetre == debut);
    entiere.then_some(corps)
}

/// Le fichier courant et l'ancien, pour ce compte.
fn chemins(racine: &Path, compte: &str) -> (PathBuf, PathBuf) {
    (
        racine.join(format!("{compte}.jsonl")),
        racine.join(format!("{compte}.1.jsonl")),
    )
}

/// Le fil d'écriture : il vide la file jusqu'à ce que le journal disparaisse.
fn ecrire_sans_fin(racine: &Path, reception: &Receiver<Ordre>) {
    while let Ok(ordre) = reception.recv() {
        match ordre {
            Ordre::Ecrire { compte, ligne } => {
                if let Err(erreur) = ajouter(racine, &compte, &ligne) {
                    eprintln!(
                        "air-mail-server : journal d'audit — une entrée de `{compte}` ne s'écrit \
                         pas ({erreur})"
                    );
                }
            }
            Ordre::Oublier { compte } => {
                let (courant, ancien) = chemins(racine, &compte);
                for chemin in [courant, ancien] {
                    match std::fs::remove_file(&chemin) {
                        Ok(()) => {}
                        Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {}
                        Err(erreur) => eprintln!(
                            "air-mail-server : journal d'audit de `{compte}` NON effacé \
                             ({erreur}) — à effacer avant de recréer ce compte"
                        ),
                    }
                }
            }
        }
    }
}

/// Ajoute une ligne au fichier de ce compte, en le faisant tourner s'il est
/// plein.
fn ajouter(racine: &Path, compte: &str, ligne: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let (courant, ancien) = chemins(racine, compte);
    if std::fs::metadata(&courant).is_ok_and(|vu| vu.len() >= ROTATION_OCTETS) {
        std::fs::rename(&courant, &ancien)?;
    }
    let mut fichier = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&courant)?;
    // **UNE SEULE ÉCRITURE PAR LIGNE** : en `O_APPEND`, elle ne s'entrelace
    // avec rien, et une interruption laisse au pire une ligne sans fin — que la
    // lecture écarte.
    fichier.write_all(ligne)?;
    fichier.sync_data()
}

#[cfg(test)]
mod tests;
