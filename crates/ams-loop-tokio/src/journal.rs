// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Une ligne de journal par connexion, écrite à sa fermeture.
//!
//! # POURQUOI UNE SEULE LIGNE, ET À LA FIN
//!
//! Un journal qui écrit à l'ouverture ne sait rien encore : ni ce qui a été
//! négocié, ni qui s'est authentifié, ni ce qui a été remis. Il faudrait alors
//! deux lignes par connexion, que l'exploitant devrait recoller lui-même —
//! et elles s'entrelaceraient, puisque le serveur sert des milliers de
//! connexions à la fois.
//!
//! **La ligne part donc quand tout est su**, et elle porte tout : d'où vient
//! le pair, ce que TLS a négocié, sous quel mécanisme il s'est authentifié et
//! au nom de quel compte, ce qu'il a fait, et combien de temps cela a pris.
//!
//! # CE QU'ELLE NE PORTE PAS, ET C'EST DÉLIBÉRÉ
//!
//! - **Aucun secret** : ni mot de passe, ni preuve SCRAM, ni octets de
//!   liaison. Le mécanisme se nomme ; ce qu'il a transporté, non.
//! - **Aucune adresse d'enveloppe ni objet de message.** Un journal
//!   d'exploitation dit QUI s'est connecté et CE QU'IL A OBTENU ; il n'est pas
//!   une copie du courrier, et le laisser le devenir ferait des sauvegardes de
//!   `journald` un second magasin de messages que personne n'a décidé.
//! - **Rien que le pair ait écrit**, à une exception près : le nom du compte,
//!   et seulement APRÈS que la politique l'a reconnu et canonisé. Recopier au
//!   journal ce qu'un inconnu a tapé y laisserait écrire n'importe quoi.
//!
//! # LE NOM DU COMPTE EST ASSAINI AVANT D'ÊTRE ÉCRIT
//!
//! `journald` reçoit des lignes ; un octet de contrôle dans l'une d'elles la
//! coupe en deux, et une fausse ligne se lit comme une vraie. Le nom passe
//! donc par [`Compte`], qui ne laisse sortir que de l'ASCII imprimable.

use core::fmt;
use core::time::Duration;

use ams_session::Mecanisme;
use rustls::ProtocolVersion;

/// La longueur maximale d'un nom de compte au journal.
///
/// C'est celle que les sessions retiennent — au-delà, la politique aurait déjà
/// refusé le nom.
pub const COMPTE_MAX: usize = 64;

/// Ce que TLS a négocié sur une connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chiffrement {
    /// La version, telle qu'on l'écrit au journal : `TLS1.3`, `TLS1.2`.
    pub version: &'static str,
    /// La suite négociée, sous son nom IANA.
    pub suite: &'static str,
}

impl fmt::Display for Chiffrement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.version, self.suite)
    }
}

/// Ce que `rustls` dit de la session, ou `None` s'il ne dit rien.
///
/// **`None` NE VEUT PAS DIRE « EN CLAIR »** : la poignée de main peut avoir
/// abouti sans que la version ou la suite soient lisibles. L'appelant sait par
/// ailleurs si la connexion était chiffrée, et les deux ne se déduisent pas
/// l'une de l'autre.
pub(crate) fn chiffrement_de(connexion: &rustls::ServerConnection) -> Option<Chiffrement> {
    let version = match connexion.protocol_version()? {
        ProtocolVersion::TLSv1_3 => "TLS1.3",
        ProtocolVersion::TLSv1_2 => "TLS1.2",
        // C4 n'en autorise pas d'autres. Si une version inattendue arrivait
        // ici, la nommer par son ordinal vaut mieux que de la taire.
        autre => autre.as_str().unwrap_or("TLS?"),
    };
    let suite = connexion
        .negotiated_cipher_suite()?
        .suite()
        .as_str()
        .unwrap_or("suite inconnue");
    Some(Chiffrement { version, suite })
}

/// Un nom de compte prêt à écrire : de l'ASCII imprimable, et borné.
///
/// **IL EST `Copy`**, pour que les résumés de connexion le restent : ils
/// traversent les boucles par valeur, et y glisser une allocation ferait payer
/// un tas à chaque connexion pour une ligne de journal.
#[derive(Clone, Copy)]
pub struct Compte {
    octets: [u8; COMPTE_MAX],
    len: usize,
}

impl Default for Compte {
    fn default() -> Self {
        Self {
            octets: [0; COMPTE_MAX],
            len: 0,
        }
    }
}

impl Compte {
    /// Retient un nom, **en n'en gardant que l'ASCII imprimable**.
    ///
    /// Tout le reste — octet de contrôle, séquence UTF-8, retour à la ligne —
    /// devient `?`. Un nom plus long que [`COMPTE_MAX`] est tronqué : au
    /// journal, un nom coupé se reconnaît, là où une ligne coupée ment.
    #[must_use]
    pub fn neuf(nom: &[u8]) -> Self {
        let mut compte = Self::default();
        for octet in nom.iter().take(COMPTE_MAX) {
            let propre = if octet.is_ascii_graphic() {
                *octet
            } else {
                b'?'
            };
            if let Some(place) = compte.octets.get_mut(compte.len) {
                *place = propre;
                compte.len = compte.len.saturating_add(1);
            }
        }
        compte
    }

    /// Le nom est-il vide ?
    #[must_use]
    pub const fn est_vide(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for Compte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl PartialEq for Compte {
    fn eq(&self, autre: &Self) -> bool {
        self.octets.get(..self.len) == autre.octets.get(..autre.len)
    }
}

impl Eq for Compte {}

impl fmt::Display for Compte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Les octets ont été filtrés à l'ASCII imprimable : ils sont de l'UTF-8
        // valide par construction, et `from_utf8` ne peut pas échouer ici.
        let lisible =
            core::str::from_utf8(self.octets.get(..self.len).unwrap_or_default()).unwrap_or("?");
        f.write_str(lisible)
    }
}

/// Ce qu'une connexion laisse au journal.
///
/// Les trois protocoles servis la remplissent chacun à leur façon, et la ligne
/// rendue a la même forme pour les trois : c'est ce qui permet de les lire
/// ensemble.
pub struct Trace<'a> {
    /// `SMTP`, `IMAP` ou `POP3`.
    pub protocole: &'static str,
    /// D'où venait le pair.
    pub pair: &'a dyn fmt::Display,
    /// Ce que TLS a négocié, si la connexion a été chiffrée.
    pub chiffrement: Option<Chiffrement>,
    /// La connexion a-t-elle été chiffrée ? **Indépendant du précédent.**
    pub tls: bool,
    /// Sous quel mécanisme le pair s'est authentifié, s'il l'a fait.
    pub mecanisme: Option<Mecanisme>,
    /// Au nom de quel compte.
    pub compte: Compte,
    /// Ce que la connexion a produit, dit en clair par l'appelant : « 1 message
    /// accepté », « 12 messages remis », « banni ».
    pub issue: &'a dyn fmt::Display,
    /// Combien de commandes ont été traitées.
    pub commandes: u64,
    /// Combien de temps la connexion a duré.
    pub duree: Duration,
}

impl fmt::Display for Trace<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} — ", self.protocole, self.pair)?;
        match (self.chiffrement, self.tls) {
            (Some(chiffrement), _) => write!(f, "{chiffrement}")?,
            // Chiffré, mais `rustls` n'a pas dit quoi : ne pas écrire « en
            // clair » serait faux, l'inventer le serait aussi.
            (None, true) => f.write_str("TLS (non renseigné)")?,
            (None, false) => f.write_str("EN CLAIR")?,
        }
        match (self.mecanisme, self.compte.est_vide()) {
            (Some(mecanisme), false) => {
                write!(f, ", AUTH {} `{}`", mecanisme.nom(), self.compte)?;
            }
            // Authentifié, mais le nom n'a pas tenu : le dire vaut mieux que de
            // laisser croire à une session anonyme.
            (Some(mecanisme), true) => write!(f, ", AUTH {} (compte illisible)", mecanisme.nom())?,
            (None, _) => f.write_str(", sans authentification")?,
        }
        write!(
            f,
            ", {}, {} commande(s), {} s",
            self.issue,
            self.commandes,
            self.duree.as_secs()
        )
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use ams_session::Mecanisme;

    use super::{Chiffrement, Compte, Trace};

    fn trace<'a>(
        chiffrement: Option<Chiffrement>,
        tls: bool,
        mecanisme: Option<Mecanisme>,
        compte: Compte,
        pair: &'a dyn core::fmt::Display,
        issue: &'a dyn core::fmt::Display,
    ) -> Trace<'a> {
        Trace {
            protocole: "SMTP",
            pair,
            chiffrement,
            tls,
            mecanisme,
            compte,
            issue,
            commandes: 6,
            duree: Duration::from_secs(3),
        }
    }

    #[test]
    fn la_ligne_complete_porte_tout_ce_qui_a_ete_negocie() {
        let chiffrement = Chiffrement {
            version: "TLS1.3",
            suite: "TLS13_AES_256_GCM_SHA384",
        };
        let ligne = trace(
            Some(chiffrement),
            true,
            Some(Mecanisme::Plain),
            Compte::neuf(b"ofrou-sierre"),
            &"178.197.196.110",
            &"1 message accepté",
        )
        .to_string();
        assert_eq!(
            ligne,
            "SMTP 178.197.196.110 — TLS1.3 (TLS13_AES_256_GCM_SHA384), AUTH PLAIN \
             `ofrou-sierre`, 1 message accepté, 6 commande(s), 3 s"
        );
    }

    #[test]
    fn une_connexion_en_clair_et_anonyme_le_dit() {
        let ligne = trace(
            None,
            false,
            None,
            Compte::default(),
            &"2001:db8::1",
            &"rien",
        )
        .to_string();
        assert_eq!(
            ligne,
            "SMTP 2001:db8::1 — EN CLAIR, sans authentification, rien, 6 commande(s), 3 s"
        );
    }

    #[test]
    fn un_chiffrement_que_rustls_ne_decrit_pas_ne_se_lit_pas_en_clair() {
        let ligne = trace(None, true, None, Compte::default(), &"192.0.2.1", &"rien").to_string();
        assert!(ligne.contains("TLS (non renseigné)"), "{ligne}");
    }

    #[test]
    fn un_compte_qui_n_a_pas_tenu_se_distingue_d_une_session_anonyme() {
        let ligne = trace(
            None,
            true,
            Some(Mecanisme::ScramSha256Plus),
            Compte::default(),
            &"192.0.2.1",
            &"rien",
        )
        .to_string();
        assert!(
            ligne.contains("AUTH SCRAM-SHA-256-PLUS (compte illisible)"),
            "{ligne}"
        );
    }

    #[test]
    fn un_nom_de_compte_ne_peut_pas_couper_la_ligne_en_deux() {
        // Un retour à la ligne, une tabulation, un octet nul et de l'UTF-8 :
        // `journald` lirait deux lignes là où il n'y a qu'une connexion.
        let compte = Compte::neuf("a\nb\tc\0dé".as_bytes());
        let rendu = compte.to_string();
        assert!(!rendu.contains('\n'), "{rendu}");
        assert!(!rendu.contains('\t'), "{rendu}");
        // `é` fait deux octets en UTF-8, et les deux sont remplacés.
        assert_eq!(rendu, "a?b?c?d??");
    }

    #[test]
    fn un_nom_trop_long_est_tronque_et_non_refuse() {
        let compte = Compte::neuf(&[b'x'; super::COMPTE_MAX + 40]);
        assert_eq!(compte.to_string().len(), super::COMPTE_MAX);
    }

    #[test]
    fn le_compte_vide_se_reconnait() {
        assert!(Compte::default().est_vide());
        assert!(!Compte::neuf(b"contact").est_vide());
        assert_eq!(Compte::neuf(b"contact"), Compte::neuf(b"contact"));
        assert_ne!(Compte::neuf(b"contact"), Compte::neuf(b"support"));
        assert_eq!(format!("{:?}", Compte::neuf(b"contact")), "contact");
    }
}
