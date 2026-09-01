// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que l'API REST sert, lu dans le magasin.
//!
//! # UNE SEULE VUE DU MAGASIN POUR LES DEUX PROTOCOLES
//!
//! Ce module ne lit pas les Maildir : il interroge le MÊME [`Mailboxes`] qu'IMAP.
//! Ce n'est pas une économie de lignes, c'est ce qui empêche les deux protocoles
//! de se contredire.
//!
//! Une seconde voie de lecture aurait sa propre idée de ce qu'est un message
//! lisible, de ce que vaut un `UIDVALIDITY`, de quels dossiers existent. Deux
//! fenêtres ouvertes sur la même boîte finiraient par ne plus montrer la même
//! chose, et personne ne saurait laquelle croire.
//!
//! # UN COMPTE ORDINAIRE N'OBTIENT JAMAIS LA PORTÉE D'ADMINISTRATION
//!
//! Un mot de passe ouvre le courrier, la soumission et la supervision de SON
//! compte. Il n'ouvre pas l'administration — créer un compte, en effacer un,
//! lever un bannissement. **Cette limite est dans le code, et non dans une
//! configuration** : un réglage finirait par être basculé, et un compte
//! compromis deviendrait alors le serveur entier.
//!
//! # CE QUI N'EST PAS ENCORE SERVI LE DIT
//!
//! Les ressources d'administration et de soumission répondent `501`. §15.6.2 de
//! RFC 9110 : « the server does not support the functionality required ». C'est
//! la réponse honnête — un `404` ferait croire que la ressource n'existe pas, et
//! un `500` qu'elle a échoué.

use std::sync::Arc;

use ams_api::{JSON_MEDIA_TYPE, Resource, Scope};
use ams_auth::Account;
use ams_loop_tokio::http::{Api, Served};
use ams_proto_http::{Method, StatusCode};
use ams_sasl::Credentials;
use ams_session::http::render::{self, MailboxRow, MessageRow};
use ams_session::imap::{Mailbox as _, Mailboxes as _};

use crate::imap::BoitesImap;
use crate::policy::Places;

/// Combien de messages une page rend au plus.
///
/// Cinquante. Le client demande la suite avec le curseur que la réponse porte —
/// voir [`render::write_messages`]. Une page plus grande ferait retenir plus
/// longtemps ce qu'un client peut demander sans fin.
const PAGE_MAX: usize = 50;

/// Combien de boîtes une liste rend au plus.
///
/// Deux cent cinquante-six. Ce sont les dossiers d'un compte, donc ce que ce
/// compte a créé lui-même : la borne n'est pas là contre lui, elle est là pour
/// que la réponse tienne dans un tampon dont on connaît la taille.
const BOITES_MAX: usize = 256;

/// Combien de vérifications de mot de passe tournent en même temps.
///
/// La même raison qu'ailleurs : Argon2id demande dix-neuf mébioctets par
/// vérification, et rien ne borne le nombre de connexions HTTP simultanées.
const VERIFICATIONS_SIMULTANEES: usize = 4;

/// Ce que l'API sert, adossé au magasin.
pub struct ApiMaildir {
    /// Le même service de boîtes qu'IMAP.
    boites: Arc<BoitesImap>,
    /// Les comptes, pour vérifier un mot de passe.
    comptes: Arc<Vec<Account>>,
    /// La borne sur les vérifications simultanées.
    places: Places,
}

impl ApiMaildir {
    /// Monte l'API sur le service de boîtes et le magasin de comptes.
    #[must_use]
    pub fn new(boites: Arc<BoitesImap>, comptes: Arc<Vec<Account>>) -> Self {
        Self {
            boites,
            comptes,
            places: Places::new(VERIFICATIONS_SIMULTANEES),
        }
    }

    /// La liste des boîtes d'un compte.
    fn mailboxes<'o>(&self, compte: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let mut lignes = std::vec::Vec::with_capacity(BOITES_MAX);
        let mut textes = std::vec::Vec::with_capacity(BOITES_MAX);
        for rang in 0..BOITES_MAX {
            let mut place = [0_u8; 512];
            let Some(vue) = self.boites.name(compte.as_bytes(), rang, &mut place) else {
                break;
            };
            // **UN NOM QUI N'EST PAS DE L'UTF-8 NE SE REND PAS** : il ne peut pas
            // entrer dans un document JSON (§8.1 de RFC 8259), et le remplacer
            // par des points d'interrogation en ferait un nom qu'aucune requête
            // ne pourrait désigner.
            let Ok(nom) = core::str::from_utf8(vue.name) else {
                continue;
            };
            if !vue.selectable {
                continue;
            }
            textes.push(nom.to_string());
        }
        for nom in &textes {
            let Some(boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
                continue;
            };
            lignes.push(MailboxRow {
                name: nom,
                messages: boite.exists(),
                unseen: non_lus(&boite),
                uid_next: boite.uid_next(),
                uid_validity: boite.uid_validity(),
            });
        }
        rendre(render::write_mailboxes(&lignes, sortie))
    }

    /// L'état d'une boîte.
    fn mailbox<'o>(&self, compte: &str, nom: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let Some(boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };
        let ligne = MailboxRow {
            name: nom,
            messages: boite.exists(),
            unseen: non_lus(&boite),
            uid_next: boite.uid_next(),
            uid_validity: boite.uid_validity(),
        };
        rendre(render::write_mailbox(&ligne, sortie))
    }

    /// Une page de messages.
    fn messages<'o>(&self, compte: &str, nom: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let Some(boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };
        let mut resumes = std::vec::Vec::with_capacity(PAGE_MAX);
        let mut suivant = None;
        for sequence in 1..=boite.exists() {
            let Some(info) = boite.info(sequence) else {
                continue;
            };
            if resumes.len() >= PAGE_MAX {
                // **LE CURSEUR EST L'UID DU PREMIER QU'ON NE REND PAS.** Un
                // curseur sur le dernier rendu obligerait le client à savoir
                // s'il est inclus ou non.
                suivant = Some(info.uid);
                break;
            }
            // **C'EST ICI QUE LA PAGE COÛTE**, et c'est pourquoi elle est bornée :
            // un fichier ouvert par message rendu, et pas un de plus. La boîte
            // entière ne l'est jamais.
            resumes.push(resumer(&boite, sequence, info));
        }
        let page: std::vec::Vec<MessageRow<'_>> = resumes.iter().map(ligne_de).collect();
        rendre(render::write_messages(
            &page,
            boite.uid_validity(),
            suivant,
            sortie,
        ))
    }

    /// Un message.
    fn message<'o>(&self, compte: &str, nom: &str, uid: u64, sortie: &'o mut [u8]) -> Served<'o> {
        let Some(boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };
        let voulu = u32::try_from(uid).ok();
        let trouve = (1..=boite.exists())
            .filter_map(|sequence| boite.info(sequence).map(|info| (sequence, info)))
            .find(|(_, info)| Some(info.uid) == voulu);
        let Some((sequence, info)) = trouve else {
            return absente(sortie);
        };
        let resume = resumer(&boite, sequence, info);
        rendre(render::write_message(
            &ligne_de(&resume),
            boite.uid_validity(),
            sortie,
        ))
    }
}

impl Api for ApiMaildir {
    fn serve<'o>(
        &self,
        resource: Resource<'_>,
        _method: Method,
        account: &str,
        _body: &[u8],
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        match resource {
            Resource::Health => rendre(render::write_health(sortie)),
            Resource::Metrics => rendre(render::write_metrics(
                &[("mailboxes", self.compte_des_boites(account))],
                sortie,
            )),
            Resource::Mailboxes => self.mailboxes(account, sortie),
            Resource::Mailbox { boite } => self.mailbox(account, boite, sortie),
            Resource::Messages { boite } => self.messages(account, boite, sortie),
            Resource::Message { boite, uid } => self.message(account, boite, uid, sortie),
            // **CE QUI N'EST PAS ENCORE SERVI LE DIT** (§15.6.2 de RFC 9110).
            _ => pas_encore(sortie),
        }
    }

    /// # Deux précautions, et aucune n'est facultative
    ///
    /// Les mêmes que pour `AUTH` en SMTP : `block_in_place`, parce qu'Argon2id
    /// est délibérément lent et bloquerait l'ordonnanceur ; et une borne sur les
    /// vérifications simultanées, parce que chacune réclame dix-neuf mébioctets.
    ///
    /// Le reste — le compte inconnu qui coûte le même temps — vit dans
    /// `ams-auth`, qui est couvert à 100 %.
    fn authenticate(&self, login: &str, password: &[u8]) -> Option<Scope> {
        let identifiants = Credentials {
            authorization_identity: b"",
            authentication_identity: login.as_bytes(),
            password,
        };
        let ouvre = tokio::task::block_in_place(|| {
            self.places
                .occuper(|| ams_auth::authenticate(&self.comptes, &identifiants))
        });
        // **UN MOT DE PASSE N'OUVRE PAS L'ADMINISTRATION.** Voir l'en-tête du
        // module : la limite est dans le code, et non dans une configuration.
        ouvre.then(|| {
            Scope::one(ams_api::Area::Mail, ams_api::Rights::Write)
                .with(ams_api::Area::Submit, ams_api::Rights::Write)
                .with(ams_api::Area::Observe, ams_api::Rights::Read)
        })
    }

    /// # L'ALÉA VIENT DU NOYAU, ET SE RELIT À CHAQUE JETON
    ///
    /// Un générateur qu'on garderait entre deux jetons devrait être protégé d'un
    /// verrou, et son état survivrait à un `fork`. Une lecture par jeton coûte un
    /// appel système, et un jeton ne s'émet qu'à l'ouverture d'une session.
    ///
    /// `/dev/urandom` ne bloque pas une fois la machine amorcée. **S'il est
    /// illisible, on rend zéro** : le jeton reste scellé et vérifiable, seule sa
    /// révocation individuelle devient impossible — ce qui vaut mieux que de
    /// refuser toute ouverture de session.
    fn nonce(&self) -> u64 {
        use std::io::Read as _;

        let mut octets = [0_u8; 8];
        let lu = std::fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut octets))
            .is_ok();
        match lu {
            true => u64::from_ne_bytes(octets),
            false => 0,
        }
    }
}

impl ApiMaildir {
    /// Combien de boîtes ce compte porte.
    fn compte_des_boites(&self, compte: &str) -> u64 {
        let mut combien = 0_u64;
        for rang in 0..BOITES_MAX {
            let mut place = [0_u8; 512];
            if self
                .boites
                .name(compte.as_bytes(), rang, &mut place)
                .is_none()
            {
                break;
            }
            combien = combien.saturating_add(1);
        }
        combien
    }
}

/// Ce qu'on retient d'un message le temps d'écrire la réponse.
///
/// # POURQUOI DEUX PASSES, ET NON UNE
///
/// [`MessageRow`] EMPRUNTE son sujet et son expéditeur ; les octets doivent donc
/// vivre plus longtemps que la ligne qui les désigne. On les rassemble d'abord,
/// on construit les lignes ensuite. Une seule passe demanderait à chaque ligne de
/// posséder ses textes, c'est-à-dire de les recopier pour rien.
struct Resume {
    /// Ce que la boîte sait du message sans ouvrir son fichier.
    info: ams_session::imap::MessageInfo,
    /// Son sujet, décodé — `None` s'il n'en porte pas, ou qu'on n'a pas su le
    /// rendre entier.
    sujet: Option<std::vec::Vec<u8>>,
    /// L'adresse de son expéditeur.
    expediteur: Option<std::vec::Vec<u8>>,
}

/// Ce qu'un sujet et un expéditeur occupent, dans les tampons qu'on prête.
///
/// Ce sont ceux d'`ams-mime`, et ils viennent des RFC : §2.1.1 de RFC 5322 pour
/// la longueur d'une ligne, §4.5.3.1.3 de RFC 5321 pour celle d'un chemin.
const SUJET_MAX: usize = ams_mime::DIGEST_SUBJECT_MAX;
/// Voir [`SUJET_MAX`].
const EXPEDITEUR_MAX: usize = ams_mime::DIGEST_FROM_MAX;

/// Lit le sujet et l'expéditeur d'un message.
fn resumer(
    boite: &crate::imap::BoiteImap,
    sequence: u32,
    info: ams_session::imap::MessageInfo,
) -> Resume {
    let mut sujet = [0_u8; SUJET_MAX];
    let mut expediteur = [0_u8; EXPEDITEUR_MAX];
    let vu = boite.digest(sequence, &mut sujet, &mut expediteur);
    let prendre = |octets: &[u8], combien: Option<usize>| {
        combien.map(|n| octets.get(..n).unwrap_or_default().to_vec())
    };
    Resume {
        info,
        sujet: prendre(&sujet, vu.subject),
        expediteur: prendre(&expediteur, vu.from),
    }
}

/// La ligne que rend un résumé.
///
/// # CE QUI N'EST PAS DE L'UTF-8 N'EST PAS RENDU
///
/// §6.2 de RFC 2047 laisse un mot encodé nommer un jeu de caractères qu'on ne
/// sait pas convertir, et `ams-mime` le recopie alors tel quel — c'est la vérité
/// plutôt qu'une conversion inventée. Ces octets-là ne sont pas du texte JSON, et
/// les y écrire ferait une réponse qu'aucun client ne lirait. On rend `null` :
/// le message a un sujet, nous ne savons pas le dire.
fn ligne_de(resume: &Resume) -> MessageRow<'_> {
    fn texte(octets: &Option<std::vec::Vec<u8>>) -> Option<&str> {
        octets
            .as_deref()
            .and_then(|octets| core::str::from_utf8(octets).ok())
    }
    MessageRow {
        uid: resume.info.uid,
        size: resume.info.size,
        flags: resume.info.flags,
        received: resume.info.internal_date,
        subject: texte(&resume.sujet),
        from: texte(&resume.expediteur),
    }
}

/// Combien de messages ne portent pas `\Seen`.
fn non_lus<M: ams_session::imap::Mailbox>(boite: &M) -> u32 {
    (1..=boite.exists())
        .filter_map(|sequence| boite.info(sequence))
        .filter(|info| !info.flags.contains(ams_proto_imap::Flags::SEEN))
        .count()
        .try_into()
        .unwrap_or(u32::MAX)
}

/// Une écriture réussie, ou notre faute.
fn rendre(ecrit: Result<&[u8], ams_api::Error>) -> Served<'_> {
    match ecrit {
        Ok(corps) => Served {
            status: StatusCode::OK,
            media: JSON_MEDIA_TYPE,
            body: corps,
        },
        // **LE TAMPON EST LE NÔTRE** : le client n'y peut rien, et le lui dire
        // précisément ne l'avancerait pas.
        Err(_) => Served {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: &[],
        },
    }
}

/// Une boîte ou un message qu'on ne trouve pas.
///
/// **LE MÊME `404` QUE POUR UNE ROUTE INCONNUE** : la boîte d'un autre compte et
/// la boîte qui n'existe pas se répondent pareil, sans quoi la différence dirait
/// laquelle des deux choses on a touchée.
fn absente(sortie: &mut [u8]) -> Served<'_> {
    match ams_api::problem(ams_api::Reason::NoSuchResource, sortie) {
        Ok(corps) => Served {
            status: StatusCode::NOT_FOUND,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: corps,
        },
        Err(_) => Served {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: &[],
        },
    }
}

/// Une ressource que ce serveur ne sert pas encore.
fn pas_encore(sortie: &mut [u8]) -> Served<'_> {
    match ams_api::problem(ams_api::Reason::NoSuchResource, sortie) {
        Ok(corps) => Served {
            status: StatusCode::NOT_IMPLEMENTED,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: corps,
        },
        Err(_) => Served {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: &[],
        },
    }
}

#[cfg(test)]
mod tests {
    use ams_session::imap::MessageInfo;

    use super::{Resume, ligne_de};

    /// Un résumé porteur de ces deux textes.
    fn resume(sujet: Option<&[u8]>, expediteur: Option<&[u8]>) -> Resume {
        Resume {
            info: MessageInfo {
                uid: 7,
                size: 42,
                flags: ams_proto_imap::Flags::default(),
                internal_date: 1_700_000_000,
            },
            sujet: sujet.map(<[u8]>::to_vec),
            expediteur: expediteur.map(<[u8]>::to_vec),
        }
    }

    /// **L'ABSENCE ET LE VIDE NE SE CONFONDENT PAS DANS LA LIGNE NON PLUS.**
    ///
    /// C'est la distinction que `write_digest` a établie ; la perdre ici la
    /// rendrait inutile, et le client lirait `""` là où le message n'a rien.
    #[test]
    fn l_absence_et_le_vide_traversent_la_ligne() {
        let vu = resume(Some(b""), None);
        let ligne = ligne_de(&vu);
        assert_eq!(ligne.subject, Some(""), "un sujet présent, et vide");
        assert_eq!(ligne.from, None, "pas d'expéditeur du tout");

        let vu = resume(None, Some(b"jean@example.test"));
        let ligne = ligne_de(&vu);
        assert_eq!(ligne.subject, None);
        assert_eq!(ligne.from, Some("jean@example.test"));
        assert_eq!(ligne.uid, 7, "et le reste de l'information passe");
        assert_eq!(ligne.size, 42);
    }

    /// **CE QUI N'EST PAS DE L'UTF-8 N'EST PAS RENDU.**
    ///
    /// §6.2 de RFC 2047 laisse un mot encodé nommer un jeu qu'on ne sait pas
    /// convertir, et `ams-mime` le recopie alors tel quel — la vérité plutôt
    /// qu'une conversion inventée. Ces octets ne sont pas du texte JSON, et les y
    /// écrire ferait une réponse qu'aucun client ne lirait.
    #[test]
    fn ce_qui_n_est_pas_de_l_utf8_ne_se_rend_pas() {
        let vu = resume(Some(&[0xff, 0xfe]), Some(&[0xff]));
        let ligne = ligne_de(&vu);
        assert_eq!(
            ligne.subject, None,
            "on préfère `null` à une réponse cassée"
        );
        assert_eq!(ligne.from, None);
    }
}
