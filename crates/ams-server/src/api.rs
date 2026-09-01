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

/// Les champs d'en-tête qui désignent des destinataires (§3.6.3 de RFC 5322).
///
/// **`Bcc` EN FAIT PARTIE** : une copie cachée est une copie. Ce qui la distingue
/// est qu'elle ne figure pas dans le message REMIS, et non qu'elle ne serait pas
/// remise.
const DESTINATAIRES: [&[u8]; 3] = [b"to", b"cc", b"bcc"];

/// Combien de destinataires une soumission peut désigner.
///
/// Soixante-quatre. Aucune RFC ne le borne — c'est le nombre de boîtes qu'un
/// seul dépôt fait écrire, et sans borne un message unique en ferait écrire
/// autant que le magasin en porte.
const DESTINATAIRES_MAX: usize = 64;

/// Combien de vérifications de mot de passe tournent en même temps.
///
/// La même raison qu'ailleurs : Argon2id demande dix-neuf mébioctets par
/// vérification, et rien ne borne le nombre de connexions HTTP simultanées.
const VERIFICATIONS_SIMULTANEES: usize = 4;

/// Ce que l'API sert, adossé au magasin.
pub struct ApiMaildir {
    /// Le même service de boîtes qu'IMAP.
    boites: Arc<BoitesImap>,
    /// Les comptes, pour vérifier un mot de passe et router un destinataire.
    comptes: Arc<Vec<Account>>,
    /// Les mêmes boîtes que la remise SMTP, pour y déposer une soumission.
    ///
    /// **LE MÊME CHEMIN, ET NON UN SECOND** : un message déposé par l'API doit
    /// arriver comme celui qui entre par SMTP — même écriture, même validation,
    /// même magasin. Une seconde façon de remettre finirait par diverger, et deux
    /// messages identiques n'auraient pas le même sort selon la porte d'entrée.
    remise: crate::delivery::Boites,
    /// La borne sur les vérifications simultanées.
    places: Places,
}

impl ApiMaildir {
    /// Monte l'API sur le service de boîtes et le magasin de comptes.
    #[must_use]
    pub fn new(
        boites: Arc<BoitesImap>,
        comptes: Arc<Vec<Account>>,
        remise: crate::delivery::Boites,
    ) -> Self {
        Self {
            boites,
            comptes,
            remise,
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

    /// Dépose un message, et le remet aux boîtes de ses destinataires.
    ///
    /// # LA MÊME REMISE QUE SMTP, ET SEULEMENT LOCALE
    ///
    /// Ce serveur ne relaie pas. Un destinataire qui ne mène à aucun compte d'ici
    /// fait refuser tout le dépôt : l'accepter à moitié laisserait l'expéditeur
    /// croire que son message est parti là où il ne partira jamais.
    ///
    /// # UN COMPTE N'ÉCRIT QU'EN SON NOM
    ///
    /// Le `From:` doit être une adresse que le compte authentifié déclare. Sans
    /// ce contrôle, un compte ouvert suffirait à écrire au nom de n'importe qui
    /// d'autre sur ce serveur — et le destinataire n'aurait aucun moyen de le
    /// voir, puisque le message serait par ailleurs parfaitement authentique.
    ///
    /// **LES ADRESSES DE RÉCEPTION SERVENT D'IDENTITÉS D'ÉMISSION**, et c'est une
    /// équivalence qu'on pose ici : un compte peut écrire depuis ce qu'il peut
    /// recevoir. Elle est conventionnelle, et elle évite un second champ dans le
    /// magasin de comptes qui pourrait diverger du premier.
    ///
    /// # ET LE `Bcc` NE PART PAS
    ///
    /// §3.6.3 de RFC 5322 : une copie cachée est cachée. Le message remis est
    /// donc écrit sans ce champ — **à tous**, y compris à celui qui y figure : il
    /// sait déjà qu'il l'a reçu, et lui montrer la liste révélerait les autres.
    fn submissions<'o>(&self, compte: &str, corps: &[u8], sortie: &'o mut [u8]) -> Served<'o> {
        let bornes = ams_mime::Limits::DEFAULT;
        let Ok(message) = ams_mime::Message::parse(corps, &bornes) else {
            return refus_de_depot(sortie);
        };
        if !ecrit_bien_en_son_nom(&self.comptes, compte, &message) {
            return refus_de_depot(sortie);
        }
        let Some(destinataires) = destinataires_de(&self.comptes, &message) else {
            return refus_de_depot(sortie);
        };

        let Some(remis) = message_a_remettre(corps, &message, &bornes) else {
            return notre_faute();
        };

        let mut remise = crate::delivery::MaildirDelivery::new(
            std::sync::Arc::clone(&self.remise),
            std::sync::Arc::clone(&self.comptes),
        );
        let issue = deposer(&mut remise, &destinataires, &remis);
        if issue.is_err() {
            // **CE N'EST PAS LA FAUTE DU DÉPOSANT**, et ce n'est pas définitif :
            // plus d'UID, disque plein. §15.6.4 de RFC 9110 dit exactement cela,
            // et un `500` ferait renoncer un client qui pourrait réessayer.
            {
                use ams_loop_tokio::Delivery as _;
                remise.abort();
            }
            return indisponible(sortie);
        }
        let combien = u64::try_from(destinataires.len()).unwrap_or(u64::MAX);
        rendre(render::write_metrics(&[("delivered", combien)], sortie))
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
        body: &[u8],
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
            Resource::Submissions => self.submissions(account, body, sortie),
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

/// Le `From:` du message appartient-il à ce compte ?
fn ecrit_bien_en_son_nom(
    comptes: &[Account],
    compte: &str,
    message: &ams_mime::Message<'_>,
) -> bool {
    let Some(champ) = message.fields().find(|champ| champ.name_is(b"from")) else {
        return false;
    };
    let Some(adresse) = ams_mime::bare_address(champ.raw_value()) else {
        return false;
    };
    ams_auth::route(comptes, adresse).is_some_and(|vu| vu.login == compte)
}

/// Les destinataires du message, s'ils sont tous lisibles et tous d'ici.
///
/// **UN SEUL QU'ON NE SAIT PAS LIRE FAIT TOUT REFUSER.** L'écarter en silence
/// remettrait le message à moins de monde que l'expéditeur ne l'a demandé, et
/// rien dans la réponse ne le lui dirait.
fn destinataires_de(
    comptes: &[Account],
    message: &ams_mime::Message<'_>,
) -> Option<std::vec::Vec<Vec<u8>>> {
    let mut vus: std::vec::Vec<Vec<u8>> = std::vec::Vec::new();
    for champ in message.fields() {
        if !DESTINATAIRES.iter().any(|nom| champ.name_is(nom)) {
            continue;
        }
        for element in ams_mime::address_elements(champ.raw_value()) {
            let adresse = ams_mime::bare_address(element)?;
            // §3.6.3 : le nom d'un groupe n'est pas un destinataire, mais il
            // n'est pas non plus une faute — `bare_address` l'a déjà écarté
            // faute d'arobase, et l'on n'arrive donc jamais ici avec lui.
            ams_auth::route(comptes, adresse)?;
            if vus.iter().any(|deja| deja == adresse) {
                // **UN DESTINATAIRE NOMMÉ DEUX FOIS N'EST QU'UN.** Le remettre
                // deux fois lui donnerait deux copies du même message, ce
                // qu'aucun expéditeur ne demande en écrivant `To:` et `Cc:`.
                continue;
            }
            if vus.len() >= DESTINATAIRES_MAX {
                return None;
            }
            vus.push(adresse.to_vec());
        }
    }
    (!vus.is_empty()).then_some(vus)
}

/// Un dépôt qu'on refuse.
///
/// **UNE SEULE RÉPONSE POUR TOUTES LES RAISONS** : un en-tête illisible, un
/// `From:` qui n'est pas à soi, un destinataire qu'on ne sait pas lire, un
/// destinataire qui n'est pas d'ici. Les distinguer ferait de la soumission un
/// moyen d'énumérer les comptes locaux, et un seul compte ouvert suffirait alors
/// à dresser la liste de tous les autres.
fn refus_de_depot(sortie: &mut [u8]) -> Served<'_> {
    match ams_api::problem(ams_api::Reason::BadMessage, sortie) {
        Ok(corps) => Served {
            status: StatusCode::BAD_REQUEST,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: corps,
        },
        Err(_) => notre_faute(),
    }
}

/// Une remise qui n'a pas abouti, et qui pourrait aboutir plus tard.
///
/// §15.6.4 de RFC 9110 : « the server is currently unable to handle the request
/// due to a temporary overload or scheduled maintenance ». Un `500` ferait
/// renoncer un client qui n'a rien fait de mal.
fn indisponible(sortie: &mut [u8]) -> Served<'_> {
    match ams_api::problem(ams_api::Reason::BadMessage, sortie) {
        Ok(corps) => Served {
            status: StatusCode::SERVICE_UNAVAILABLE,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: corps,
        },
        Err(_) => notre_faute(),
    }
}

/// Ce qui n'appartient qu'à nous.
///
/// **ELLE NE REND PAS DE CORPS**, et n'emprunte donc pas le tampon : celui-ci
/// vient d'échouer à porter un document, et le lui redemander ne donnerait rien
/// de plus.
const fn notre_faute<'o>() -> Served<'o> {
    Served {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        media: ams_api::PROBLEM_MEDIA_TYPE,
        body: &[],
    }
}

/// Remet ce message à ces destinataires.
///
/// Séparée pour que `?` serve : l'appelante doit annuler ce qui a commencé.
fn deposer(
    remise: &mut crate::delivery::MaildirDelivery,
    destinataires: &[Vec<u8>],
    message: &[u8],
) -> Result<(), ams_loop_tokio::DeliveryFailure> {
    use ams_loop_tokio::Delivery as _;

    for adresse in destinataires {
        remise.add_recipient(adresse)?;
    }
    remise.append(message)?;
    remise.finish()
}

/// Le message tel qu'il sera remis : son en-tête sans `Bcc`, puis son corps.
///
/// # LE MESSAGE REMIS N'EST PAS CELUI QU'ON A REÇU
///
/// §3.6.3 de RFC 5322 : une copie cachée est cachée. Le champ disparaît donc du
/// message remis — **à tous**, y compris à celui qui y figure : il sait déjà
/// qu'il l'a reçu, et lui montrer la liste révélerait les autres.
///
/// Rien d'autre ne change. L'en-tête se réécrit champ par champ, dans l'ordre où
/// il est venu, et le corps se recopie tel quel : un message que l'on remanierait
/// davantage ne serait plus celui que l'expéditeur a signé.
fn message_a_remettre(
    brut: &[u8],
    message: &ams_mime::Message<'_>,
    bornes: &ams_mime::Limits,
) -> Option<std::vec::Vec<u8>> {
    // **ON LUI DONNE LE MESSAGE ENTIER, ET NON SON SEUL BLOC D'EN-TÊTE** :
    // `header_block` s'arrête AVANT la ligne vide, et `write_header_fields` relit
    // ce qu'on lui passe — il lui faut donc de quoi savoir où l'en-tête finit.
    // Le corps qui suit ne le regarde pas : il n'écrit que des champs.
    //
    // **LE TAMPON NE GRANDIT PAS, MAIS LA MARGE NE COÛTE RIEN** : on retire un
    // champ, et l'on réécrit les autres tels quels. Il meurt avec la requête.
    let mut remis = std::vec![0_u8; brut.len().saturating_add(64)];
    let ecrits = ams_mime::write_header_fields(brut, b"bcc", true, &mut remis, bornes).ok()?;
    remis.truncate(ecrits);
    remis.extend_from_slice(message.body());
    Some(remis)
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

    use super::{Resume, destinataires_de, ecrit_bien_en_son_nom, ligne_de, message_a_remettre};

    /// Deux comptes du magasin, avec leurs adresses.
    fn comptes() -> std::vec::Vec<super::Account> {
        let nomme = |login: std::string::String| super::Account {
            addresses: std::vec![std::format!("{login}@exemple.test")],
            hash: std::string::String::new(),
            login,
        };
        // Deux comptes nommés, et de quoi dépasser la borne des destinataires.
        ["marc".to_string(), "jeanne".to_string()]
            .into_iter()
            .chain((0..=super::DESTINATAIRES_MAX).map(|rang| std::format!("d{rang}")))
            .map(nomme)
            .collect()
    }

    /// Les destinataires de ce message, sous une forme qu'un essai lit.
    fn vers(entete: &str) -> Option<std::vec::Vec<std::string::String>> {
        // §2.1 : l'en-tête se termine par une ligne vide, et non par la
        // dernière ligne de champ.
        let brut = std::format!("{entete}\r\n\r\n");
        let bornes = ams_mime::Limits::DEFAULT;
        let message = ams_mime::Message::parse(brut.as_bytes(), &bornes).expect("lisible");
        destinataires_de(&comptes(), &message).map(|vus| {
            vus.into_iter()
                .map(|adresse| std::string::String::from_utf8_lossy(&adresse).into_owned())
                .collect()
        })
    }

    /// Ce compte écrit-il bien en son nom ?
    fn en_son_nom(compte: &str, entete: &str) -> bool {
        // §2.1 : l'en-tête se termine par une ligne vide, et non par la
        // dernière ligne de champ.
        let brut = std::format!("{entete}\r\n\r\n");
        let bornes = ams_mime::Limits::DEFAULT;
        let message = ams_mime::Message::parse(brut.as_bytes(), &bornes).expect("lisible");
        ecrit_bien_en_son_nom(&comptes(), compte, &message)
    }

    /// **UN COMPTE N'ÉCRIT QU'EN SON NOM.**
    ///
    /// Sans ce contrôle, un compte ouvert suffirait à écrire au nom de n'importe
    /// qui d'autre sur ce serveur — et le destinataire n'aurait aucun moyen de le
    /// voir, puisque le message serait par ailleurs parfaitement authentique.
    #[test]
    fn un_compte_n_ecrit_qu_en_son_nom() {
        assert!(en_son_nom("marc", "From: marc@exemple.test"));
        assert!(en_son_nom("marc", "From: \"Marc\" <marc@exemple.test>"));
        assert!(
            !en_son_nom("marc", "From: jeanne@exemple.test"),
            "l'adresse d'un autre compte d'ici"
        );
        assert!(
            !en_son_nom("marc", "From: marc@ailleurs.test"),
            "une adresse qui n'est d'aucun compte"
        );
        assert!(!en_son_nom("marc", "Subject: sans expéditeur"));
        assert!(
            !en_son_nom("marc", "From: marc@exemple.test, jeanne@exemple.test"),
            "§3.6.2 : à plusieurs mains, on ne désigne personne"
        );
    }

    /// **LES TROIS CHAMPS DÉSIGNENT DES DESTINATAIRES**, `Bcc` compris.
    ///
    /// Ce qui distingue une copie cachée est qu'elle ne figure pas dans le
    /// message REMIS, et non qu'elle ne serait pas remise.
    #[test]
    fn to_cc_et_bcc_designent_tous_des_destinataires() {
        assert_eq!(
            vers("To: marc@exemple.test\r\nCc: jeanne@exemple.test"),
            Some(std::vec![
                "marc@exemple.test".to_string(),
                "jeanne@exemple.test".to_string()
            ])
        );
        assert_eq!(
            vers("Bcc: jeanne@exemple.test"),
            Some(std::vec!["jeanne@exemple.test".to_string()])
        );
    }

    /// **UN DESTINATAIRE NOMMÉ DEUX FOIS N'EST QU'UN.**
    ///
    /// Écrire `To:` et `Cc:` à la même personne est ordinaire, et lui remettre
    /// deux copies du même message ne l'est pas.
    #[test]
    fn un_destinataire_repete_ne_compte_qu_une_fois() {
        assert_eq!(
            vers("To: marc@exemple.test\r\nCc: \"Marc\" <marc@exemple.test>"),
            Some(std::vec!["marc@exemple.test".to_string()])
        );
    }

    /// **CE SERVEUR NE RELAIE PAS**, et un seul destinataire d'ailleurs fait tout
    /// refuser.
    ///
    /// L'accepter à moitié laisserait l'expéditeur croire que son message est
    /// parti là où il ne partira jamais.
    #[test]
    fn un_destinataire_d_ailleurs_fait_tout_refuser() {
        assert_eq!(vers("To: quelqu-un@ailleurs.test"), None);
        assert_eq!(
            vers("To: marc@exemple.test, quelqu-un@ailleurs.test"),
            None,
            "le premier est d'ici, et cela ne suffit pas"
        );
    }

    /// **UN DESTINATAIRE QU'ON NE SAIT PAS LIRE FAIT TOUT REFUSER.**
    ///
    /// L'écarter en silence remettrait le message à moins de monde que
    /// l'expéditeur ne l'a demandé, et rien dans la réponse ne le lui dirait.
    #[test]
    fn un_destinataire_illisible_fait_tout_refuser() {
        assert_eq!(vers("To: marc @ exemple.test"), None);
        assert_eq!(vers("To: pas-d-arobase"), None);
    }

    /// **UN MESSAGE SANS DESTINATAIRE NE VA NULLE PART**, et n'est pas un dépôt.
    #[test]
    fn un_message_sans_destinataire_se_refuse() {
        assert_eq!(vers("From: marc@exemple.test"), None);
        assert_eq!(
            vers("To:"),
            None,
            "un champ présent et vide ne désigne rien"
        );
    }

    /// **AU-DELÀ DE LA BORNE, ON REFUSE PLUTÔT QUE DE TRONQUER.**
    ///
    /// Remettre à soixante-quatre destinataires sur cent laisserait l'expéditeur
    /// croire que les trente-six autres l'ont reçu.
    #[test]
    fn trop_de_destinataires_fait_refuser() {
        // **UN PAR LIGNE** : §2.1.1 de RFC 5322 borne une ligne à neuf cent
        // quatre-vingt-dix-huit caractères, et une liste d'une seule ligne ferait
        // refuser l'en-tête avant qu'on n'atteigne la borne qu'on éprouve.
        let liste = |combien: usize| {
            let mut champ = std::string::String::from("To:");
            for rang in 0..combien {
                champ.push_str(&std::format!("\r\n d{rang}@exemple.test,"));
            }
            champ.push_str("\r\n marc@exemple.test");
            champ
        };

        let juste = vers(&liste(super::DESTINATAIRES_MAX - 1)).expect("à la borne, cela passe");
        assert_eq!(juste.len(), super::DESTINATAIRES_MAX);
        assert_eq!(
            vers(&liste(super::DESTINATAIRES_MAX)),
            None,
            "un de plus, et l'on refuse plutôt que de tronquer"
        );
    }

    /// **LE `Bcc` NE PART PAS, ET RIEN D'AUTRE NE CHANGE** (§3.6.3 de RFC 5322).
    ///
    /// Une copie cachée est cachée — y compris pour celui qui y figure : il sait
    /// déjà qu'il l'a reçu, et lui montrer la liste révélerait les autres.
    ///
    /// Et un message qu'on remanierait davantage ne serait plus celui que
    /// l'expéditeur a signé : les autres champs gardent leur ordre et leur texte,
    /// le corps se recopie tel quel.
    #[test]
    fn le_bcc_ne_part_pas_et_rien_d_autre_ne_change() {
        // **`concat!` PLUTÔT QU'UN LITTÉRAL CONTINUÉ** : `cargo fmt` recolle les
        // lignes d'un littéral coupé par `\`, et les espaces d'indentation
        // deviennent alors un repliement — l'en-tête ne se termine plus, et
        // l'essai n'éprouve plus ce qu'il croit.
        let brut = concat!(
            "From: marc@exemple.test\r\n",
            "To: jeanne@exemple.test\r\n",
            "Bcc: d0@exemple.test\r\n",
            "Subject: =?utf-8?Q?bonjour?=\r\n",
            "\r\n",
            "le corps, avec un Bcc: qui n'en est pas un\r\n",
        )
        .as_bytes();
        let bornes = ams_mime::Limits::DEFAULT;
        let message = ams_mime::Message::parse(brut, &bornes).expect("lisible");
        let remis = message_a_remettre(brut, &message, &bornes).expect("réécrit");
        let texte = std::string::String::from_utf8_lossy(&remis).into_owned();

        // **ON REGARDE L'EN-TÊTE, ET NON TOUT LE MESSAGE** : le corps de cet
        // essai porte exprès les lettres `Bcc:`, pour montrer qu'on ne le
        // remanie pas. Chercher dans tout le texte confondrait les deux.
        let entete = texte.split("\r\n\r\n").next().unwrap_or_default();
        assert!(
            !entete.contains("Bcc:"),
            "la copie cachée reste cachée : {entete}"
        );
        assert!(texte.contains("From: marc@exemple.test\r\n"));
        assert!(texte.contains("To: jeanne@exemple.test\r\n"));
        assert!(
            texte.contains("Subject: =?utf-8?Q?bonjour?=\r\n"),
            "un sujet ne se décode pas en chemin : {texte}"
        );
        assert!(
            texte.ends_with("le corps, avec un Bcc: qui n'en est pas un\r\n"),
            "le corps se recopie tel quel : {texte}"
        );
    }

    /// **UN MESSAGE SANS `Bcc` TRAVERSE SANS ÊTRE TOUCHÉ.**
    #[test]
    fn un_message_sans_bcc_traverse_tel_quel() {
        let brut = b"From: marc@exemple.test\r\nTo: jeanne@exemple.test\r\n\r\nbonjour";
        let bornes = ams_mime::Limits::DEFAULT;
        let message = ams_mime::Message::parse(brut, &bornes).expect("lisible");
        let remis = message_a_remettre(brut, &message, &bornes).expect("réécrit");
        assert_eq!(remis, brut, "rien à retirer, rien à changer");
    }

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
