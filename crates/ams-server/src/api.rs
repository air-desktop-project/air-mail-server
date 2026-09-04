// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que l'API REST sert, lu dans le magasin.
//!
//! # UNE SEULE VUE DU MAGASIN POUR LES DEUX PROTOCOLES
//!
//! Ce module ne lit pas les Maildir : il interroge le MÊME [`Mailboxes`](ams_session::imap::Mailboxes) qu'IMAP.
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
//! Tout est servi : le courrier, les jetons, la supervision, la soumission et
//! l'administration — **y compris ce qui modifie le magasin de comptes**. Celui-ci
//! est modifiable pendant qu'on sert : voir `crate::comptes`.
//!
//! # ET LE JETON D'ADMINISTRATION SE FRAPPE AILLEURS
//!
//! `air-mail-admin token` le scelle avec le secret que la configuration porte,
//! donc depuis la machine du serveur. C'est la même autorité que celle qui peut
//! arrêter le service ou lire les boîtes : on n'en ajoute aucune, et la phrase
//! ci-dessus reste vraie mot pour mot.

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

/// Ce qu'un mot de passe peut occuper, une fois déséchappé.
///
/// Deux cent cinquante-six octets. Ce n'est pas une politique de mot de passe —
/// il n'y en a pas — c'est la taille du tampon qu'on prête au lecteur de JSON.
const MOT_DE_PASSE_MAX: usize = 256;

/// Combien d'adresses un compte peut déclarer.
///
/// Trente-deux. Aucune RFC ne le borne : c'est le nombre d'adresses qu'un seul
/// corps de requête peut faire écrire dans le magasin.
const ADRESSES_MAX: usize = 32;

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
    comptes: Arc<crate::comptes::Comptes>,
    /// Les mêmes boîtes que la remise SMTP, pour y déposer une soumission.
    ///
    /// **LE MÊME CHEMIN, ET NON UN SECOND** : un message déposé par l'API doit
    /// arriver comme celui qui entre par SMTP — même écriture, même validation,
    /// même magasin. Une seconde façon de remettre finirait par diverger, et deux
    /// messages identiques n'auraient pas le même sort selon la porte d'entrée.
    remise: Arc<crate::delivery::Boites>,
    /// Les domaines qu'on héberge, tels que la configuration les nomme.
    domaines: Arc<Vec<String>>,
    /// Le videur (C8), pour voir et lever ses bannissements.
    ///
    /// **LE MÊME QUE CELUI QUI PUNIT**, et non une copie : un état par voie de
    /// lecture montrerait des peines que le garde n'applique pas, et en cacherait
    /// qu'il applique.
    guard: Arc<ams_loop_tokio::SharedGuard>,
    /// Ce qui rate à la remise, compté et dit — LE MÊME que celui de SMTP.
    ///
    /// Deux compteurs diraient deux fois la première ligne, et donneraient à
    /// l'exploitant deux bilans qu'il devrait additionner lui-même.
    incidents: Arc<crate::incidents::Incidents>,
    /// La borne sur les vérifications simultanées.
    places: Places,
    /// La file de réémission, quand l'émission est ouverte.
    ///
    /// **`None` FERME LA PORTE**, exactement comme du côté SMTP : une soumission
    /// qui nomme un destinataire d'ailleurs est refusée, et rien ne sort. C'est
    /// aussi ce qui fait que les deux portes n'ont pas deux règles.
    file: Option<ams_loop_tokio::Spool>,
    /// Ce qu'un message peut peser, pour borner ce qu'on rassemble en file.
    message_max: usize,
    /// De quoi signer ce qui sort (RFC 6376), quand une clé est nommée.
    ///
    /// **LA MÊME QUE DU CÔTÉ SMTP** : les deux portes de soumission n'ont pas
    /// deux règles, pas plus pour la signature que pour le relais.
    dkim: Option<ams_loop_tokio::DkimSigner>,
}

impl ApiMaildir {
    /// Monte l'API sur le service de boîtes et le magasin de comptes.
    #[must_use]
    pub fn new(
        boites: Arc<BoitesImap>,
        comptes: Arc<crate::comptes::Comptes>,
        remise: Arc<crate::delivery::Boites>,
        domaines: Arc<Vec<String>>,
        guard: Arc<ams_loop_tokio::SharedGuard>,
        incidents: Arc<crate::incidents::Incidents>,
    ) -> Self {
        Self {
            boites,
            comptes,
            remise,
            domaines,
            guard,
            incidents,
            places: Places::new(VERIFICATIONS_SIMULTANEES),
            // ON N'ÉMET PAS, SAUF DEMANDE EXPRESSE — et le constructeur ne prend
            // pas ce champ : un argument de plus dans une liste qui en compte
            // déjà sept se passe à l'envers sans que le compilateur bronche, et
            // celui-ci ouvre un relais.
            file: None,
            message_max: 0,
            // ON NE SIGNE PAS SANS CLÉ, et le constructeur ne prend pas ce
            // champ non plus : une signature qu'on produirait sans clé publiée
            // échouerait partout, ce qui est pire que pas de signature.
            dkim: None,
        }
    }

    /// Lui donne de quoi signer ce qu'elle met en file (RFC 6376).
    #[must_use]
    pub fn avec_dkim(mut self, signataire: ams_loop_tokio::DkimSigner) -> Self {
        self.dkim = Some(signataire);
        self
    }

    /// Lui donne de quoi mettre en file ce qui n'est pas d'ici.
    ///
    /// **C'est la seule façon d'ouvrir l'émission par l'API**, et elle laisse une
    /// ligne à lire au démarrage du serveur.
    #[must_use]
    pub fn avec_file(mut self, file: ams_loop_tokio::Spool, message_max: usize) -> Self {
        self.file = Some(file);
        self.message_max = message_max;
        self
    }

    /// La liste des comptes.
    ///
    /// **AUCUNE EMPREINTE N'EN SORT** : la représentation d'un compte n'en porte
    /// pas, et le mot de passe est une ressource à part qui ne se lit pas.
    fn accounts<'o>(&self, sortie: &'o mut [u8]) -> Served<'o> {
        let vue = self.comptes.vue();
        let adresses: std::vec::Vec<std::vec::Vec<&str>> = vue
            .iter()
            .map(|compte| compte.addresses.iter().map(String::as_str).collect())
            .collect();
        let lignes: std::vec::Vec<render::AccountRow<'_>> = vue
            .iter()
            .zip(&adresses)
            .map(|(compte, adresses)| render::AccountRow {
                login: &compte.login,
                addresses: adresses,
            })
            .collect();
        rendre(render::write_accounts(&lignes, sortie))
    }

    /// Un compte.
    fn account<'o>(&self, nom: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let vue = self.comptes.vue();
        let Some(compte) = vue.iter().find(|compte| compte.login == nom) else {
            return absente(sortie);
        };
        let adresses: std::vec::Vec<&str> = compte.addresses.iter().map(String::as_str).collect();
        rendre(render::write_account(
            &render::AccountRow {
                login: &compte.login,
                addresses: &adresses,
            },
            sortie,
        ))
    }

    /// Crée un compte, ou remplace celui qui portait ce nom.
    ///
    /// # POURQUOI LA BOÎTE S'OUVRE AVANT QUE LE COMPTE NE SOIT ÉCRIT
    ///
    /// Un compte sans boîte s'authentifierait et ne recevrait rien : un
    /// demi-compte, que rien ne signale. Si la boîte ne peut pas s'ouvrir —
    /// disque plein, permissions — le compte n'est pas écrit et rien n'a changé.
    ///
    /// L'ordre inverse laisserait un compte inscrit sans boîte, et il faudrait le
    /// réparer à la main.
    ///
    /// **UN RÉPERTOIRE QUI SURVIT À UN ÉCHEC N'EST PAS UN PROBLÈME** : une boîte
    /// vide ne se distingue pas d'une boîte neuve, et la tentative suivante la
    /// réemploie.
    fn poser_un_compte<'o>(
        &self,
        nom: &str,
        corps: &[u8],
        remplacer: bool,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let mut secret = [0_u8; MOT_DE_PASSE_MAX];
        let mut place = [""; ADRESSES_MAX];
        let Ok(lu) = render::read_account_body(corps, &mut secret, &mut place) else {
            return refus_de_corps(sortie);
        };
        // §3.4 de RFC 9110 : l'identité d'une ressource est son URI. Un `login`
        // dans le corps qui contredirait le chemin poserait la question de savoir
        // lequel des deux nomme le compte, et il n'y a pas de bonne réponse.
        if lu.login.is_some_and(|dit| dit != nom) {
            return refus_de_compte(sortie);
        }
        let (Some(secret), Some(combien)) = (lu.password, lu.addresses) else {
            // Créer un compte demande les deux : sans secret il ne s'authentifie
            // pas, et une liste d'adresses absente n'est pas une liste vide.
            return refus_de_corps(sortie);
        };
        let adresses: std::vec::Vec<String> = place
            .get(..combien)
            .unwrap_or_default()
            .iter()
            .map(|adresse| (*adresse).to_string())
            .collect();

        let existait = self.comptes.vue().iter().any(|vu| vu.login == nom);
        if existait && !remplacer {
            return conflit(sortie);
        }
        let Some(hash) = self.empreinte(secret.as_bytes()) else {
            return notre_faute();
        };
        // **LA BOÎTE D'ABORD.**
        if self.ouvrir_la_boite(nom).is_none() {
            return indisponible(sortie);
        }

        let compte = Account {
            login: nom.to_string(),
            hash,
            addresses: adresses,
        };
        if let Err(quoi) = self.comptes.modifier(|comptes| {
            comptes.retain(|vu| vu.login != nom);
            comptes.push(compte);
            Ok(())
        }) {
            return dire_la_faute(&quoi, sortie);
        }
        let servi = self.account(nom, sortie);
        Served {
            status: match existait {
                true => StatusCode::OK,
                false => StatusCode::CREATED,
            },
            ..servi
        }
    }

    /// Retire un compte.
    ///
    /// # LA BOÎTE RESTE SUR LE DISQUE, ET C'EST DÉLIBÉRÉ
    ///
    /// Effacer les messages d'un compte est irréversible, et rien dans « retirer
    /// un compte » ne demande cela — un administrateur qui retire un compte par
    /// erreur doit pouvoir le remettre. C'est aussi ce que fait déjà
    /// `air-mail-admin account remove`, et deux outils qui feraient deux choses
    /// différentes du même mot seraient un piège.
    ///
    /// Le répertoire se supprime à la main, quand on l'a décidé.
    fn retirer_un_compte<'o>(&self, nom: &str, sortie: &'o mut [u8]) -> Served<'o> {
        if !self.comptes.vue().iter().any(|vu| vu.login == nom) {
            return absente(sortie);
        }
        if let Err(quoi) = self.comptes.modifier(|comptes| {
            comptes.retain(|vu| vu.login != nom);
            Ok(())
        }) {
            return dire_la_faute(&quoi, sortie);
        }
        // La carte des boîtes suit le magasin : une boîte qui resterait
        // accessible sans compte serait servie à un nom que plus rien n'authentifie.
        self.remise.retirer(nom);
        Served {
            status: StatusCode::NO_CONTENT,
            media: JSON_MEDIA_TYPE,
            body: &[],
            ..Served::default()
        }
    }

    /// Change le secret d'un compte.
    fn poser_un_secret<'o>(&self, nom: &str, corps: &[u8], sortie: &'o mut [u8]) -> Served<'o> {
        let mut secret = [0_u8; MOT_DE_PASSE_MAX];
        let mut place = [""; ADRESSES_MAX];
        let Ok(lu) = render::read_account_body(corps, &mut secret, &mut place) else {
            return refus_de_corps(sortie);
        };
        // **CE QU'ON N'EMPLOIE PAS, ON LE REFUSE** : accepter `addresses` ici en
        // silence ferait croire au client qu'on les a changées.
        let (Some(secret), None, None) = (lu.password, lu.login, lu.addresses) else {
            return refus_de_corps(sortie);
        };
        if !self.comptes.vue().iter().any(|vu| vu.login == nom) {
            return absente(sortie);
        }
        let Some(hash) = self.empreinte(secret.as_bytes()) else {
            return notre_faute();
        };
        match self.comptes.modifier(|comptes| {
            let compte = comptes
                .iter_mut()
                .find(|vu| vu.login == nom)
                .ok_or(crate::comptes::Faute::Introuvable)?;
            compte.hash = hash;
            Ok(())
        }) {
            Ok(()) => Served {
                status: StatusCode::NO_CONTENT,
                media: JSON_MEDIA_TYPE,
                body: &[],
                ..Served::default()
            },
            Err(quoi) => dire_la_faute(&quoi, sortie),
        }
    }

    /// Remplace les adresses d'un compte.
    fn poser_des_adresses<'o>(&self, nom: &str, corps: &[u8], sortie: &'o mut [u8]) -> Served<'o> {
        let mut secret = [0_u8; MOT_DE_PASSE_MAX];
        let mut place = [""; ADRESSES_MAX];
        let Ok(lu) = render::read_account_body(corps, &mut secret, &mut place) else {
            return refus_de_corps(sortie);
        };
        let (Some(combien), None, None) = (lu.addresses, lu.login, lu.password) else {
            return refus_de_corps(sortie);
        };
        let adresses: std::vec::Vec<String> = place
            .get(..combien)
            .unwrap_or_default()
            .iter()
            .map(|adresse| (*adresse).to_string())
            .collect();
        if !self.comptes.vue().iter().any(|vu| vu.login == nom) {
            return absente(sortie);
        }
        match self.comptes.modifier(|comptes| {
            let compte = comptes
                .iter_mut()
                .find(|vu| vu.login == nom)
                .ok_or(crate::comptes::Faute::Introuvable)?;
            compte.addresses = adresses;
            Ok(())
        }) {
            Ok(()) => self.account(nom, sortie),
            Err(quoi) => dire_la_faute(&quoi, sortie),
        }
    }

    /// Les adresses d'un compte, seules.
    fn adresses_de<'o>(&self, nom: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let vue = self.comptes.vue();
        let Some(compte) = vue.iter().find(|vu| vu.login == nom) else {
            return absente(sortie);
        };
        let adresses: std::vec::Vec<&str> = compte.addresses.iter().map(String::as_str).collect();
        rendre(render::write_domains(&adresses, sortie))
    }

    /// L'empreinte d'un secret, au sel du noyau.
    ///
    /// **LES MÊMES DEUX PRÉCAUTIONS QUE POUR LA VÉRIFICATION** : `block_in_place`,
    /// parce qu'Argon2id est délibérément lent, et la borne sur les calculs
    /// simultanés, parce que chacun réclame dix-neuf mébioctets.
    fn empreinte(&self, secret: &[u8]) -> Option<String> {
        let sel = self.sel()?;
        tokio::task::block_in_place(|| {
            self.places
                .occuper(|| ams_auth::hash_password(secret, &sel).ok())
        })
    }

    /// Seize octets d'aléa, tirés du noyau.
    ///
    /// **UN SEL PAR COMPTE, ET JAMAIS DEUX FOIS LE MÊME** : c'est ce qui empêche
    /// de reconnaître deux comptes qui ont choisi le même mot de passe, et de
    /// précalculer une table pour tous.
    fn sel(&self) -> Option<[u8; 16]> {
        use std::io::Read as _;
        let mut graine = [0_u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut graine))
            .ok()?;
        Some(graine)
    }

    /// Ouvre la boîte de ce compte, et la pose dans la carte.
    ///
    /// **AVANT QUE LE COMPTE N'EXISTE**, donc par [`Boites::ouvrir`] et non par
    /// `get` : le magasin ne peut pas encore répondre pour un compte qu'on est en
    /// train de créer. La mécanique, elle, est celle de la carte — une boîte ne
    /// naît qu'à un seul endroit.
    ///
    /// `block_in_place` parce qu'ouvrir un Maildir relit son index : c'est une
    /// attente sur le disque, et cette tâche-ci sert une requête HTTP.
    fn ouvrir_la_boite(&self, nom: &str) -> Option<()> {
        tokio::task::block_in_place(|| self.remise.ouvrir(nom)).map(|_| ())
    }

    /// Les domaines qu'on héberge.
    fn domains<'o>(&self, sortie: &'o mut [u8]) -> Served<'o> {
        let noms: std::vec::Vec<&str> = self.domaines.iter().map(String::as_str).collect();
        rendre(render::write_domains(&noms, sortie))
    }

    /// Les bannissements en cours (C8).
    fn bans<'o>(&self, sortie: &'o mut [u8]) -> Served<'o> {
        let vus = self.guard.banned();
        let textes: std::vec::Vec<(std::string::String, u8, u64)> = vus
            .iter()
            .map(|(cle, reste)| (adresse_de(cle), bits_de(cle), *reste))
            .collect();
        let lignes: std::vec::Vec<render::BanRow<'_>> = textes
            .iter()
            .map(|(source, prefixe, reste)| render::BanRow {
                source,
                prefix: *prefixe,
                seconds: *reste,
            })
            .collect();
        rendre(render::write_bans(&lignes, sortie))
    }

    /// Lève un bannissement.
    ///
    /// # `204` QU'IL Y AIT EU QUELQUE CHOSE À LEVER OU NON
    ///
    /// §15.3.5 de RFC 9110 : `204` dit que la demande a abouti et qu'il n'y a rien
    /// à rendre. Une source non bannie EST dans l'état demandé — « qu'elle ne soit
    /// pas bannie » —, et répondre `404` ferait de cette ressource un moyen de
    /// SONDER qui est banni sans avoir à lister.
    fn lift<'o>(&self, source: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let Some(vue) = source_de(source) else {
            return absente(sortie);
        };
        self.guard.lift(vue);
        Served {
            status: StatusCode::NO_CONTENT,
            media: JSON_MEDIA_TYPE,
            body: &[],
            ..Served::default()
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
        let vue = self.comptes.vue();
        let Some(expediteur) = ecrit_bien_en_son_nom(&vue, compte, &message) else {
            // **LA MÊME RÈGLE QUE SMTP, ET DÉSORMAIS LE MÊME AVEU.** Cette porte
            // refusait l'usurpation en silence : le `400` partait au déposant, et
            // l'exploitant n'apprenait rien d'un compte authentifié qui tente
            // d'écrire au nom d'un autre. C'est précisément ce qu'il veut voir.
            crate::incidents::dire(&self.incidents, crate::incidents::Cause::Usurpation);
            return refus_de_depot(sortie);
        };
        let Some(destinataires) = destinataires_de(&vue, &message, self.file.is_some()) else {
            return refus_de_depot(sortie);
        };

        let Some(remis) = message_a_remettre(corps, &message, &bornes) else {
            return notre_faute();
        };

        let mut remise = crate::delivery::MaildirDelivery::new(
            std::sync::Arc::clone(&self.remise),
            std::sync::Arc::clone(&self.comptes),
            std::sync::Arc::clone(&self.incidents),
        );
        if let Some(file) = self.file.clone() {
            remise = remise.avec_file(file, self.message_max);
        }
        remise = remise.avec_domaines(std::sync::Arc::clone(&self.domaines));
        if let Some(signataire) = self.dkim.clone() {
            remise = remise.avec_dkim(signataire);
        }
        let issue = deposer(&mut remise, expediteur, &destinataires, &remis);
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

    /// Le message entier, tel qu'il est sur le disque.
    ///
    /// # POURQUOI CETTE RESSOURCE SE LIT PAR MORCEAUX, ET SEULE
    ///
    /// Un message fait la taille que son expéditeur a voulue. Une réponse de
    /// cette API rend une tranche d'un tampon que la boucle a alloué. Sans les
    /// portées de §14 de RFC 9110, un message entier ne se lirait pas du tout par
    /// HTTP — ce n'est pas un confort qui manquerait, c'est la ressource.
    fn message_brut<'o>(
        &self,
        compte: &str,
        nom: &str,
        uid: u64,
        portee: Option<&[u8]>,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some((boite, sequence, info)) = self.trouver(compte, nom, uid) else {
            return absente(sortie);
        };
        self.ecouler(&boite, sequence, 0, info.size, portee, sortie)
    }

    /// Une partie MIME d'un message, telle que §6.4.5 la numérote.
    fn partie_de_message<'o>(
        &self,
        compte: &str,
        nom: &str,
        uid: u64,
        chemin: &str,
        portee: Option<&[u8]>,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some((boite, sequence, _info)) = self.trouver(compte, nom, uid) else {
            return absente(sortie);
        };
        // §6.4.5 : `1`, `2.1`, `3.2.4`. Un segment qui n'est pas un nombre ne
        // désigne aucune partie, et deviner ce qu'il voulait dire serait servir
        // autre chose que ce qu'on a demandé.
        let mut rangs: std::vec::Vec<u32> = std::vec::Vec::new();
        for morceau in chemin.split('.') {
            let Ok(rang) = morceau.parse::<u32>() else {
                return absente(sortie);
            };
            if rang == 0 {
                return absente(sortie);
            }
            rangs.push(rang);
        }
        // **UN DÉBUT ET UNE FIN, ET NON UNE LONGUEUR** : `part_span` rend un
        // intervalle. Les confondre faisait lire au-delà du fichier, et la
        // lecture échouait — une partie parfaitement présente rendait `404`.
        let Some((debut, fin)) = boite.partie(sequence, &rangs) else {
            return absente(sortie);
        };
        self.ecouler(
            &boite,
            sequence,
            debut,
            fin.saturating_sub(debut),
            portee,
            sortie,
        )
    }

    /// La boîte, le rang et ce qu'on sait du message que cet UID désigne.
    fn trouver(
        &self,
        compte: &str,
        nom: &str,
        uid: u64,
    ) -> Option<(crate::imap::BoiteImap, u32, ams_session::imap::MessageInfo)> {
        let boite = self.boites.open(compte.as_bytes(), nom.as_bytes())?;
        let voulu = u32::try_from(uid).ok()?;
        (1..=boite.exists())
            .filter_map(|sequence| boite.info(sequence).map(|info| (sequence, info)))
            .find(|(_, info)| info.uid == voulu)
            .map(|(sequence, info)| (boite, sequence, info))
    }

    /// Écoule `complete` octets à partir de `origine`, selon ce que le client
    /// demande.
    ///
    /// # SANS `Range`, ON NE MENT PAS
    ///
    /// Si tout tient, on rend tout, avec `Accept-Ranges` pour dire que la porte
    /// existe. Si tout ne tient pas, il n'y a pas de réponse conforme : envoyer
    /// l'entier est impossible, un `206` qu'on n'a pas demandé n'est pas conforme
    /// (§15.3.7), et tronquer en silence serait mentir.
    ///
    /// On répond alors `413` avec `Accept-Ranges`, ce qui veut dire : « je ne
    /// peux pas te l'envoyer d'un coup, voici la porte ». **C'est un écart, et il
    /// est assumé** : ce serveur ne sait pas écouler une réponse, et le dire vaut
    /// mieux que de rendre la moitié d'un message.
    fn ecouler<'o>(
        &self,
        boite: &crate::imap::BoiteImap,
        sequence: u32,
        origine: u64,
        complete: u64,
        portee: Option<&[u8]>,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let fenetre = sortie.len().min(FENETRE_MAX);
        let demandee = portee.map(|valeur| ams_proto_http::parse_range(valeur, complete));

        let (debut, combien, partiel) = match demandee {
            // §15.5.17 : ce qui commence au-delà ne peut pas être satisfait.
            Some(Err(ams_proto_http::RangeFault::Unsatisfiable)) => {
                return hors_bornes(complete, sortie);
            }
            Some(Ok(voulue)) => {
                let combien = usize::try_from(voulue.octets())
                    .unwrap_or(usize::MAX)
                    .min(fenetre);
                (voulue.first, combien, true)
            }
            // §14.2 : un champ qu'on ne comprend pas s'ignore, et l'on répond
            // comme s'il n'était pas là.
            Some(Err(ams_proto_http::RangeFault::Ignored)) | None => {
                let entier = usize::try_from(complete).unwrap_or(usize::MAX);
                if entier > fenetre {
                    return trop_grand(sortie);
                }
                (0, entier, false)
            }
        };

        let Some(octets) = boite.fenetre(sequence, origine.saturating_add(debut), combien) else {
            return absente(sortie);
        };
        let place = sortie.get_mut(..octets.len()).unwrap_or_default();
        place.copy_from_slice(&octets);
        let rendu = sortie.get(..octets.len()).unwrap_or_default();

        let dernier = debut.saturating_add(octets.len() as u64).saturating_sub(1);
        Served {
            status: match partiel {
                true => StatusCode::PARTIAL_CONTENT,
                false => StatusCode::OK,
            },
            media: ams_api::MESSAGE_MEDIA_TYPE,
            body: rendu,
            ranges: true,
            range: partiel.then_some(ams_loop_tokio::http::ContentRange {
                part: Some((debut, dernier)),
                complete,
            }),
        }
    }

    /// Cherche dans une boîte.
    ///
    /// # ON RÉEMPLOIE L'ÉVALUATEUR D'IMAP, ET ON NE LE RÉÉCRIT PAS
    ///
    /// `ams-proto-imap` sait déjà décider si un message correspond à une
    /// expression, et `BoiteImap` sait déjà lui lire ce qu'il demande — c'est ce
    /// qui sert `SEARCH`. Un second évaluateur aurait fini par répondre
    /// différemment de celui d'IMAP sur le même message, et personne ne saurait
    /// lequel croire.
    ///
    /// Les critères JSON se traduisent donc vers la syntaxe de §6.4.4, et
    /// `write_quoted` échappe les textes : un sujet portant un guillemet aurait
    /// coupé l'expression en deux, et la recherche aurait porté sur la moitié.
    fn search<'o>(
        &self,
        compte: &str,
        nom: &str,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Ok(criteres) = render::read_search_criteria(corps) else {
            return refus_de_corps(sortie);
        };
        // **UNE RECHERCHE SANS CRITÈRE N'EN EST PAS UNE** : elle rendrait la boîte
        // entière, ce que la liste des messages fait déjà, en paginé.
        if criteres.is_empty() {
            return refus_de_corps(sortie);
        }
        let Some(expression) = expression_de(&criteres) else {
            return refus_de_corps(sortie);
        };
        let Some(boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };
        let bornes = ams_proto_imap::Limits::DEFAULT;
        let Ok(recherche) = ams_proto_imap::Search::parse(&expression, &bornes) else {
            return refus_de_corps(sortie);
        };

        let exists = boite.exists();
        let dernier = boite.info(exists).map_or(0, |info| info.uid);
        let mut trouves = std::vec::Vec::with_capacity(PAGE_MAX);
        let mut complet = true;
        for sequence in 1..=exists {
            let Some(info) = boite.info(sequence) else {
                continue;
            };
            if trouves.len() >= RESULTATS_MAX {
                // **ON LE DIT** : un client qui croirait avoir tous les résultats
                // agirait sur une moitié.
                complet = false;
                break;
            }
            let candidat = ams_proto_imap::Candidate {
                sequence,
                uid: info.uid,
                size: info.size,
                flags: info.flags,
                internal_date: info.internal_date,
            };
            let mut source = Lecteur {
                boite: &boite,
                sequence,
            };
            if recherche.matches(&candidat, exists, dernier, &mut source) {
                trouves.push(info.uid);
            }
        }
        rendre(render::write_search(
            &trouves,
            boite.uid_validity(),
            complet,
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
        method: Method,
        account: &str,
        body: &[u8],
        portee: Option<&[u8]>,
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
            Resource::MessageRaw { boite, uid } => {
                self.message_brut(account, boite, uid, portee, sortie)
            }
            Resource::MessagePart { boite, uid, partie } => {
                self.partie_de_message(account, boite, uid, partie, portee, sortie)
            }
            Resource::Search { boite } => self.search(account, boite, body, sortie),
            Resource::Submissions => self.submissions(account, body, sortie),
            // **L'ADMINISTRATION, EN LECTURE ET EN ÉCRITURE.** Le magasin est
            // modifiable pendant qu'on sert : voir `crate::comptes`.
            Resource::Accounts if matches!(method, Method::Post) => {
                // **`POST` CRÉE, ET REFUSE DE REMPLACER** : le nom vient alors du
                // corps, puisque le chemin ne le porte pas.
                let mut secret = [0_u8; MOT_DE_PASSE_MAX];
                let mut place = [""; ADRESSES_MAX];
                match render::read_account_body(body, &mut secret, &mut place) {
                    Ok(lu) => match lu.login {
                        Some(nom) => self.poser_un_compte(nom, body, false, sortie),
                        None => refus_de_corps(sortie),
                    },
                    Err(_) => refus_de_corps(sortie),
                }
            }
            Resource::Accounts => self.accounts(sortie),
            // **`PUT` POSE UN ÉTAT** : il crée ou remplace, et redemander le même
            // état deux fois donne le même résultat (§9.3.4 de RFC 9110).
            Resource::Account { compte } if matches!(method, Method::Put) => {
                self.poser_un_compte(compte, body, true, sortie)
            }
            Resource::Account { compte } if matches!(method, Method::Delete) => {
                self.retirer_un_compte(compte, sortie)
            }
            Resource::Account { compte } => self.account(compte, sortie),
            Resource::AccountPassword { compte } => self.poser_un_secret(compte, body, sortie),
            Resource::AccountAddresses { compte } if matches!(method, Method::Put) => {
                self.poser_des_adresses(compte, body, sortie)
            }
            Resource::AccountAddresses { compte } => self.adresses_de(compte, sortie),
            Resource::Domains => self.domains(sortie),
            Resource::Bans => self.bans(sortie),
            Resource::Ban { source } if matches!(method, Method::Delete) => {
                self.lift(source, sortie)
            }
            // **IL NE RESTE RIEN À SERVIR ICI** : `Tokens` et `CurrentToken` se
            // décident dans la session, avant que cette interface ne soit
            // appelée. Ce bras existe pour que le jour où une ressource
            // s'ajoute au routage sans être servie, elle le DISE (§15.6.2) au
            // lieu d'être servie de travers.
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
                .occuper(|| ams_auth::authenticate(&self.comptes.vue(), &identifiants))
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
            ..Served::default()
        },
        // **LE TAMPON EST LE NÔTRE** : le client n'y peut rien, et le lui dire
        // précisément ne l'avancerait pas.
        Err(_) => Served {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: &[],
            ..Served::default()
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
            ..Served::default()
        },
        Err(_) => Served {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: &[],
            ..Served::default()
        },
    }
}

/// Le `From:` du message appartient-il à ce compte ?
fn ecrit_bien_en_son_nom<'m>(
    comptes: &[Account],
    compte: &str,
    message: &ams_mime::Message<'m>,
) -> Option<&'m [u8]> {
    let champ = message.fields().find(|champ| champ.name_is(b"from"))?;
    let adresse = ams_mime::bare_address(champ.raw_value())?;
    // **L'ADRESSE EST RENDUE, ET NON SEULEMENT VÉRIFIÉE** : c'est elle qui
    // devient le chemin de retour d'un message mis en file, donc l'adresse à
    // laquelle un rapport de non-remise reviendra. La retrouver ailleurs
    // reviendrait à la relire deux fois, et deux lectures d'un même champ
    // finissent par ne plus dire la même chose.
    ams_auth::route(comptes, adresse)
        .is_some_and(|vu| vu.login == compte)
        .then_some(adresse)
}

/// Les destinataires du message, s'ils sont tous lisibles et tous servables.
///
/// **UN SEUL QU'ON NE SAIT PAS LIRE FAIT TOUT REFUSER.** L'écarter en silence
/// remettrait le message à moins de monde que l'expéditeur ne l'a demandé, et
/// rien dans la réponse ne le lui dirait.
///
/// # `relaie` EST CE QUI SÉPARE UNE SOUMISSION D'UN RELAIS OUVERT
///
/// Faux, seules les adresses d'ici sont acceptées, et c'était le seul
/// comportement avant que l'émission n'existe. Vrai, une adresse d'ailleurs
/// passe aussi — et la remise la mettra en file.
///
/// **Le porteur du jeton est déjà authentifié** quand on arrive ici : cette
/// ressource n'est servie qu'à un compte, avec la portée de soumission. C'est le
/// pendant exact de ce que la session SMTP exige, et les deux portes appliquent
/// donc la même règle.
fn destinataires_de(
    comptes: &[Account],
    message: &ams_mime::Message<'_>,
    relaie: bool,
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
            if ams_auth::route(comptes, adresse).is_none() && !relaie {
                return None;
            }
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

/// L'adresse d'un préfixe, telle qu'on la rend et telle qu'on la relit.
///
/// **SANS SA LONGUEUR** : une barre oblique dans un chemin fait deux segments
/// d'un seul (§3.3 de RFC 3986), et le routage y verrait une autre ressource. La
/// longueur voyage donc dans un champ à part.
fn adresse_de(cle: &ams_guard::Key) -> std::string::String {
    let octets = cle.octets();
    if cle.is_v6() {
        let mut adresse = [0_u16; 8];
        for (rang, place) in adresse.iter_mut().enumerate() {
            let haut = octets.get(rang.saturating_mul(2)).copied().unwrap_or(0);
            let bas = octets.get(rang.saturating_mul(2).saturating_add(1));
            *place = u16::from(haut)
                .saturating_mul(256)
                .saturating_add(u16::from(bas.copied().unwrap_or(0)));
        }
        return std::net::Ipv6Addr::from(adresse).to_string();
    }
    let mut quatre = [0_u8; 4];
    quatre.copy_from_slice(octets.get(..4).unwrap_or(&[0; 4]));
    std::net::Ipv4Addr::from(quatre).to_string()
}

/// Combien de bits le préfixe de cette clé couvre.
///
/// **ON LE DEMANDE AUX SEUILS, ET NON À LA CLÉ** : la clé porte des octets
/// masqués, pas la longueur qui les a masqués. Deux sources d'une même vérité
/// finiraient par différer.
fn bits_de(cle: &ams_guard::Key) -> u8 {
    let seuils = ams_guard::Thresholds::DEFAULT;
    match cle.is_v6() {
        true => seuils.ipv6_prefix_bits,
        false => seuils.ipv4_prefix_bits,
    }
}

/// La source que ce texte désigne, s'il en désigne une.
fn source_de(texte: &str) -> Option<ams_guard::Source> {
    match texte.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(adresse) => Some(ams_guard::Source::V4(adresse.octets())),
        std::net::IpAddr::V6(adresse) => Some(ams_guard::Source::V6(adresse.octets())),
    }
}

/// Ce qu'un morceau de message peut faire, en octets.
///
/// **C'EST NOTRE BORNE, PAS CELLE DU CLIENT** : il demande la portée qu'il veut,
/// et §14.4 nous laisse en rendre moins — `Content-Range` dit alors exactement ce
/// qui part, et le client redemande la suite.
const FENETRE_MAX: usize = 64 * 1024;

/// Une portée qu'on ne peut pas satisfaire (§15.5.17 de RFC 9110).
///
/// **ELLE DIT LA TAILLE**, par un `Content-Range` sans portée : c'est ce qui
/// permet au client de recommencer sans deviner.
fn hors_bornes(complete: u64, sortie: &mut [u8]) -> Served<'_> {
    let servi = probleme(
        ams_api::Reason::NoSuchResource,
        StatusCode::RANGE_NOT_SATISFIABLE,
        sortie,
    );
    Served {
        ranges: true,
        // §15.5.17 : la forme `*` dit la taille sans désigner de portée.
        range: Some(ams_loop_tokio::http::ContentRange {
            part: None,
            complete,
        }),
        ..servi
    }
}

/// Une représentation qu'on ne sait pas envoyer d'un coup.
///
/// **IL N'Y A PAS DE RÉPONSE CONFORME ICI**, et c'est écrit plutôt que caché :
/// envoyer l'entier est impossible, un `206` qu'on n'a pas demandé n'est pas
/// conforme (§15.3.7), et tronquer en silence serait mentir. `Accept-Ranges` dit
/// au client par où passer.
fn trop_grand(sortie: &mut [u8]) -> Served<'_> {
    let servi = probleme(
        ams_api::Reason::NoSuchResource,
        StatusCode::CONTENT_TOO_LARGE,
        sortie,
    );
    Served {
        ranges: true,
        ..servi
    }
}

/// Ce qu'une recherche peut rendre d'UID.
///
/// Deux cent cinquante-six. Une recherche parcourt toute la boîte ; ce qui est
/// borné ici, c'est ce qu'on RETIENT et ce qu'on écrit — et un client qui en veut
/// davantage a `SEARCH` en IMAP, qui écoule.
const RESULTATS_MAX: usize = 256;

/// L'expression de §6.4.4 que ces critères décrivent.
///
/// **LES CRITÈRES SE COMBINENT PAR « ET »**, et c'est l'implicite de §6.4.4 :
/// deux clefs côte à côte demandent les deux. `OR` et `NOT` ne sont pas servis —
/// les offrir demanderait un arbre en JSON, c'est-à-dire un second langage de
/// recherche à côté de celui d'IMAP.
///
/// Rend `None` si un texte ne peut pas s'écrire : il porte alors une fin de ligne,
/// qu'une chaîne citée ne peut pas transporter (§4.3).
fn expression_de(criteres: &render::SearchCriteria<'_>) -> Option<std::vec::Vec<u8>> {
    let mut expression: std::vec::Vec<u8> = std::vec::Vec::new();
    // **UNE FONCTION, ET NON UNE FERMETURE** : une fermeture qui emprunte
    // `expression` interdirait de l'employer autrement dans la même portée, et
    // l'écriture d'un texte cité demande justement les deux.
    fn mot(expression: &mut std::vec::Vec<u8>, quoi: &[u8]) {
        if !expression.is_empty() {
            expression.push(b' ');
        }
        expression.extend_from_slice(quoi);
    }

    for (valeur, pose, ote) in [
        (criteres.seen, &b"SEEN"[..], &b"UNSEEN"[..]),
        (criteres.answered, b"ANSWERED", b"UNANSWERED"),
        (criteres.flagged, b"FLAGGED", b"UNFLAGGED"),
        (criteres.deleted, b"DELETED", b"UNDELETED"),
        (criteres.draft, b"DRAFT", b"UNDRAFT"),
    ] {
        match valeur {
            Some(true) => mot(&mut expression, pose),
            Some(false) => mot(&mut expression, ote),
            None => {}
        }
    }

    for (texte, clef) in [
        (criteres.from, &b"FROM"[..]),
        (criteres.to, b"TO"),
        (criteres.subject, b"SUBJECT"),
        (criteres.body, b"BODY"),
        (criteres.text, b"TEXT"),
    ] {
        let Some(texte) = texte else {
            continue;
        };
        let mut place = std::vec![0_u8; texte.len().saturating_mul(2).saturating_add(2)];
        let ecrits = ams_proto_imap::write_quoted(texte.as_bytes(), &mut place).ok()?;
        mot(&mut expression, clef);
        expression.push(b' ');
        expression.extend_from_slice(place.get(..ecrits).unwrap_or_default());
    }
    Some(expression)
}

/// Ce que l'évaluateur de recherche demande à lire d'un message.
///
/// **IL NE LIT RIEN LUI-MÊME** (C1) : `ams-proto-imap` ne connaît ni fichier ni
/// boîte, et c'est cette pièce-ci qui va chercher les octets — la même que celle
/// qui sert `SEARCH` en IMAP.
struct Lecteur<'a> {
    /// La boîte ouverte.
    boite: &'a crate::imap::BoiteImap,
    /// Le message qu'on juge en ce moment.
    sequence: u32,
}

impl ams_proto_imap::SearchSource for Lecteur<'_> {
    fn contains(&mut self, scope: ams_proto_imap::SearchScope, field: &[u8], text: &[u8]) -> bool {
        use ams_session::imap::Mailbox as _;
        self.boite.contains(self.sequence, scope, field, text)
    }

    fn sent_day(&mut self) -> Option<u64> {
        use ams_session::imap::Mailbox as _;
        self.boite.sent_day(self.sequence)
    }
}

/// Traduit une faute du magasin, **et l'écrit au journal**.
///
/// Ce qu'on rend au client est volontairement pauvre — un code, une phrase.
/// L'exploitant qui lit le journal du serveur, lui, a droit à la raison exacte :
/// « ce compte n'est pas acceptable » sans la cause l'enverrait chercher au
/// hasard, et c'est lui qui doit réparer.
fn dire_la_faute<'o>(quoi: &crate::comptes::Faute, sortie: &'o mut [u8]) -> Served<'o> {
    eprintln!("air-mail-server : magasin de comptes — {quoi}");
    match *quoi {
        crate::comptes::Faute::Ecriture(_) => indisponible(sortie),
        crate::comptes::Faute::Introuvable => absente(sortie),
        crate::comptes::Faute::Refuse(_) => refus_de_compte(sortie),
    }
}

/// Un corps qu'on ne sait pas lire.
fn refus_de_corps(sortie: &mut [u8]) -> Served<'_> {
    probleme(
        ams_api::Reason::BadJsonBody,
        StatusCode::BAD_REQUEST,
        sortie,
    )
}

/// Un compte qu'on refuse.
///
/// **CELUI-CI SE DIT, ET C'EST L'INVERSE D'UN DÉPÔT REFUSÉ** : qui le lit tient
/// un jeton d'administration, donc l'autorité qui peut déjà lire la liste des
/// comptes. Lui cacher pourquoi son nom est refusé ne protégerait rien.
fn refus_de_compte(sortie: &mut [u8]) -> Served<'_> {
    probleme(ams_api::Reason::BadAccount, StatusCode::BAD_REQUEST, sortie)
}

/// Un compte qui existe déjà.
///
/// §15.5.10 de RFC 9110 : la demande est bien formée, et c'est l'ÉTAT de la
/// ressource qui l'empêche. Un `400` enverrait le client relire son corps, qui
/// n'a rien à corriger.
fn conflit(sortie: &mut [u8]) -> Served<'_> {
    probleme(ams_api::Reason::BadAccount, StatusCode::CONFLICT, sortie)
}

/// Un document de problème, avec le code qu'on a choisi.
fn probleme(raison: ams_api::Reason, statut: StatusCode, sortie: &mut [u8]) -> Served<'_> {
    match ams_api::problem(raison, sortie) {
        Ok(corps) => Served {
            status: statut,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: corps,
            ..Served::default()
        },
        Err(_) => notre_faute(),
    }
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
            ..Served::default()
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
            ..Served::default()
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
        // **ÉCRITS À LA MAIN, ET NON `..Default::default()`** : cette fonction
        // est `const`, et un `Default` ne l'est pas. C'est le seul endroit du
        // fichier où la liste se répète, et elle tient sur deux lignes.
        ranges: false,
        range: None,
    }
}

/// Remet ce message à ces destinataires.
///
/// Séparée pour que `?` serve : l'appelante doit annuler ce qui a commencé.
fn deposer(
    remise: &mut crate::delivery::MaildirDelivery,
    expediteur: &[u8],
    destinataires: &[Vec<u8>],
    message: &[u8],
) -> Result<(), ams_loop_tokio::DeliveryFailure> {
    use ams_loop_tokio::Delivery as _;

    // **LE CHEMIN DE RETOUR D'ABORD**, comme la boucle SMTP le fait : c'est le
    // `From:` VÉRIFIÉ du déposant, donc l'une des adresses de son compte, et
    // c'est là qu'un rapport de non-remise reviendra.
    remise.begin(Some(expediteur));
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
            ..Served::default()
        },
        Err(_) => Served {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: &[],
            ..Served::default()
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

    /// Les destinataires de ce message, SANS ÉMISSION — le comportement d'avant
    /// la file, et celui qui vaut encore quand personne n'a demandé à émettre.
    fn vers(entete: &str) -> Option<std::vec::Vec<std::string::String>> {
        vers_avec(entete, false)
    }

    /// Les destinataires de ce message, l'émission étant ouverte ou non.
    fn vers_avec(entete: &str, relaie: bool) -> Option<std::vec::Vec<std::string::String>> {
        // §2.1 : l'en-tête se termine par une ligne vide, et non par la
        // dernière ligne de champ.
        let brut = std::format!("{entete}\r\n\r\n");
        let bornes = ams_mime::Limits::DEFAULT;
        let message = ams_mime::Message::parse(brut.as_bytes(), &bornes).expect("lisible");
        destinataires_de(&comptes(), &message, relaie).map(|vus| {
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
        ecrit_bien_en_son_nom(&comptes(), compte, &message).is_some()
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

#[cfg(test)]
mod porte_http {
    use std::sync::Arc;

    use super::{ApiMaildir, Account};
    use crate::incidents::{Cause, Incidents};

    /// Un répertoire qui s'efface quand l'essai finit.
    struct Ephemere(std::path::PathBuf);

    impl Drop for Ephemere {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Une API montée sur deux comptes, et le compteur qu'elle partage.
    fn api(nom: &str) -> (Ephemere, ApiMaildir, Arc<Incidents>) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |depuis| depuis.as_nanos());
        let racine = std::env::temp_dir().join(std::format!("ams-api-{nom}-{unique}"));
        std::fs::create_dir_all(&racine).expect("créable");

        let nomme = |login: &str| Account {
            login: login.to_string(),
            hash: std::string::String::new(),
            addresses: std::vec![std::format!("{login}@example.com")],
        };
        let comptes = Arc::new(crate::comptes::Comptes::new(
            racine.join("comptes.bin"),
            std::vec![nomme("jean"), nomme("marie")],
        ));
        let boites = Arc::new(crate::delivery::Boites::new(
            std::collections::BTreeMap::new(),
            racine.clone(),
            b"mail.example.com".to_vec(),
            Arc::clone(&comptes),
        ));
        let incidents = Arc::new(Incidents::new());
        let api = ApiMaildir::new(
            Arc::new(crate::imap::BoitesImap::new(
                Arc::clone(&boites),
                b"mail.example.com",
            )),
            Arc::clone(&comptes),
            boites,
            Arc::new(std::vec![std::string::String::from("example.com")]),
            Arc::new(ams_loop_tokio::SharedGuard::new(
                16,
                ams_guard::Thresholds::default(),
            )),
            Arc::clone(&incidents),
        );
        (Ephemere(racine), api, incidents)
    }

    /// **UNE USURPATION REFUSÉE PAR L'API SE DIT, COMME CELLE DE SMTP.**
    ///
    /// Les deux portes appliquent la même règle (RFC 6409 §6.1) par deux
    /// fonctions distinctes, et une seule la comptait : le `400` partait au
    /// déposant, et l'exploitant n'apprenait rien d'un compte authentifié qui
    /// tente d'écrire au nom d'un autre. C'est pourtant exactement ce qu'il veut
    /// voir — il connaît ce compte, et peut le suspendre.
    #[test]
    fn une_usurpation_par_l_api_est_comptee() {
        let (_ephemere, api, incidents) = api("usurpation");
        let faux = b"From: marie@example.com\r\nTo: jean@example.com\r\n\r\nnon.\r\n";
        let mut sortie = std::vec![0_u8; 4096];

        // `jean` dépose un message qui se dit de `marie`.
        let rendu = api.submissions("jean", faux, &mut sortie);

        assert_eq!(
            rendu.status,
            ams_proto_http::StatusCode::BAD_REQUEST,
            "le dépôt est refusé"
        );
        assert_eq!(
            incidents.bilan(),
            std::vec![(Cause::Usurpation, 1)],
            "et le refus est COMPTÉ : sans cela, il ne laissait aucune trace"
        );
    }

    /// Et un dépôt en son propre nom ne compte rien : un journal qui crie à
    /// chaque message est un journal qu'on cesse de lire.
    #[test]
    fn un_depot_en_son_nom_ne_compte_rien() {
        let (_ephemere, api, incidents) = api("legitime");
        let bon = b"From: jean@example.com\r\nTo: jean@example.com\r\n\r\noui.\r\n";
        let mut sortie = std::vec![0_u8; 4096];

        let _ = api.submissions("jean", bon, &mut sortie);

        assert!(
            incidents.bilan().is_empty(),
            "rien d'anormal, donc rien à dire"
        );
    }
}
