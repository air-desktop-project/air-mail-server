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
use ams_loop_tokio::http::{Admission, Api, Served};
use ams_proto_http::{Method, StatusCode};
use ams_sasl::Credentials;
use ams_session::http::render::{self, MailboxRow, MessageRow};
use ams_session::imap::{Mailbox as _, Mailboxes as _};

use crate::imap::BoitesImap;
use crate::policy::Places;

/// Combien de messages une page rend au plus, et par défaut.
///
/// Cinquante. Le client demande la suite avec le curseur que la réponse porte —
/// voir [`render::write_messages`]. **LA BORNE VIENT DU TAMPON DE HTTP/3** —
/// soixante-quatre kibioctets de réponse — et d'un sujet qui peut en faire un :
/// une page plus grande tiendrait en HTTP/2 et échouerait en HTTP/3. Un `limit`
/// plus grand est refusé, et non ramené en silence : le client croirait avoir
/// reçu tout ce qu'il a demandé.
const PAGE_MAX: usize = 50;

/// Combien de disparitions une page du journal rend au plus.
///
/// **CINQ CENTS UID** : au plus six kibioctets, qui tiennent avec cinquante
/// messages dans le tampon de HTTP/3. Au-delà, `more` fait revenir le client.
const DISPARUS_PAR_PAGE: usize = 500;

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
    /// Les sessions ouvertes, et le seul endroit où l'on peut les fermer.
    ///
    /// **C'EST CE QUI REND UN JETON RÉVOCABLE.** Sans ce registre, un jeton se
    /// vérifiait sans rien consulter et n'avait d'autre fin que son expiration.
    sessions: Arc<crate::sessions::Sessions>,
    /// Le débit de chaque appareil, une fois authentifié (phase 6).
    debits: crate::debits::Debits,
    /// Le journal d'audit, quand la configuration en nomme le répertoire
    /// (phase 6). `None` : rien ne s'écrit, et les routes `…/audit` rendent 501.
    audit: Option<Arc<crate::audit::Audit>>,
    /// Ce que la configuration exige de l'attestation de clef d'Android
    /// (0.2.39). Éteint par défaut : aucune n'est lue.
    juge: crate::attestation::Juge,
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
    /// Le domaine que les appareils font entrer dans leur signature.
    ///
    /// **LE MÊME QUE CELUI DE LA SESSION, ET LE SERVEUR LE LEUR DONNE DEPUIS UNE
    /// SEULE SOURCE.** La session l'annonce au client, l'API le vérifie ; deux
    /// valeurs donneraient deux condensats, et **aucune signature ne passerait
    /// jamais** — sans que rien ne dise pourquoi.
    ///
    /// Ce n'est PAS la liste des domaines hébergés : celle-ci en porte
    /// plusieurs, et « le premier » n'est pas une identité de serveur.
    domaine: Vec<u8>,
    /// La clé qui scelle les invitations.
    ///
    /// **LA MÊME QUE CELLE DES JETONS, ET C'EST VOULU.** Deux clés seraient deux
    /// secrets à ranger, à tourner et à perdre ; une seule suffit parce que
    /// l'octet de version sépare les deux objets, et qu'il est couvert par le
    /// sceau. Elle vient du même endroit que celle de la session — la
    /// configuration —, et le serveur la leur donne toutes les deux au
    /// démarrage.
    scellement: Option<ams_api::Key>,
    /// Les appareils enrôlés, quand la configuration en nomme le magasin.
    ///
    /// **`None` VEUT DIRE « CE SERVEUR NE SERT PAS CELA »**, et les deux routes
    /// de `/v1/me/devices` répondent alors 501. Rendre une liste vide à la
    /// place ferait passer une configuration oubliée pour un compte sans
    /// appareil, et l'exploitant chercherait le défaut chez l'utilisateur.
    appareils: Option<Arc<crate::appareils::Appareils>>,
    /// Le réveil des appareils abonnés, s'il y a un magasin d'appareils.
    reveil: Option<Arc<crate::reveil::Reveil>>,
    /// La clef publique VAPID, en base64url, si Web Push est servi.
    vapid: Option<String>,
    /// De quoi signer ce qui sort (RFC 6376), quand une clé est nommée.
    ///
    /// **LA MÊME QUE DU CÔTÉ SMTP** : les deux portes de soumission n'ont pas
    /// deux règles, pas plus pour la signature que pour le relais.
    dkim: Option<ams_loop_tokio::DkimSigner>,
    /// Le magasin SCRAM, quand ce serveur sert SCRAM.
    ///
    /// **POSER UN MOT DE PASSE REDÉRIVE SON VÉRIFICATEUR**, sans quoi un client
    /// qui choisit SCRAM — Thunderbird — échouerait avec le nouveau mot de
    /// passe. `None` quand SCRAM n'est pas servi : il n'y a alors rien à tenir
    /// à jour.
    scram: Option<Arc<crate::scram::Verificateurs>>,
    /// Les mots de passe applicatifs, quand la configuration en nomme le
    /// magasin. `None` : les routes `/v1/me/app-passwords` rendent 501.
    applicatifs: Option<Arc<crate::applicatifs::Applicatifs>>,
    /// Les délégations, quand la configuration en nomme le magasin. `None` :
    /// aucune boîte d'autrui ne s'atteint.
    delegations: Option<Arc<crate::delegations::Delegations>>,
    /// Les brouillons, quand la configuration en nomme le répertoire. `None` :
    /// les routes `/v1/drafts` rendent 501.
    brouillons: Option<Arc<crate::brouillons::Brouillons>>,
    /// Le registre des clés d'idempotence, qui vit à côté des brouillons.
    /// `None` : le champ `Idempotency-Key` est ignoré.
    idempotence: Option<Arc<crate::idempotence::Idempotence>>,
}

/// Combien de mots de passe applicatifs un compte peut avoir.
///
/// **SEIZE** : un client de courrier par poste et par téléphone, avec de la
/// marge. Sans borne, un jeton volé en fabriquerait autant qu'il veut, et la
/// liste que son propriétaire lit pour repérer l'intrus deviendrait illisible.
const APPLICATIFS_PAR_COMPTE: usize = 16;

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
            sessions: Arc::new(crate::sessions::Sessions::new()),
            // LE DÉBIT DE DÉPART, que la configuration remplace : voir
            // `avec_debit`.
            debits: crate::debits::Debits::new(ams_guard::Rate::DEFAULT),
            // PAS DE JOURNAL SANS RÉPERTOIRE : voir `avec_audit`.
            audit: None,
            // AUCUNE ATTESTATION LUE, SAUF DEMANDE : voir `avec_attestation`.
            juge: crate::attestation::Juge::eteint(),
            guard,
            incidents,
            places: Places::new(VERIFICATIONS_SIMULTANEES),
            // ON N'ÉMET PAS, SAUF DEMANDE EXPRESSE — et le constructeur ne prend
            // pas ce champ : un argument de plus dans une liste qui en compte
            // déjà sept se passe à l'envers sans que le compilateur bronche, et
            // celui-ci ouvre un relais.
            file: None,
            message_max: 0,
            // PAS D'APPAREILS SANS MAGASIN, et le constructeur ne prend pas ce
            // champ non plus : voir `avec_appareils`.
            appareils: None,
            reveil: None,
            vapid: None,
            scram: None,
            applicatifs: None,
            delegations: None,
            brouillons: None,
            idempotence: None,
            // ET PAS D'INVITATIONS SANS CLÉ : voir `avec_scellement`.
            scellement: None,
            // NI DE SESSIONS PAR CLEF SANS DOMAINE : voir `avec_domaine`.
            domaine: Vec::new(),
            // ON NE SIGNE PAS SANS CLÉ, et le constructeur ne prend pas ce
            // champ non plus : une signature qu'on produirait sans clé publiée
            // échouerait partout, ce qui est pire que pas de signature.
            dkim: None,
        }
    }

    /// Refuse un enrôlement pour son attestation : le journal dit pourquoi, le
    /// client lit seulement que l'attestation n'est pas recevable.
    fn refuser_l_attestation<'o>(
        &self,
        compte: &str,
        refus: crate::attestation::Refus,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        eprintln!(
            "air-mail-server : attestation refusée pour `{compte}` — {}",
            refus.dire()
        );
        let mut servi = probleme(
            ams_api::Reason::AttestationRefused,
            ams_api::Reason::AttestationRefused.status(),
            sortie,
        );
        // **UNE ATTESTATION REFUSÉE COMPTE POUR LE VIDEUR**, comme une
        // invitation forgée : cette porte s'ouvre sans jeton.
        servi.peer_fault = true;
        servi
    }

    /// Lui dit ce qu'exiger de l'attestation de clef d'Android.
    #[must_use]
    pub fn avec_attestation(mut self, juge: crate::attestation::Juge) -> Self {
        self.juge = juge;
        self
    }

    /// Lui donne le journal d'audit.
    #[must_use]
    pub fn avec_audit(mut self, audit: Arc<crate::audit::Audit>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Note un événement au journal d'audit de ce compte, s'il y en a un.
    fn noter(
        &self,
        compte: &str,
        evenement: crate::audit::Evenement<'_>,
        source: Option<ams_guard::Source>,
    ) {
        if let Some(audit) = self.audit.as_ref() {
            let texte = source.map(texte_de_source);
            audit.noter(compte, evenement, texte.as_deref(), crate::maintenant());
        }
    }

    /// `GET /v1/me/audit` et `/v1/accounts/{compte}/audit` — les entrées les
    /// plus récentes d'abord.
    ///
    /// **CE QUI NE TIENT PAS NE SORT PAS** : la réponse s'arrête à la dernière
    /// entrée entière qui tient, plutôt que d'échouer. Une ligne fait au plus
    /// quelques centaines d'octets, et `limit` est borné.
    fn journal_d_audit<'o>(
        &self,
        compte: &str,
        limite: Option<u16>,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(audit) = self.audit.as_ref() else {
            return pas_encore(sortie);
        };
        let limite = limite
            .map_or(crate::audit::LIMITE_PAR_DEFAUT, usize::from)
            .min(crate::audit::LIMITE_MAX);
        let entrees = audit.lire(compte, limite);
        let pied: &[u8] = b"]}";
        let mut corps: std::vec::Vec<u8> = std::vec::Vec::from(&b"{\"entries\":["[..]);
        for entree in &entrees {
            let virgule = usize::from(corps.len() > b"{\"entries\":[".len());
            let besoin = corps
                .len()
                .saturating_add(virgule)
                .saturating_add(entree.len())
                .saturating_add(pied.len());
            if besoin > sortie.len() {
                break;
            }
            if virgule == 1 {
                corps.push(b',');
            }
            corps.extend_from_slice(entree);
        }
        corps.extend_from_slice(pied);
        let Some(place) = sortie.get_mut(..corps.len()) else {
            return notre_faute();
        };
        place.copy_from_slice(&corps);
        Served {
            status: StatusCode::OK,
            media: JSON_MEDIA_TYPE,
            body: place,
            ..Served::default()
        }
    }

    /// Note au journal ce qu'une requête réussie a fait, quand son chemin dit
    /// tout ce qu'il faut en savoir.
    ///
    /// **APRÈS LA RÉPONSE, ET SEULEMENT SUR UN SUCCÈS** : une révocation
    /// refusée n'a rien révoqué. Ce que le chemin ne dit pas — l'identifiant
    /// d'un appareil ou d'un mot de passe créé — se note là où il naît.
    fn noter_ce_que_le_chemin_dit(
        &self,
        acteur: &str,
        resource: Resource<'_>,
        method: Method,
        source: ams_guard::Source,
    ) {
        use crate::audit::Evenement;
        let source = Some(source);
        match (resource, method) {
            (Resource::OwnAppPassword { id }, Method::Delete) => {
                self.noter(acteur, Evenement::ApplicatifRevoque { id }, source);
            }
            (Resource::OwnPassword, Method::Put) => {
                self.noter(acteur, Evenement::SecretChange { par: "self" }, source);
            }
            (Resource::AccountPassword { compte }, Method::Put) => {
                self.noter(compte, Evenement::SecretChange { par: "admin" }, source);
            }
            // **UNE DÉLÉGATION S'ÉCRIT DANS LES DEUX JOURNAUX** : le titulaire
            // doit voir qui atteint sa boîte, et le délégué ce qu'on lui a
            // ouvert.
            (Resource::Delegate { compte, delegue }, Method::Put) => {
                let evenement = Evenement::DelegationPosee {
                    titulaire: compte,
                    delegue,
                };
                self.noter(compte, evenement, source);
                self.noter(delegue, evenement, source);
            }
            (Resource::Delegate { compte, delegue }, Method::Delete) => {
                let evenement = Evenement::DelegationRetiree {
                    titulaire: compte,
                    delegue,
                };
                self.noter(compte, evenement, source);
                self.noter(delegue, evenement, source);
            }
            _ => {}
        }
    }

    /// Lui donne le débit de chaque appareil, tel que la configuration le dit.
    #[must_use]
    pub fn avec_debit(mut self, debit: ams_guard::Rate) -> Self {
        self.debits = crate::debits::Debits::new(debit);
        self
    }

    /// Lui dit quel domaine les appareils font entrer dans leur signature.
    ///
    /// **LE SERVEUR DOIT LUI DONNER LE MÊME QU'À LA SESSION**, et depuis la même
    /// source : c'est la session qui l'annonce au client, et cette API qui le
    /// vérifie.
    #[must_use]
    pub fn avec_domaine(mut self, domaine: &[u8]) -> Self {
        self.domaine = domaine.to_vec();
        self
    }

    /// Lui donne la clé qui scelle les invitations.
    ///
    /// **C'est la MÊME que celle des jetons**, et le serveur la lui passe depuis
    /// la configuration, en même temps qu'à la session. Sans elle, frapper une
    /// invitation rend `501`.
    #[must_use]
    pub fn avec_scellement(mut self, clef: ams_api::Key) -> Self {
        self.scellement = Some(clef);
        self
    }

    /// Lui donne le magasin des appareils enrôlés.
    ///
    /// **C'est la seule façon d'ouvrir `/v1/me/devices`**, et le serveur ne
    /// l'appelle que si la configuration nomme un magasin.
    #[must_use]
    pub fn avec_appareils(mut self, magasin: Arc<crate::appareils::Appareils>) -> Self {
        self.appareils = Some(magasin);
        self
    }

    /// Lui donne la clef publique VAPID, que `GET /v1/me/push` publie.
    #[must_use]
    pub fn avec_vapid(mut self, publique: String) -> Self {
        self.vapid = Some(publique);
        self
    }

    /// Lui donne le réveil : ce que l'API remet localement réveille les
    /// appareils abonnés, et `/v1/metrics` dit ce qu'il a fait.
    #[must_use]
    pub fn avec_reveil(mut self, reveil: Arc<crate::reveil::Reveil>) -> Self {
        self.reveil = Some(reveil);
        self
    }

    /// Lui donne le magasin SCRAM, pour que poser un mot de passe y redérive le
    /// vérificateur du compte.
    #[must_use]
    pub fn avec_scram(mut self, verificateurs: Arc<crate::scram::Verificateurs>) -> Self {
        self.scram = Some(verificateurs);
        self
    }

    /// Lui donne le magasin des mots de passe applicatifs : c'est ce qui ouvre
    /// `/v1/me/app-passwords`.
    #[must_use]
    pub fn avec_applicatifs(mut self, magasin: Arc<crate::applicatifs::Applicatifs>) -> Self {
        self.applicatifs = Some(magasin);
        self
    }

    /// Lui donne le magasin des délégations : c'est ce qui ouvre les boîtes
    /// d'autrui sous `/v1/accounts/{compte}/mailboxes/…`.
    #[must_use]
    pub fn avec_delegations(mut self, magasin: Arc<crate::delegations::Delegations>) -> Self {
        self.delegations = Some(magasin);
        self
    }

    /// Lui donne le répertoire des brouillons : c'est ce qui ouvre `/v1/drafts`,
    /// donc les messages avec pièces jointes.
    #[must_use]
    pub fn avec_brouillons(mut self, brouillons: Arc<crate::brouillons::Brouillons>) -> Self {
        self.brouillons = Some(brouillons);
        self
    }

    /// Lui donne le registre des clés d'idempotence : c'est ce qui fait qu'une
    /// soumission rejouée ne part pas deux fois.
    #[must_use]
    pub fn avec_idempotence(mut self, registre: Arc<crate::idempotence::Idempotence>) -> Self {
        self.idempotence = Some(registre);
        self
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
        if !secret_recevable(secret) {
            return refus_de_corps(sortie);
        }
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
        if !self.poser_le_verificateur(nom, secret.as_bytes(), &hash) {
            return indisponible(sortie);
        }
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
        // **SES DÉLÉGATIONS AUSSI, DANS LES DEUX SENS** : un compte recréé sous
        // le même nom hériterait sinon des accès de l'ancien, ou de ses
        // délégués.
        if let Some(table) = self.delegations.as_ref()
            && let Err(quoi) = table.modifier(|tenues| {
                tenues.retain(|tenue| tenue.delegate != nom && tenue.owner != nom);
                Ok(())
            })
        {
            eprintln!("air-mail-server : délégations de `{nom}` NON retirées ({quoi})");
        }
        // **SES MOTS DE PASSE APPLICATIFS PARTENT AVEC LUI.** Ils n'ouvrent plus
        // rien sans compte ; mais un compte recréé sous le même nom en
        // hériterait, et le nouveau titulaire aurait des secrets qu'il n'a
        // jamais vus. Un échec se dit et ne défait pas le retrait.
        if let Some(magasin) = self.applicatifs.as_ref()
            && let Err(quoi) = magasin.modifier(|entrees| {
                entrees.retain(|entree| entree.login != nom);
                Ok(())
            })
        {
            eprintln!(
                "air-mail-server : mots de passe applicatifs de `{nom}` NON retirés ({quoi}) — \
                 à retirer avant de recréer ce compte"
            );
        }
        // **SES APPAREILS PARTENT AVEC LUI, ET LEURS ABONNEMENTS** (0.2.31).
        // Ils restaient : un compte recréé sous le même nom se serait ouvert
        // aux clefs de l'ancien titulaire. Un échec se dit, comme pour les
        // mots de passe applicatifs.
        if let Some(magasin) = self.appareils.as_ref()
            && let Err(quoi) = magasin.modifier(|appareils| {
                appareils.retain(|appareil| appareil.login != nom);
                Ok(())
            })
        {
            eprintln!(
                "air-mail-server : appareils de `{nom}` NON retirés ({quoi}) — \
                 à retirer avant de recréer ce compte"
            );
        }
        // **ET SES SESSIONS FERMENT**, par mot de passe comme par clef.
        self.sessions.fermer_le_compte(nom);
        // Ses seaux et ses refus s'oublient aussi : un compte recréé sous ce
        // nom repart d'un seau plein et d'un compteur à zéro.
        self.debits.oublier(nom);
        // **ET SON JOURNAL D'AUDIT S'EFFACE** : un compte recréé sous ce nom y
        // lirait d'où se connectait quelqu'un d'autre.
        if let Some(audit) = self.audit.as_ref() {
            audit.oublier(nom);
        }
        // Et ce que le réveil a compté pour lui s'oublie : un compte recréé
        // sous ce nom n'hérite pas des compteurs de l'ancien.
        if let Some(reveil) = self.reveil.as_ref() {
            reveil.oublier(nom);
        }
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
        if !secret_recevable(secret) {
            return refus_de_corps(sortie);
        }
        if !self.comptes.vue().iter().any(|vu| vu.login == nom) {
            return absente(sortie);
        }
        let Some(hash) = self.empreinte(secret.as_bytes()) else {
            return notre_faute();
        };
        if !self.poser_le_verificateur(nom, secret.as_bytes(), &hash) {
            return indisponible(sortie);
        }
        match self.comptes.modifier(|comptes| {
            let compte = comptes
                .iter_mut()
                .find(|vu| vu.login == nom)
                .ok_or(crate::comptes::INTROUVABLE)?;
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

    /// **Change le secret de QUI APPELLE**, et de personne d'autre.
    ///
    /// # LE JETON DIT QUI, LE MOT DE PASSE ACTUEL DIT QUE C'EST BIEN LUI
    ///
    /// `porteur` vient du jeton, déjà scellé et vérifié : la boucle ne l'appelle
    /// pas autrement. Il n'est donc jamais lu dans le corps — un champ `login`
    /// y serait refusé, et c'est ce qui rend cette route incapable de toucher le
    /// compte d'un autre, quoi que le client écrive.
    ///
    /// Le mot de passe actuel, lui, est exigé. Sans lui, un jeton ramassé dans
    /// le journal d'un intermédiaire suffirait à verrouiller le propriétaire
    /// hors de sa boîte, DÉFINITIVEMENT : un vol de jeton, qui expire,
    /// deviendrait un vol de compte, qui n'expire pas.
    ///
    /// # POURQUOI 403 ET NON 401
    ///
    /// Le jeton est bon — c'est ce qui a permis d'arriver ici. Répondre 401
    /// ferait recommencer au client une authentification qui a réussi ; §15.5.4
    /// de RFC 9110 réserve le 403 à « la requête est comprise, et refusée ». Ce
    /// qui manque est une preuve de possession, pas une identité.
    fn poser_mon_secret<'o>(
        &self,
        porteur: &str,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let mut actuel = [0_u8; MOT_DE_PASSE_MAX];
        let mut neuf = [0_u8; MOT_DE_PASSE_MAX];
        let Ok(lu) = render::read_own_password_body(corps, &mut actuel, &mut neuf) else {
            return refus_de_corps(sortie);
        };
        // **AVANT MÊME DE VÉRIFIER L'ANCIEN** : refuser d'abord ce qui ne peut
        // de toute façon pas être posé épargne un Argon2id de dix-neuf
        // mébioctets à qui se trompe de corps.
        if !secret_recevable(lu.new) {
            return refus_de_corps(sortie);
        }

        // **LA VÉRIFICATION D'ABORD, ET SON COÛT EST LE MÊME QU'AILLEURS** :
        // Argon2id est délibérément lent, et chaque calcul réclame dix-neuf
        // mébioctets. Un compte disparu depuis la frappe du jeton échoue ici
        // comme un mot de passe faux, et pour le même prix.
        if !self.verifie(porteur, lu.current.as_bytes()) {
            return Served {
                peer_fault: true,
                ..probleme(ams_api::Reason::BadPassword, StatusCode::FORBIDDEN, sortie)
            };
        }

        let Some(hash) = self.empreinte(lu.new.as_bytes()) else {
            return notre_faute();
        };
        if !self.poser_le_verificateur(porteur, lu.new.as_bytes(), &hash) {
            return indisponible(sortie);
        }
        match self.comptes.modifier(|comptes| {
            let compte = comptes
                .iter_mut()
                .find(|vu| vu.login == porteur)
                .ok_or(crate::comptes::INTROUVABLE)?;
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

    /// Redérive le vérificateur SCRAM d'un compte dont on pose le secret.
    ///
    /// **À APPELER AVANT D'ÉCRIRE LE COMPTE** : le vérificateur est lié à
    /// `empreinte`, que le compte ne porte pas encore — il ne s'ouvre donc pas
    /// tant que le compte n'est pas écrit, et l'ordre ne laisse aucune fenêtre.
    ///
    /// `true` si rien n'était à faire ou si c'est fait ; `false` si le magasin
    /// SCRAM a refusé, et l'appelant renonce alors à poser le secret : un
    /// mot de passe changé dont SCRAM ne saurait rien laisserait les clients
    /// SCRAM en échec sans que personne ne sache pourquoi.
    fn poser_le_verificateur(&self, login: &str, secret: &[u8], empreinte: &str) -> bool {
        let Some(verificateurs) = self.scram.as_ref() else {
            return true;
        };
        match verificateurs.deriver_et_poser(login, secret, empreinte) {
            Ok(()) => true,
            Err(cause) => {
                eprintln!(
                    "air-mail-server : SCRAM — le vérificateur de `{login}` ne se pose pas \
                     ({cause}) ; le mot de passe n'est PAS changé"
                );
                false
            }
        }
    }

    /// Ce compte ouvre-t-il avec ce secret ?
    ///
    /// La même discipline que partout où l'on vérifie : `block_in_place`, parce
    /// qu'Argon2id bloquerait l'ordonnanceur, et une borne sur les vérifications
    /// simultanées, parce que chacune réclame dix-neuf mébioctets.
    fn verifie(&self, login: &str, secret: &[u8]) -> bool {
        let identifiants = ams_sasl::Credentials {
            authorization_identity: b"",
            authentication_identity: login.as_bytes(),
            password: secret,
        };
        tokio::task::block_in_place(|| {
            self.places
                .occuper(|| ams_auth::authenticate(&self.comptes.vue(), &identifiants))
        })
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
                .ok_or(crate::comptes::INTROUVABLE)?;
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
    /// Les appareils de qui appelle.
    ///
    /// **LE COMPTE VIENT DU JETON, JAMAIS DU CHEMIN** : c'est ce qui rend cette
    /// route incapable de montrer les appareils d'un autre, quoi qu'on écrive
    /// dans l'URL — il n'y a rien à y écrire.
    fn mes_appareils<'o>(&self, account: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let Some(magasin) = self.appareils.as_ref() else {
            return pas_encore(sortie);
        };
        let siens = magasin.du_compte(account);
        let lignes: std::vec::Vec<render::DeviceRow<'_>> = siens
            .iter()
            .map(|appareil| render::DeviceRow {
                id: &appareil.id,
                name: &appareil.name,
                enrolled: appareil.enrolled,
                // **EN SECONDES DEHORS**, comme tout ce que cette API rend ; le
                // magasin compte en millisecondes pour le défi.
                last_seen: appareil.last_seen / 1_000,
                push: appareil.push.as_ref().map(|push| push.channel().name()),
                attestation: appareil.attestation.map(ams_config::Attested::name),
            })
            .collect();
        rendre(render::write_devices(&lignes, sortie))
    }

    /// Enrôle un second appareil, approuvé par un premier.
    ///
    /// # LE JETON NE SUFFIT PAS, ET C'EST TOUT L'INTÉRÊT
    ///
    /// Un jeton vaut quinze minutes ; une clef enrôlée vaut jusqu'à sa
    /// révocation. Laisser un simple porteur créer une clef ferait **d'un vol de
    /// quinze minutes un accès permanent**, que fermer la session ne retirerait
    /// pas. On exige donc un défi signé par un appareil DÉJÀ enrôlé : la preuve
    /// qu'on tient l'enclave à cet instant, et pas seulement un jeton.
    ///
    /// # ET LE DÉFI PORTE SON PROPRE RÔLE
    ///
    /// `ams-pairing`, et non `ams-session`. Une signature obtenue pour ouvrir
    /// une boîte ne doit pas valoir pour ajouter un appareil — sans quoi une
    /// application qui demande « ouvre ma boîte » à son propriétaire obtiendrait
    /// de quoi lui en ajouter un.
    fn appairer<'o>(
        &self,
        account: &str,
        body: &[u8],
        source: ams_guard::Source,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let (Some(_), Some(clef)) = (self.appareils.as_ref(), self.scellement.as_ref()) else {
            return pas_encore(sortie);
        };
        let Ok(demande) = render::read_pairing_request(body) else {
            return corps_refuse(sortie);
        };

        // **LE DÉFI D'ABORD** : sans lui, rien de ce qui suit n'est autorisé.
        let mut place = [0_u8; ams_api::CHALLENGE_OCTETS_MAX];
        let Ok(defi) = ams_api::verify_challenge(
            clef,
            demande.challenge.as_bytes(),
            millisecondes(),
            &mut place,
        ) else {
            return refus_d_appairage(sortie);
        };
        // **LE DÉFI DOIT DÉSIGNER LE COMPTE DU JETON.** Sans ce contrôle, un
        // défi obtenu pour un autre compte servirait ici — et l'appareil
        // approbateur serait celui d'un autre.
        if defi.login != account {
            return refus_d_appairage(sortie);
        }
        // **LA CLEF NOUVELLE, D'ABORD** — parce que la signature la couvre. Une
        // clef qui n'est pas un point de la courbe n'est pas une clef faible :
        // c'est une clef qui n'existe pas.
        let mut octets = [0_u8; ams_auth::CLE_OCTETS];
        let Ok(lus) = ams_api::decode_base64url(demande.public_key.as_bytes(), &mut octets) else {
            return corps_de_l_enrolement_refuse(sortie);
        };
        let Ok(cle) = ams_auth::Cle::lire(lus) else {
            return corps_de_l_enrolement_refuse(sortie);
        };
        // **L'ATTESTATION DE LA CLEF NOUVELLE** (0.2.39) : son défi est le
        // condensat du défi d'appairage, que l'approbateur a signé.
        let atteste = match self.juge.juger(
            &cle.octets(),
            demande.challenge,
            demande.attestation,
            maintenant_i64(),
        ) {
            Ok(atteste) => atteste,
            Err(refus) => return self.refuser_l_attestation(account, refus, sortie),
        };
        let id = en_hexadecimal(&ams_sasl::sha256(&cle.octets()));

        // **LA SIGNATURE, SANS RIEN ÉCRIRE ENCORE**, et sur CE QU'ELLE APPROUVE :
        // l'identifiant du nouvel appareil entre dans le condensat. Une
        // signature donnée pour la tablette que le propriétaire a vue ne vaut
        // donc pas pour une autre clef. Tant que la demande peut échouer pour
        // une autre raison, le défi ne doit pas être consommé.
        if self
            .signature_recevable(
                ams_api::Geste::Appairage {
                    nouvel_appareil: id.as_bytes(),
                },
                account,
                defi.device,
                defi.issued_at_ms,
                demande.challenge,
                demande.signature,
            )
            .is_none()
        {
            return refus_d_appairage(sortie);
        }

        let adresses: std::vec::Vec<String> = {
            let comptes = self.comptes.vue();
            let Some(compte) = comptes.iter().find(|connu| connu.login == account) else {
                return absente(sortie);
            };
            compte.addresses.clone()
        };

        let a_ranger = ams_config::Device {
            login: String::from(account),
            id: id.clone(),
            name: String::from(demande.name),
            enrolled: crate::maintenant(),
            last_seen: 0,
            push: None,
            attestation: atteste,
            public_key: cle,
        };
        // **UNE SEULE ÉCRITURE, QUI DÉCIDE DE TOUT SOUS LE VERROU** : le rejeu,
        // le doublon, le plafond, puis la date de l'approbateur ET le nouvel
        // appareil ensemble. Un appairage refusé — `409` compris — laisse donc
        // l'approbateur tel qu'il était, et son défi suivant n'a pas à attendre.
        let issue = self.consommer(defi.device, defi.issued_at_ms, |appareils| {
            let siens = appareils
                .iter()
                .filter(|connu| connu.login == account)
                .count();
            // **LA MÊME CLEF NE S'ENRÔLE PAS DEUX FOIS.** Le magasin le
            // refuserait — deux appareils ne partagent pas un identifiant —, mais
            // il le refuserait par une faute que le client ne saurait pas lire.
            if appareils
                .iter()
                .any(|connu| connu.login == account && connu.id == id)
            {
                return Err(Refus::Doublon);
            }
            if siens >= APPAREILS_PAR_COMPTE {
                return Err(Refus::Plein);
            }
            appareils.push(a_ranger);
            Ok(())
        });
        match issue {
            Ok(()) => {}
            Err(Refus::Preuve) => return refus_d_appairage(sortie),
            Err(Refus::Doublon) => return deja_enrole(sortie),
            Err(Refus::Plein) => return trop_d_appareils(sortie),
            Err(Refus::Magasin(quoi)) => return dire_la_faute(&quoi, sortie),
        }

        self.noter(
            account,
            crate::audit::Evenement::AppareilAppaire {
                appareil: &id,
                nom: demande.name,
            },
            Some(source),
        );
        let vues: std::vec::Vec<&str> = adresses.iter().map(String::as_str).collect();
        cree(render::write_enrolled(&id, account, &vues, sortie))
    }

    /// Les mots de passe applicatifs de qui appelle — **sans leurs secrets**, que
    /// le serveur n'a pas.
    fn mes_applicatifs<'o>(&self, account: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let Some(magasin) = self.applicatifs.as_ref() else {
            return pas_encore(sortie);
        };
        let siens = magasin.du_compte(account);
        let lignes: std::vec::Vec<render::AppPasswordRow<'_>> = siens
            .iter()
            .map(|entree| render::AppPasswordRow {
                id: &entree.id,
                name: &entree.name,
                created: entree.created,
                last_used: entree.last_used,
            })
            .collect();
        rendre(render::write_app_passwords(&lignes, sortie))
    }

    /// Crée un mot de passe applicatif pour qui appelle, et le rend UNE FOIS.
    ///
    /// # LE SERVEUR TIRE LE SECRET
    ///
    /// Cent vingt-huit bits du noyau. Un secret choisi par l'utilisateur serait
    /// réemployé ailleurs, deviné, ou trop court — et c'est parce qu'il ne l'est
    /// pas qu'un SHA-256 suffit à le ranger.
    ///
    /// # UN JETON SUFFIT, ET C'EST UN CHOIX
    ///
    /// Contrairement à l'appairage, qui crée une clef valant jusqu'à sa
    /// révocation, un mot de passe applicatif **n'ouvre pas cette API** : un
    /// jeton volé qui en fabriquerait un obtiendrait l'accès au courrier, pas
    /// celui de fabriquer davantage une fois le jeton expiré. Il reste visible
    /// dans la liste que le propriétaire lit, et se révoque seul.
    fn creer_un_applicatif<'o>(
        &self,
        account: &str,
        body: &[u8],
        source: ams_guard::Source,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(magasin) = self.applicatifs.as_ref() else {
            return pas_encore(sortie);
        };
        let mut place = [0_u8; ams_config::APP_NOM_OCTETS_MAX];
        let Ok(nom) = render::read_app_password_request(body, &mut place) else {
            return corps_refuse(sortie);
        };
        if !self
            .comptes
            .vue()
            .iter()
            .any(|compte| compte.login == account)
        {
            return absente(sortie);
        }
        let mut alea = [0_u8; ams_auth::APP_ALEA_OCTETS];
        {
            use std::io::Read as _;
            if std::fs::File::open("/dev/urandom")
                .and_then(|mut source| source.read_exact(&mut alea))
                .is_err()
            {
                return notre_faute();
            }
        }
        let (id, mot_de_passe, condensat) = ams_auth::fabriquer_applicatif(&alea);
        let cree_le = crate::maintenant();
        let neuf = ams_auth::AppPassword {
            login: String::from(account),
            id: id.clone(),
            name: String::from(nom),
            created: cree_le,
            last_used: 0,
            digest: condensat,
        };
        // **LE PLAFOND SE JUGE SOUS LE VERROU** : deux créations simultanées
        // passeraient sinon toutes deux un contrôle fait avant.
        let mut plein = false;
        if let Err(quoi) = magasin.modifier(|entrees| {
            if entrees.iter().filter(|e| e.login == account).count() >= APPLICATIFS_PAR_COMPTE {
                plein = true;
                return Err(crate::applicatifs::INTROUVABLE);
            }
            entrees.push(neuf);
            Ok(())
        }) {
            return match plein {
                true => probleme(ams_api::Reason::LimitReached, StatusCode::CONFLICT, sortie),
                false => dire_la_faute(&quoi, sortie),
            };
        }
        self.noter(
            account,
            crate::audit::Evenement::ApplicatifCree { id: &id, nom },
            Some(source),
        );
        cree(render::write_app_password_created(
            &render::AppPasswordRow {
                id: &id,
                name: nom,
                created: cree_le,
                last_used: 0,
            },
            &mot_de_passe,
            sortie,
        ))
    }

    /// Révoque un mot de passe applicatif à soi.
    ///
    /// Celui d'un autre est « introuvable », et non « interdit » — la même règle
    /// que pour les appareils, et pour la même raison.
    fn revoquer_un_applicatif<'o>(
        &self,
        account: &str,
        id: &str,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(magasin) = self.applicatifs.as_ref() else {
            return pas_encore(sortie);
        };
        match magasin.modifier(|entrees| {
            let place = entrees
                .iter()
                .position(|entree| entree.login == account && entree.id == id)
                .ok_or(crate::applicatifs::INTROUVABLE)?;
            entrees.remove(place);
            Ok(())
        }) {
            Ok(()) => sans_contenu(),
            Err(quoi) => dire_la_faute(&quoi, sortie),
        }
    }

    /// Les boîtes d'autrui que ce compte atteint, et ses droits sur chacune.
    fn mes_delegations<'o>(&self, account: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let recues = self
            .delegations
            .as_ref()
            .map(|table| table.recues_par(account))
            .unwrap_or_default();
        let noms: std::vec::Vec<std::vec::Vec<&str>> =
            recues.iter().map(|tenue| tenue.rights.names()).collect();
        let lignes: std::vec::Vec<render::DelegationRow<'_>> = recues
            .iter()
            .zip(&noms)
            .map(|(tenue, droits)| render::DelegationRow {
                login: &tenue.owner,
                rights: droits,
            })
            .collect();
        rendre(render::write_delegations(
            "delegations",
            "account",
            &lignes,
            sortie,
        ))
    }

    /// Qui atteint la boîte de ce compte, et avec quels droits.
    fn delegues_de<'o>(&self, compte: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let Some(table) = self.delegations.as_ref() else {
            return pas_encore(sortie);
        };
        if !self.comptes.vue().iter().any(|connu| connu.login == compte) {
            return absente(sortie);
        }
        let accordees = table.accordees_par(compte);
        let noms: std::vec::Vec<std::vec::Vec<&str>> =
            accordees.iter().map(|tenue| tenue.rights.names()).collect();
        let lignes: std::vec::Vec<render::DelegationRow<'_>> = accordees
            .iter()
            .zip(&noms)
            .map(|(tenue, droits)| render::DelegationRow {
                login: &tenue.delegate,
                rights: droits,
            })
            .collect();
        rendre(render::write_delegations(
            "delegates",
            "login",
            &lignes,
            sortie,
        ))
    }

    /// Pose ou remplace une délégation. `201` si elle est neuve, `200` si elle
    /// en remplace une.
    ///
    /// **LES DEUX COMPTES DOIVENT EXISTER**, et être deux : une délégation de
    /// soi à soi ne donnerait rien. Les droits se nomment `read`, `write`,
    /// `send` ; écrire et envoyer IMPLIQUENT lire, et la réponse le montre.
    fn poser_une_delegation<'o>(
        &self,
        compte: &str,
        delegue: &str,
        body: &[u8],
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(table) = self.delegations.as_ref() else {
            return pas_encore(sortie);
        };
        let Ok((noms, combien)) = render::read_rights_request(body) else {
            return corps_refuse(sortie);
        };
        let mut droits = ams_config::Rights::READ;
        for nom in noms.iter().take(combien) {
            let Some(droit) = ams_config::Rights::from_name(nom) else {
                return corps_refuse(sortie);
            };
            droits = droits.with(droit);
        }
        if compte == delegue {
            return refus_de_compte(sortie);
        }
        {
            let comptes = self.comptes.vue();
            let existe = |login: &str| comptes.iter().any(|connu| connu.login == login);
            if !existe(compte) || !existe(delegue) {
                return absente(sortie);
            }
        }
        let mut neuve = true;
        if let Err(quoi) = table.modifier(|tenues| {
            neuve = !tenues
                .iter()
                .any(|tenue| tenue.delegate == delegue && tenue.owner == compte);
            tenues.retain(|tenue| !(tenue.delegate == delegue && tenue.owner == compte));
            tenues.push(ams_config::Delegation {
                delegate: String::from(delegue),
                owner: String::from(compte),
                rights: droits,
            });
            Ok(())
        }) {
            return dire_la_faute(&quoi, sortie);
        }
        eprintln!(
            "air-mail-server : délégation posée — `{delegue}` atteint la boîte de `{compte}` \
             ({})",
            droits.names().join(", ")
        );
        let noms = droits.names();
        let servi = rendre(render::write_delegations(
            "delegates",
            "login",
            &[render::DelegationRow {
                login: delegue,
                rights: &noms,
            }],
            sortie,
        ));
        Served {
            status: if neuve {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            ..servi
        }
    }

    /// Retire une délégation : elle cesse de valoir à la requête suivante.
    fn retirer_une_delegation<'o>(
        &self,
        compte: &str,
        delegue: &str,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(table) = self.delegations.as_ref() else {
            return pas_encore(sortie);
        };
        match table.modifier(|tenues| {
            let place = tenues
                .iter()
                .position(|tenue| tenue.delegate == delegue && tenue.owner == compte)
                .ok_or(crate::delegations::INTROUVABLE)?;
            tenues.remove(place);
            Ok(())
        }) {
            Ok(()) => {
                eprintln!(
                    "air-mail-server : délégation retirée — `{delegue}` n'atteint plus la \
                     boîte de `{compte}`"
                );
                sans_contenu()
            }
            Err(quoi) => dire_la_faute(&quoi, sortie),
        }
    }

    /// Révoque un appareil à soi.
    ///
    /// # UN APPAREIL QUI N'EST PAS LE SIEN EST « INTROUVABLE »
    ///
    /// Et non « interdit ». La distinction serait l'information elle-même :
    /// répondre 403 sur l'appareil d'un autre et 404 sur un identifiant qui
    /// n'existe pas laisserait énumérer les appareils du serveur, un
    /// identifiant à la fois.
    ///
    /// # ELLE N'EST PAS IDEMPOTENTE, ET C'EST VOULU
    ///
    /// Révoquer deux fois rend 404 la seconde fois. §9.3.5 de RFC 9110 l'admet :
    /// ce qui doit être idempotent, c'est l'EFFET, et il l'est — l'appareil
    /// n'est plus là dans les deux cas. Rendre 204 à une révocation qui n'a rien
    /// retiré laisserait croire qu'on a retiré quelque chose.
    /// Révoque un appareil de ce compte — ou TOUS, quand `id` est `None`.
    ///
    /// `par` dit qui révoque : son titulaire (`self`) ou l'administration
    /// (`admin`), et le journal d'audit l'écrit.
    ///
    /// # TOUS, C'EST LA VOIE DE SECOURS (0.2.41)
    ///
    /// Une invitation ne vaut que pour un compte sans appareil, et un
    /// utilisateur qui a perdu son seul téléphone n'a plus rien pour en
    /// approuver un autre. L'exploitant révoque donc tout, puis réinvite.
    /// **Révoquer tout sur un compte qui n'a rien est déjà l'état demandé** :
    /// `204` aussi.
    fn revoquer_des_appareils<'o>(
        &self,
        compte: &str,
        id: Option<&str>,
        par: &'static str,
        source: ams_guard::Source,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(magasin) = self.appareils.as_ref() else {
            return pas_encore(sortie);
        };
        let mut revoques: std::vec::Vec<String> = std::vec::Vec::new();
        match magasin.modifier(|appareils| {
            match id {
                Some(id) => {
                    let place = appareils
                        .iter()
                        .position(|connu| connu.login == compte && connu.id == id)
                        .ok_or(crate::appareils::INTROUVABLE)?;
                    revoques.push(appareils.remove(place).id);
                }
                None => appareils.retain(|connu| {
                    let sien = connu.login == compte;
                    if sien {
                        revoques.push(connu.id.clone());
                    }
                    !sien
                }),
            }
            Ok(())
        }) {
            Ok(()) => {
                // **UNE RÉVOCATION RÉVOQUE** : ses sessions ferment ici, et non
                // à l'expiration de leurs jetons. L'abonnement, lui, est parti
                // avec la fiche.
                for appareil in &revoques {
                    self.sessions.fermer_l_appareil(compte, appareil);
                    self.noter(
                        compte,
                        crate::audit::Evenement::AppareilRevoque { appareil, par },
                        Some(source),
                    );
                }
                if par == "admin" {
                    eprintln!(
                        "air-mail-server : l'administration a révoqué {} appareil(s) de `{compte}`",
                        revoques.len()
                    );
                }
                sans_contenu()
            }
            Err(quoi) => dire_la_faute(&quoi, sortie),
        }
    }

    /// Ce que le réveil a fait pour les appareils de ce compte.
    fn bilan_du_reveil(&self, account: &str) -> crate::reveil::Bilan {
        self.reveil
            .as_ref()
            .map(|reveil| reveil.bilan(account))
            .unwrap_or_default()
    }

    /// L'appareil qui a ouvert la session de cette requête, s'il y en a un.
    fn appareil_de_la_session(&self, account: &str, nonce: u64) -> Option<String> {
        self.sessions.appareil(account, nonce, microsecondes())
    }

    /// `GET /v1/me/push` — l'abonnement de l'appareil qui appelle.
    fn mon_abonnement<'o>(&self, account: &str, nonce: u64, sortie: &'o mut [u8]) -> Served<'o> {
        let Some(magasin) = self.appareils.as_ref() else {
            return pas_encore(sortie);
        };
        let Some(id) = self.appareil_de_la_session(account, nonce) else {
            return probleme(ams_api::Reason::NotADevice, StatusCode::CONFLICT, sortie);
        };
        let siens = magasin.du_compte(account);
        let Some(appareil) = siens.iter().find(|connu| connu.id == id) else {
            return absente(sortie);
        };
        let abonnement = appareil
            .push
            .as_ref()
            .map(|push| (push.channel().name(), push.since()));
        rendre(render::write_push(
            abonnement,
            self.vapid.as_deref(),
            sortie,
        ))
    }

    /// `PUT /v1/me/push` — abonne l'appareil qui appelle, ou remplace son
    /// abonnement.
    ///
    /// # LA SESSION DÉSIGNE L'APPAREIL, ET LA RÈGLE EST CELLE DU FICHIER
    ///
    /// Aucun identifiant dans le chemin ni dans le corps : c'est la session,
    /// ouverte par la clef, qui dit quel appareil on abonne. Et l'abonnement
    /// passe par [`ams_config::Push::new`], la même porte que le fichier relu
    /// au démarrage — ce qui est accepté ici se relira.
    fn abonner<'o>(
        &self,
        account: &str,
        nonce: u64,
        corps: &[u8],
        source: ams_guard::Source,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let mut jeton = [0_u8; ams_config::FCM_TOKEN_MAX];
        let Ok(demande) = render::read_push_request(corps, &mut jeton) else {
            return corps_refuse(sortie);
        };
        let Some(magasin) = self.appareils.as_ref() else {
            return pas_encore(sortie);
        };
        let Some(id) = self.appareil_de_la_session(account, nonce) else {
            return probleme(ams_api::Reason::NotADevice, StatusCode::CONFLICT, sortie);
        };
        let Some(canal) = ams_config::PushChannel::from_name(demande.channel) else {
            return corps_refuse(sortie);
        };
        let Ok(abonnement) = ams_config::Push::new(
            canal,
            String::from(demande.token),
            demande.key.map(|cle| cle.to_vec()).unwrap_or_default(),
            demande.auth.map(|auth| auth.to_vec()).unwrap_or_default(),
            crate::maintenant(),
        ) else {
            return corps_refuse(sortie);
        };
        let resume = (abonnement.channel().name(), abonnement.since());
        match magasin.modifier(|appareils| {
            let appareil = appareils
                .iter_mut()
                .find(|connu| connu.login == account && connu.id == id)
                .ok_or(crate::appareils::INTROUVABLE)?;
            appareil.push = Some(abonnement);
            Ok(())
        }) {
            Ok(()) => {
                self.noter(
                    account,
                    crate::audit::Evenement::Abonnement {
                        appareil: &id,
                        canal: resume.0,
                    },
                    Some(source),
                );
                rendre(render::write_push(
                    Some(resume),
                    self.vapid.as_deref(),
                    sortie,
                ))
            }
            Err(quoi) => dire_la_faute(&quoi, sortie),
        }
    }

    /// `DELETE /v1/me/push` — désabonne l'appareil qui appelle.
    ///
    /// **SANS ABONNEMENT, C'EST DÉJÀ L'ÉTAT DEMANDÉ** : `204` aussi, comme un
    /// client qui se désabonne deux fois ne fait rien de mal.
    fn desabonner<'o>(
        &self,
        account: &str,
        nonce: u64,
        source: ams_guard::Source,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(magasin) = self.appareils.as_ref() else {
            return pas_encore(sortie);
        };
        let Some(id) = self.appareil_de_la_session(account, nonce) else {
            return probleme(ams_api::Reason::NotADevice, StatusCode::CONFLICT, sortie);
        };
        match magasin.modifier(|appareils| {
            let appareil = appareils
                .iter_mut()
                .find(|connu| connu.login == account && connu.id == id)
                .ok_or(crate::appareils::INTROUVABLE)?;
            appareil.push = None;
            Ok(())
        }) {
            Ok(()) => {
                self.noter(
                    account,
                    crate::audit::Evenement::Desabonnement { appareil: &id },
                    Some(source),
                );
                sans_contenu()
            }
            Err(quoi) => dire_la_faute(&quoi, sortie),
        }
    }

    /// Frappe une invitation pour un compte.
    ///
    /// # LE COMPTE DOIT EXISTER, ET ON LE VÉRIFIE ICI
    ///
    /// Une invitation pour un compte qui n'existe pas est une faute de frappe de
    /// l'exploitant, et elle ne se verrait qu'à l'enrôlement — c'est-à-dire chez
    /// l'utilisateur, qui n'y peut rien et ne saura pas quoi dire.
    ///
    /// # ET ON NE VÉRIFIE PAS QU'IL N'A PAS D'APPAREIL
    ///
    /// Ce serait courir après l'état : entre la frappe et l'enrôlement, un
    /// appareil peut s'enrôler ou se révoquer. **C'est l'enrôlement qui décide**,
    /// parce que c'est lui qui agit. Refuser ici en plus donnerait deux règles
    /// pour une seule question, et elles divergeraient.
    fn frapper_une_invitation<'o>(
        &self,
        body: &[u8],
        source: ams_guard::Source,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(clef) = self.scellement.as_ref() else {
            return pas_encore(sortie);
        };
        let Ok(demande) = render::read_invitation_request(body) else {
            return corps_refuse(sortie);
        };
        // **LE COMPTE, MAINTENANT** : voir ci-dessus.
        if !self
            .comptes
            .vue()
            .iter()
            .any(|compte| compte.login == demande.login)
        {
            return absente(sortie);
        }

        let minutes = demande.minutes.unwrap_or(INVITATION_MINUTES);
        let Some(duree) = minutes
            .checked_mul(60_000_000)
            .filter(|duree| *duree <= ams_api::INVITATION_LIFETIME_MAX_US && *duree > 0)
        else {
            return corps_refuse(sortie);
        };
        let maintenant = microsecondes();
        let expiry = maintenant.saturating_add(duree);

        let mut texte = [0_u8; ams_api::INVITATION_ENCODED_OCTETS_MAX];
        let Ok(ecrite) = ams_api::issue_invitation(
            clef,
            &ams_api::Invitation {
                login: demande.login,
                expiry,
            },
            maintenant,
            &mut texte,
        ) else {
            // Le nom vient du magasin, donc il est recevable ; ce qui reste est
            // notre tampon, et c'est notre faute.
            return notre_faute();
        };
        self.noter(
            demande.login,
            crate::audit::Evenement::InvitationEmise,
            Some(source),
        );
        // **EN SECONDES DEHORS**, comme tout ce que cette API rend.
        cree(render::write_invitation(
            ecrite,
            demande.login,
            expiry / 1_000_000,
            sortie,
        ))
    }

    /// Cet appareil a-t-il signé ce défi, pour CE geste ?
    ///
    /// # ELLE NE FAIT QUE LIRE
    ///
    /// Le défi n'est consommé que par [`Self::consommer`], dans la même
    /// écriture que ce que la preuve autorise. **Une demande qui échoue après la
    /// signature ne touche donc pas à la date de l'appareil** : un appairage
    /// refusé pour doublon n'empêche pas la session qui suit.
    ///
    /// # TROIS CONTRÔLES, ET LE TROISIÈME EST CELUI QU'ON OUBLIE
    ///
    /// 1. **L'appareil existe**, sous ce compte, et porte une clef ;
    /// 2. **la signature couvre le condensat de CE défi**, lié au domaine de ce
    ///    serveur ET AU RÔLE — pas le défi nu ;
    /// 3. **le défi a été émis après la dernière session de cet appareil.**
    ///
    /// Le troisième est l'usage unique. Sans lui, un défi vaudrait soixante
    /// secondes et se rejouerait autant de fois qu'on veut pendant ce temps. Il
    /// est jugé ici pour refuser tôt, et **rejugé sous le verrou** par
    /// [`Self::consommer`] : deux présentations simultanées du même défi
    /// passeraient sinon toutes deux ce premier contrôle.
    ///
    /// # LE RÔLE SÉPARE DEUX GESTES QUI N'ONT PAS LA MÊME PORTÉE
    ///
    /// Ouvrir une session donne quinze minutes ; approuver un appairage crée une
    /// clef qui vaut jusqu'à sa révocation. **Une signature obtenue pour l'un ne
    /// vaut pas pour l'autre**, parce que les deux rôles donnent deux
    /// condensats. Et un appairage signe EN PLUS l'appareil qu'il approuve —
    /// voir [`ams_api::Geste`].
    ///
    /// # UN SEUL REFUS POUR TOUTES LES CAUSES
    ///
    /// Appareil inconnu, clef qui ne correspond pas, signature mal écrite,
    /// rejeu : `None` dans tous les cas. Les distinguer dirait à qui essaie si
    /// cet appareil existe — ce que l'émission du défi refuse déjà de dire.
    fn signature_recevable(
        &self,
        geste: ams_api::Geste<'_>,
        account: &str,
        device: &str,
        issued_at_ms: u64,
        challenge: &str,
        signature: &str,
    ) -> Option<()> {
        let magasin = self.appareils.as_ref()?;
        let connu = magasin
            .du_compte(account)
            .into_iter()
            .find(|appareil| appareil.id == device)?;

        // **LE REJEU SE REFUSE AVANT LA CRYPTOGRAPHIE**, et cet ordre a une
        // conséquence qu'il faut nommer plutôt que taire.
        //
        // Un rejeu sort d'ici sans vérifier de signature ; une signature fausse,
        // elle, coûte un décodage et une vérification sur la courbe. **Les deux
        // rendent la même réponse, mais pas dans le même temps** — et ce temps
        // dit « cet appareil s'est authentifié depuis que ce défi a été émis ».
        //
        // On garde cet ordre, pour une raison précise : **exploiter cette
        // différence suppose de connaître un identifiant d'appareil**, et un
        // identifiant est le condensat SHA-256 d'une clef publique. Il ne se
        // devine pas, et la seule route qui les liste exige le jeton de leur
        // propriétaire. Qui le connaît déjà a déjà davantage.
        if connu.last_seen >= issued_at_ms {
            return None;
        }

        let mut octets = [0_u8; ams_auth::SIGNATURE_OCTETS];
        let lue = ams_api::decode_base64url(signature.as_bytes(), &mut octets).ok()?;
        // **VIDE, RIEN NE SE VÉRIFIE**, et c'est le bon défaut : un condensat
        // lié à un domaine vide serait un condensat que deux serveurs
        // partageraient.
        if self.domaine.is_empty() {
            return None;
        }
        let condensat = ams_api::digest(geste, &self.domaine, challenge.as_bytes());
        ams_auth::verifier(&connu.public_key, &condensat, lue).ok()
    }

    /// Consomme le défi d'un appareil, et fait ce qu'il autorise, **dans la
    /// même écriture**.
    ///
    /// `ensuite` reçoit les appareils sous le verrou ; s'il refuse, **rien
    /// n'est écrit** — ni ce qu'il allait faire, ni la date de l'appareil.
    ///
    /// # L'ACCEPTATION ÉCRIT, SINON ELLE NE VAUT RIEN
    ///
    /// Noter la date est ce qui tue le défi. **Si cette écriture échoue, on
    /// REFUSE** : accorder sans noter laisserait le défi rejouable, et un disque
    /// plein deviendrait une faille.
    fn consommer<F>(&self, device: &str, issued_at_ms: u64, ensuite: F) -> Result<(), Refus>
    where
        F: FnOnce(&mut std::vec::Vec<ams_config::Device>) -> Result<(), Refus>,
    {
        let magasin = self.appareils.as_ref().ok_or(Refus::Preuve)?;
        let quand = millisecondes();
        // Ce que `ensuite` ou le rejeu ont refusé. Le magasin ne connaît que
        // ses propres fautes : on abandonne l'écriture par l'une d'elles, et la
        // vraie raison attend ici.
        let mut refus = None;
        let ecrit = magasin.modifier(|appareils| {
            let decide = (|| {
                // **LE REJEU, REJUGÉ SOUS LE VERROU** : c'est ici, et non dans
                // la lecture qui précède, que l'usage unique se décide.
                let connu = appareils
                    .iter()
                    .find(|appareil| appareil.id == device)
                    .ok_or(Refus::Preuve)?;
                if connu.last_seen >= issued_at_ms {
                    return Err(Refus::Preuve);
                }
                ensuite(&mut *appareils)?;
                let vu = appareils
                    .iter_mut()
                    .find(|appareil| appareil.id == device)
                    .ok_or(Refus::Preuve)?;
                vu.last_seen = quand;
                Ok(())
            })();
            decide.map_err(|raison| {
                refus = Some(raison);
                crate::appareils::INTROUVABLE
            })
        });
        match (ecrit, refus) {
            (Ok(()), _) => Ok(()),
            (Err(_), Some(raison)) => Err(raison),
            (Err(quoi), None) => Err(Refus::Magasin(quoi)),
        }
    }

    /// Cette signature ouvre-t-elle une session ?
    fn verifier_un_appareil(
        &self,
        account: &str,
        device: &str,
        issued_at_ms: u64,
        challenge: &str,
        signature: &str,
    ) -> Option<Scope> {
        self.signature_recevable(
            ams_api::Geste::Session,
            account,
            device,
            issued_at_ms,
            challenge,
            signature,
        )?;
        if let Err(raison) = self.consommer(device, issued_at_ms, |_| Ok(())) {
            if let Refus::Magasin(quoi) = raison {
                eprintln!("air-mail-server : magasin d'appareils — {quoi}");
            }
            return None;
        }
        // **LA MÊME PORTÉE QU'UN MOT DE PASSE, ET JAMAIS `admin`.** Une clef
        // d'appareil n'est pas une autorité d'exploitation : elle prouve qu'on
        // tient un téléphone, pas qu'on lit le secret de scellement.
        Some(PORTEE_DE_SESSION)
    }

    /// Enrôle une clef publique sur un compte, sur la foi d'une invitation que
    /// la session a déjà vérifiée.
    #[expect(
        clippy::too_many_arguments,
        reason = "les mêmes que `Api::enrol`, dont elle est le corps"
    )]
    fn enroler<'o>(
        &self,
        account: &str,
        public_key: &str,
        name: &str,
        invitation: &str,
        attestation: Option<&str>,
        source: ams_guard::Source,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(magasin) = self.appareils.as_ref() else {
            return pas_encore(sortie);
        };
        // **LA CLEF SE DÉCODE ET SE VALIDE AVANT TOUT LE RESTE.** Une clef qui
        // n'est pas un point de la courbe n'est pas une clef faible : c'est une
        // clef qui n'existe pas, et la ranger ouvrirait les attaques par courbe
        // invalide.
        let mut octets = [0_u8; ams_auth::CLE_OCTETS];
        let Ok(lus) = ams_api::decode_base64url(public_key.as_bytes(), &mut octets) else {
            return corps_de_l_enrolement_refuse(sortie);
        };
        let Ok(cle) = ams_auth::Cle::lire(lus) else {
            return corps_de_l_enrolement_refuse(sortie);
        };

        // Le compte de l'invitation doit toujours exister : un administrateur a
        // pu le retirer entre la frappe et l'enrôlement.
        let comptes = self.comptes.vue();
        let Some(compte) = comptes.iter().find(|connu| connu.login == account) else {
            return absente(sortie);
        };

        // **L'USAGE UNIQUE EST ICI, ET NULLE PART AILLEURS** : l'invitation ne
        // vaut que tant que le compte n'a AUCUN appareil. Le premier enrôlement
        // la tue, et aucun registre n'a à s'en souvenir.
        if !magasin.du_compte(account).is_empty() {
            return deja_enrole(sortie);
        }

        // **L'IDENTIFIANT EST LE CONDENSAT DE LA CLEF**, et non un tirage.
        //
        // Trois raisons. Il n'a besoin d'AUCUN aléa, donc d'aucune source qui
        // puisse manquer — celle du serveur rend zéro quand `/dev/urandom` ne
        // s'ouvre pas, et deux appareils porteraient alors le même identifiant.
        // Il est unique par construction, puisque deux clefs distinctes
        // n'auraient le même condensat qu'au prix d'une collision SHA-256. Et
        // c'est déjà l'EMPREINTE dont l'enrôlement croisé aura besoin pour se
        // faire confirmer de visu.
        // **L'ATTESTATION, AVANT DE RIEN ÉCRIRE** (0.2.39) : son défi est le
        // condensat de l'invitation, et une attestation refusée ne consomme
        // rien.
        let atteste =
            match self
                .juge
                .juger(&cle.octets(), invitation, attestation, maintenant_i64())
            {
                Ok(atteste) => atteste,
                Err(refus) => return self.refuser_l_attestation(account, refus, sortie),
            };
        let id = en_hexadecimal(&ams_sasl::sha256(&cle.octets()));

        let a_ranger = ams_config::Device {
            login: String::from(account),
            id: id.clone(),
            name: String::from(name),
            enrolled: crate::maintenant(),
            last_seen: 0,
            push: None,
            attestation: atteste,
            public_key: cle,
        };
        if let Err(quoi) = magasin.modifier(move |appareils| {
            appareils.push(a_ranger);
            Ok(())
        }) {
            return dire_la_faute(&quoi, sortie);
        }

        self.noter(
            account,
            crate::audit::Evenement::AppareilEnrole {
                appareil: &id,
                nom: name,
            },
            Some(source),
        );
        let adresses: std::vec::Vec<&str> = compte
            .addresses
            .iter()
            .map(std::string::String::as_str)
            .collect();
        cree(render::write_enrolled(&id, account, &adresses, sortie))
    }

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
            // Ni les nœuds, ni les boîtes de l'espace `Partagés` : voir `serve`.
            if !vue.selectable || ams_proto_imap::shared_name(vue.name).is_some() {
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
                highest_modseq: None,
            });
        }
        rendre(render::write_mailboxes(&lignes, sortie))
    }

    /// L'état d'une boîte.
    fn mailbox<'o>(&self, compte: &str, nom: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let Some(boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };
        // **LE POINT DU JOURNAL, TENU MAINTENANT** : c'est le curseur qu'un
        // client prend avant sa lecture complète.
        let journal = match self.journal_de(&boite) {
            Ok(journal) => journal,
            Err(servi) => return servi(sortie),
        };
        let ligne = MailboxRow {
            name: nom,
            messages: boite.exists(),
            unseen: non_lus(&boite),
            uid_next: boite.uid_next(),
            uid_validity: boite.uid_validity(),
            highest_modseq: Some(journal.modseq),
        };
        rendre(render::write_mailbox(&ligne, sortie))
    }

    /// Réconcilie le journal de cette boîte ouverte, et le rend — ou la réponse
    /// à faire si le disque ne suit pas.
    fn journal_de(
        &self,
        boite: &crate::imap::BoiteImap,
    ) -> Result<ams_config::Journal, fn(&mut [u8]) -> Served<'_>> {
        let vus: std::vec::Vec<(u32, u16)> = (1..=boite.exists())
            .filter_map(|sequence| boite.info(sequence))
            .map(|info| (info.uid, info.flags.bits()))
            .collect();
        crate::journal::reconcilier(boite.racine(), boite.uid_validity(), &vus).map_err(|cause| {
            eprintln!("air-mail-server : journal des changements — {cause}");
            indisponible as fn(&mut [u8]) -> Served<'_>
        })
    }

    /// Ce qui a changé dans une boîte depuis `since` — **LA SYNCHRONISATION
    /// INCRÉMENTALE**.
    ///
    /// Le journal se réconcilie d'abord : ce que le répertoire montre
    /// maintenant, comparé à ce qu'on avait vu. Puis on rend ce qui a un point
    /// au-delà de `since`, au plus `limit` messages changés — en entier, comme
    /// dans la liste — et une page de disparitions. `more` dit s'il faut
    /// revenir tout de suite avec le `modseq` rendu.
    fn changements<'o>(
        &self,
        compte: &str,
        nom: &str,
        requete: ams_api::Query,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let limite = requete.limit.map_or(PAGE_MAX, usize::from);
        let (Some(depuis), true) = (requete.since, limite <= PAGE_MAX) else {
            return probleme(ams_api::Reason::BadQuery, StatusCode::BAD_REQUEST, sortie);
        };
        let Some(boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };
        let journal = match self.journal_de(&boite) {
            Ok(journal) => journal,
            Err(servi) => return servi(sortie),
        };
        let Ok(delta) = journal.since(depuis, limite, DISPARUS_PAR_PAGE) else {
            return probleme(ams_api::Reason::SyncExpired, StatusCode::GONE, sortie);
        };
        // Le rang de chaque UID dans l'instantané, pour relire son résumé.
        let rangs: std::vec::Vec<(u32, u32)> = (1..=boite.exists())
            .filter_map(|sequence| boite.info(sequence).map(|info| (info.uid, sequence)))
            .collect();
        let resumes: std::vec::Vec<Resume> = delta
            .changed
            .iter()
            .filter_map(|uid| {
                let rang = rangs.binary_search_by_key(uid, |&(connu, _)| connu).ok()?;
                let (_, sequence) = *rangs.get(rang)?;
                Some(resumer(&boite, sequence, boite.info(sequence)?))
            })
            .collect();
        let lignes: std::vec::Vec<MessageRow<'_>> = resumes.iter().map(ligne_de).collect();
        rendre(render::write_changes(
            &lignes,
            &delta.vanished,
            boite.uid_validity(),
            delta.modseq,
            delta.more,
            sortie,
        ))
    }

    /// Une page de messages, **LES PLUS RÉCENTS D'ABORD**.
    ///
    /// # L'ORDRE EST CELUI QU'UN CLIENT AFFICHE
    ///
    /// La première page est ce que l'utilisateur regarde en ouvrant sa boîte :
    /// elle doit porter les derniers arrivés. Jusqu'en 0.2.17, elle portait les
    /// cinquante PLUS ANCIENS, et le curseur ne pouvait pas être renvoyé — la
    /// chaîne de requête était jetée.
    ///
    /// # LE CURSEUR EST UN UID, ET IL NE BOUGE PAS
    ///
    /// `before=<uid>` rend les messages d'UID strictement inférieur. Un UID ne
    /// change pas quand d'autres messages arrivent ou partent — là où un
    /// décalage (« à partir du 51e ») sauterait ou répéterait des messages dès
    /// que la boîte bouge entre deux pages. `next` est l'UID du dernier rendu :
    /// le renvoyer tel quel en `before` donne la page suivante.
    fn messages<'o>(
        &self,
        compte: &str,
        nom: &str,
        requete: ams_api::Query,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let limite = requete.limit.map_or(PAGE_MAX, usize::from);
        if limite > PAGE_MAX {
            return probleme(ams_api::Reason::BadQuery, StatusCode::BAD_REQUEST, sortie);
        }
        let Some(boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };
        let avant = requete.before.unwrap_or(u32::MAX);
        let mut resumes = std::vec::Vec::with_capacity(limite);
        let mut suivant = None;
        // Les numéros de séquence suivent l'ordre des UID : les parcourir à
        // rebours, c'est aller du plus récent au plus ancien.
        for sequence in (1..=boite.exists()).rev() {
            let Some(info) = boite.info(sequence) else {
                continue;
            };
            if info.uid >= avant {
                continue;
            }
            if resumes.len() >= limite {
                // **IL EN RESTE** : le curseur est l'UID du dernier rendu, que
                // le client renvoie en `before`.
                suivant = resumes.last().map(|resume: &Resume| resume.info.uid);
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
        // **LE CORPS SEUL SE SOUMET D'UN TENANT** — décision de l'exploitant :
        // les pièces jointes passent par un brouillon, par morceaux sur disque.
        if !crate::forme::corps_seul(corps) {
            return probleme(
                ams_api::Reason::AttachmentsNeedDraft,
                ams_api::Reason::AttachmentsNeedDraft.status(),
                sortie,
            );
        }
        let vue = self.comptes.vue();
        // **ENVOYER AU NOM D'AUTRUI SE DÉLÈGUE** : le droit `send` sur la boîte
        // de support@ permet d'écrire `From: support@…`. Sans lui, la règle reste
        // celle d'avant — on n'écrit qu'en son nom.
        let peut_envoyer_pour = |titulaire: &str| {
            self.delegations
                .as_ref()
                .and_then(|table| table.droits(compte, titulaire))
                .is_some_and(|droits| droits.contains(ams_config::Rights::SEND))
        };
        let Some(expediteur) = ecrit_bien_en_son_nom(&vue, compte, peut_envoyer_pour, &message)
        else {
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
        if let Some(reveil) = self.reveil.clone() {
            remise = remise.avec_reveil(reveil);
        }
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
        // **UNE COPIE DANS « ENVOYÉS »**, telle que soumise — `Bcc` compris :
        // l'expéditeur, lui, doit savoir à qui il a écrit.
        self.copier_dans_envoyes(compte, &mut |ecrire| ecrire(corps));
        let combien = u64::try_from(destinataires.len()).unwrap_or(u64::MAX);
        rendre(render::write_metrics(&[("delivered", combien)], sortie))
    }

    /// Un geste sur un brouillon, qui ne rend rien de plus qu'un `204` ou une
    /// faute.
    fn sur_un_brouillon<'o>(
        &self,
        sortie: &'o mut [u8],
        geste: impl FnOnce(
            &crate::brouillons::Brouillons,
            u64,
        ) -> Result<Option<()>, crate::brouillons::Faute>,
    ) -> Served<'o> {
        let Some(brouillons) = self.brouillons.as_ref() else {
            return pas_encore(sortie);
        };
        match geste(brouillons, crate::maintenant()) {
            Ok(_) => sans_contenu(),
            Err(faute) => faute_de_brouillon(faute, sortie),
        }
    }

    /// Crée un brouillon à partir de son corps.
    fn creer_un_brouillon<'o>(
        &self,
        compte: &str,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(brouillons) = self.brouillons.as_ref() else {
            return pas_encore(sortie);
        };
        if ams_mime::Message::parse(corps, &ams_mime::Limits::DEFAULT).is_err() {
            return refus_de_depot(sortie);
        }
        // **UN BROUILLON COMMENCE PAR SON CORPS, ET PAR RIEN D'AUTRE** : ses
        // pièces jointes viennent ensuite, déclarées et par morceaux.
        if !crate::forme::corps_seul(corps) {
            return probleme(
                ams_api::Reason::AttachmentsNeedDraft,
                ams_api::Reason::AttachmentsNeedDraft.status(),
                sortie,
            );
        }
        let Some(alea) = seize_octets() else {
            return indisponible(sortie);
        };
        match brouillons.creer(compte, corps, crate::maintenant(), alea) {
            Ok((id, expire)) => cree(render::write_draft(&id, expire, &[], sortie)),
            Err(faute) => faute_de_brouillon(faute, sortie),
        }
    }

    /// L'état d'un brouillon : son expiration, et ce que chaque pièce a reçu.
    fn etat_du_brouillon<'o>(&self, compte: &str, id: &str, sortie: &'o mut [u8]) -> Served<'o> {
        let Some(brouillons) = self.brouillons.as_ref() else {
            return pas_encore(sortie);
        };
        match brouillons.etat(compte, id, crate::maintenant()) {
            Ok((expire, pieces)) => {
                let lignes: Vec<render::AttachmentRow<'_>> =
                    pieces.iter().map(ligne_de_piece).collect();
                rendre(render::write_draft(id, expire, &lignes, sortie))
            }
            Err(faute) => faute_de_brouillon(faute, sortie),
        }
    }

    /// Déclare une pièce jointe : son nom, son type, sa taille.
    fn declarer_une_piece<'o>(
        &self,
        compte: &str,
        id: &str,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(brouillons) = self.brouillons.as_ref() else {
            return pas_encore(sortie);
        };
        let mut place = [0_u8; 256];
        let Ok(demande) = render::read_attachment_request(corps, &mut place) else {
            return corps_refuse(sortie);
        };
        match brouillons.declarer(
            compte,
            id,
            demande.name,
            demande.media,
            demande.size,
            crate::maintenant(),
        ) {
            Ok(piece) => cree(render::write_attachment(&ligne_de_piece(&piece), sortie)),
            Err(faute) => faute_de_brouillon(faute, sortie),
        }
    }

    /// Pose un morceau de pièce jointe, placé par son `Content-Range`.
    fn poser_un_morceau<'o>(
        &self,
        compte: &str,
        id: &str,
        numero: u64,
        content_range: Option<&[u8]>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(brouillons) = self.brouillons.as_ref() else {
            return pas_encore(sortie);
        };
        // **UN MORCEAU DIT SA PLACE, OU IL NE SE RANGE PAS** (§14.4) : sans
        // `Content-Range`, on ne saurait pas où mettre ces octets.
        let Some((portee, total)) = content_range.and_then(ams_proto_http::parse_content_range)
        else {
            return corps_refuse(sortie);
        };
        match brouillons.poser(
            compte,
            id,
            numero,
            (portee.first, portee.last, total),
            corps,
            crate::maintenant(),
        ) {
            Ok(piece) => rendre(render::write_attachment(&ligne_de_piece(&piece), sortie)),
            Err(faute) => faute_de_brouillon(faute, sortie),
        }
    }

    /// Compose le brouillon et l'envoie — puis l'efface.
    ///
    /// # LA MÊME PORTE QUE `/v1/submissions`
    ///
    /// Le `From:` doit être du compte (ou d'un titulaire qui lui délègue
    /// l'envoi), les destinataires se lisent dans l'en-tête, et le `Bcc:`
    /// disparaît du message remis. Seule change la façon dont les octets
    /// arrivent à la remise : **par morceaux**, lus sur le disque et encodés au
    /// fil de l'eau — aucune pièce jointe n'est entière en mémoire.
    fn envoyer_le_brouillon<'o>(&self, compte: &str, id: &str, sortie: &'o mut [u8]) -> Served<'o> {
        use ams_loop_tokio::Delivery as _;
        let Some(brouillons) = self.brouillons.as_ref() else {
            return pas_encore(sortie);
        };
        let maintenant = crate::maintenant();
        let (corps, pieces) = match brouillons.a_composer(compte, id, maintenant) {
            Ok(pret) => pret,
            Err(faute) => return faute_de_brouillon(faute, sortie),
        };
        let bornes = ams_mime::Limits::DEFAULT;
        let Ok(message) = ams_mime::Message::parse(&corps, &bornes) else {
            return refus_de_depot(sortie);
        };
        let vue = self.comptes.vue();
        let peut_envoyer_pour = |titulaire: &str| {
            self.delegations
                .as_ref()
                .and_then(|table| table.droits(compte, titulaire))
                .is_some_and(|droits| droits.contains(ams_config::Rights::SEND))
        };
        let Some(expediteur) = ecrit_bien_en_son_nom(&vue, compte, peut_envoyer_pour, &message)
        else {
            crate::incidents::dire(&self.incidents, crate::incidents::Cause::Usurpation);
            return refus_de_depot(sortie);
        };
        let Some(destinataires) = destinataires_de(&vue, &message, self.file.is_some()) else {
            return refus_de_depot(sortie);
        };
        let Some(remis) = message_a_remettre(&corps, &message, &bornes) else {
            return notre_faute();
        };
        let frontiere = format!("=_air_{id}_=");
        let mut remise = self.une_remise();
        remise.begin(Some(expediteur));
        for adresse in &destinataires {
            if remise.add_recipient(adresse).is_err() {
                remise.abort();
                return indisponible(sortie);
            }
        }
        let ecoule = crate::brouillons::composer(&remis, &pieces, &frontiere, &mut |morceau| {
            remise.append(morceau).is_ok()
        });
        if !ecoule || remise.finish().is_err() {
            remise.abort();
            return indisponible(sortie);
        }
        // La copie se recompose depuis le disque, `Bcc` compris.
        self.copier_dans_envoyes(compte, &mut |ecrire| {
            crate::brouillons::composer(&corps, &pieces, &frontiere, ecrire)
        });
        let _ = brouillons.supprimer(compte, id, maintenant);
        let combien = u64::try_from(destinataires.len()).unwrap_or(u64::MAX);
        rendre(render::write_metrics(&[("delivered", combien)], sortie))
    }

    /// Compose le brouillon et le range dans une boîte du compte — puis
    /// l'efface. **Rien ne part** : c'est l'`APPEND` d'IMAP, le `Bcc:` compris.
    fn ranger_le_brouillon<'o>(
        &self,
        compte: &str,
        id: &str,
        corps_json: &[u8],
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        use ams_session::imap::Deposit as _;
        let Some(brouillons) = self.brouillons.as_ref() else {
            return pas_encore(sortie);
        };
        let mut place = [0_u8; ams_session::imap::MAILBOX_NAME_MAX];
        let Ok(boite) = render::read_store_request(corps_json, &mut place) else {
            return corps_refuse(sortie);
        };
        // L'espace `Partagés` est celui d'IMAP : voir `serve`.
        if ams_proto_imap::shared_name(boite.as_bytes()).is_some() {
            return absente(sortie);
        }
        let maintenant = crate::maintenant();
        let (corps, pieces) = match brouillons.a_composer(compte, id, maintenant) {
            Ok(pret) => pret,
            Err(faute) => return faute_de_brouillon(faute, sortie),
        };
        let Some(mut depot) = self.boites.append(compte.as_bytes(), boite.as_bytes()) else {
            return absente(sortie);
        };
        let frontiere = format!("=_air_{id}_=");
        if !crate::brouillons::composer(&corps, &pieces, &frontiere, &mut |morceau| {
            depot.write(morceau)
        }) {
            depot.abort();
            return notre_faute();
        }
        let Some(uid) = depot.commit(ams_proto_imap::Flags::NONE, None) else {
            return notre_faute();
        };
        let _ = brouillons.supprimer(compte, id, maintenant);
        cree(render::write_uid_cree(uid, sortie))
    }

    /// Une remise comme celle de `/v1/submissions` : file, domaines, DKIM.
    fn une_remise(&self) -> crate::delivery::MaildirDelivery {
        let mut remise = crate::delivery::MaildirDelivery::new(
            std::sync::Arc::clone(&self.remise),
            std::sync::Arc::clone(&self.comptes),
            std::sync::Arc::clone(&self.incidents),
        );
        if let Some(reveil) = self.reveil.clone() {
            remise = remise.avec_reveil(reveil);
        }
        if let Some(file) = self.file.clone() {
            remise = remise.avec_file(file, self.message_max);
        }
        remise = remise.avec_domaines(std::sync::Arc::clone(&self.domaines));
        if let Some(signataire) = self.dkim.clone() {
            remise = remise.avec_dkim(signataire);
        }
        remise
    }

    /// Range une copie de ce qui vient de partir dans la boîte d'envoi du
    /// compte, marquée lue.
    ///
    /// # L'ENVOI EST FAIT, QUOI QU'IL ARRIVE ICI
    ///
    /// Le message est remis ou en file : échouer maintenant ne le rappellerait
    /// pas, et rendre une erreur ferait renvoyer au client ce qui est parti.
    /// Un échec se DIT donc au journal, et la réponse reste celle de l'envoi.
    ///
    /// **SEUL CE QUI PASSE PAR L'API EST COPIÉ** : Thunderbird et Apple Mail
    /// rangent eux-mêmes leur copie par IMAP, et en ranger une de plus la
    /// doublerait.
    fn copier_dans_envoyes(&self, compte: &str, composer: &mut Composeur<'_>) {
        use ams_session::imap::Deposit as _;
        let dire = |quoi: &str| {
            eprintln!("air-mail-server : copie dans « Envoyés » pour `{compte}` — {quoi}");
        };
        let Some(boite) = self.boites.boite_d_envoi(compte.as_bytes()) else {
            return dire("aucune boîte d'envoi ne s'ouvre ni ne se crée");
        };
        let Some(mut depot) = self.boites.append(compte.as_bytes(), &boite) else {
            return dire("la boîte d'envoi refuse le dépôt");
        };
        if !composer(&mut |morceau| depot.write(morceau)) {
            depot.abort();
            return dire("la copie n'a pas pu s'écrire");
        }
        if depot.commit(ams_proto_imap::Flags::SEEN, None).is_none() {
            dire("la copie n'a pas pu se valider");
        }
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
        let Some(balayeur) = boite.structure(sequence) else {
            return absente(sortie);
        };
        let Some(entete) = balayeur.describe_path(&rangs) else {
            return absente(sortie);
        };
        match entete.kind {
            // **UN `multipart` N'A PAS DE CONTENU À LUI** : ce sont ses filles,
            // chacune sous son chemin. Rendre ses octets bruts ferait passer
            // des frontières MIME pour un document.
            ams_mime::PartKind::Multipart => absente(sortie),
            // UN MESSAGE TRANSFÉRÉ SE REND TEL QU'IL EST : c'est un message, et
            // il se lit comme `…/raw`.
            ams_mime::PartKind::Message => {
                // **UN DÉBUT ET UNE FIN, ET NON UNE LONGUEUR** : `part_span`
                // rend un intervalle. Les confondre faisait lire au-delà du
                // fichier — une partie parfaitement présente rendait `404`.
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
            ams_mime::PartKind::Leaf => {
                // Un contenu se décrit toujours comme une partie servie.
                let Some(partie) = balayeur.part_of(&rangs) else {
                    return absente(sortie);
                };
                servir_decodee(&boite, sequence, &entete, &partie, portee, sortie)
            }
        }
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
            disposition: None,
            body: rendu,
            ranges: true,
            range: partiel.then_some(ams_loop_tokio::http::ContentRange {
                part: Some((debut, dernier)),
                complete,
            }),
            // Rendre un message n'est jamais une tentative.
            peer_fault: false,
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
    /// Ajoute un message à une boîte, tel qu'il est donné.
    ///
    /// # CE N'EST PAS UNE SOUMISSION, ET LA DIFFÉRENCE EST ENTIÈRE
    ///
    /// `POST /v1/submissions` REMET un message : il vérifie que le compte écrit
    /// en son nom, route les destinataires, signe en DKIM. Ici, on RANGE un
    /// message dans une boîte — un brouillon, une copie d'envoi, un import.
    /// Rien n'est routé, rien n'est signé, et personne d'autre ne le reçoit.
    ///
    /// C'est l'`APPEND` d'IMAP (§6.3.12 de RFC 9051), par la même porte.
    fn ajouter_un_message<'o>(
        &self,
        compte: &str,
        nom: &str,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        use ams_session::imap::Deposit as _;

        // **LE MESSAGE SE LIT AVANT D'ÊTRE RANGÉ.** Ranger ce qu'on ne sait pas
        // relire donnerait une boîte qu'IMAP ne saurait plus servir.
        let bornes = ams_mime::Limits::DEFAULT;
        if ams_mime::Message::parse(corps, &bornes).is_err() {
            return refus_de_depot(sortie);
        }
        // Le dépôt suit la même règle que la soumission : le corps seul.
        if !crate::forme::corps_seul(corps) {
            return probleme(
                ams_api::Reason::AttachmentsNeedDraft,
                ams_api::Reason::AttachmentsNeedDraft.status(),
                sortie,
            );
        }
        let Some(mut depot) = self.boites.append(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };
        if !depot.write(corps) {
            depot.abort();
            return notre_faute();
        }
        // **AUCUN DRAPEAU IMPOSÉ** : un message rangé n'est ni lu ni brouillon
        // tant que son propriétaire ne l'a pas dit. Le poser « vu » d'office
        // ferait disparaître un import d'une liste de non-lus.
        let Some(uid) = depot.commit(ams_proto_imap::Flags::NONE, None) else {
            return notre_faute();
        };
        cree(render::write_uid_cree(uid, sortie))
    }

    /// Retrouve le rang d'un message d'après son UID.
    ///
    /// **L'API DÉSIGNE PAR UID, LE MAGASIN TRAVAILLE PAR RANG.** L'UID est
    /// durable — c'est ce qu'un client retient d'une session à l'autre —, le
    /// rang ne vaut que pour l'instant où on l'a lu. Les confondre ferait agir
    /// sur le voisin dès qu'un message disparaît.
    fn rang_de<B: ams_session::imap::Mailbox>(boite: &B, uid: u64) -> Option<u32> {
        let voulu = u32::try_from(uid).ok()?;
        (1..=boite.exists()).find(|rang| boite.info(*rang).map(|info| info.uid) == Some(voulu))
    }

    /// Le rang d'un UID, par dichotomie.
    ///
    /// **LES UID CROISSENT AVEC LE RANG** — c'est une garantie d'IMAP
    /// (§2.3.1.1 de RFC 9051), que l'instantané tient. [`Self::rang_de`]
    /// parcourt la boîte ; une copie de deux cent cinquante-six messages dans
    /// une boîte de cinquante mille ferait douze millions de lectures.
    fn rang_par_dichotomie<B: ams_session::imap::Mailbox>(boite: &B, uid: u32) -> Option<u32> {
        let (mut bas, mut haut) = (1_u32, boite.exists());
        while bas <= haut {
            let milieu = bas.saturating_add(haut.saturating_sub(bas) / 2);
            let lu = boite.info(milieu)?.uid;
            match lu.cmp(&uid) {
                core::cmp::Ordering::Equal => return Some(milieu),
                core::cmp::Ordering::Less => bas = milieu.saturating_add(1),
                core::cmp::Ordering::Greater => haut = milieu.checked_sub(1)?,
            }
        }
        None
    }

    /// Copie — ou déplace — des messages d'une boîte à une autre du même
    /// compte.
    ///
    /// # TOUT OU RIEN, COMME `COPY` ET `MOVE` D'IMAP
    ///
    /// Les copies se font d'abord, toutes ; si l'une échoue, celles qui ont
    /// réussi sont DÉFAITES et rien n'a eu lieu. Un déplacement ne retire les
    /// originaux qu'ensuite, du rang le plus haut au plus bas — retirer le
    /// premier décalerait tous les rangs suivants. Un message que la source n'a
    /// plus n'est pas une faute : il est rendu dans `missing`.
    ///
    /// # LA DESTINATION EST DU MÊME COMPTE, ET PAS DE `Partagés`
    ///
    /// L'API nomme la boîte d'autrui par son chemin, sous le contrôle de la
    /// table ; une destination `Partagés/…` dans le corps rouvrirait l'espace
    /// d'IMAP que l'API ne voit pas. Elle rend `404`, comme une destination
    /// qui n'existe pas.
    fn transferer<'o>(
        &self,
        compte: &str,
        nom: &str,
        corps: &[u8],
        deplacer: bool,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let mut place = [0_u8; ams_session::imap::MAILBOX_NAME_MAX];
        let Ok(demande) = render::read_transfer_request(corps, &mut place) else {
            return corps_refuse(sortie);
        };
        let meme = demande.to == nom
            || (demande.to.eq_ignore_ascii_case("INBOX") && nom.eq_ignore_ascii_case("INBOX"));
        // Déplacer une boîte vers elle-même ne ferait que renuméroter.
        if deplacer && meme {
            return corps_refuse(sortie);
        }
        if ams_proto_imap::shared_name(demande.to.as_bytes()).is_some() {
            return absente(sortie);
        }
        let Some(destination) = self.boites.open(compte.as_bytes(), demande.to.as_bytes()) else {
            return absente(sortie);
        };
        let validite = destination.uid_validity();
        drop(destination);
        let Some(mut boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };

        let mut faits: Vec<(u32, u32, u32)> = Vec::with_capacity(demande.uids().len());
        let mut absents: Vec<u32> = Vec::new();
        for uid in demande.uids() {
            let Some(rang) = Self::rang_par_dichotomie(&boite, *uid) else {
                absents.push(*uid);
                continue;
            };
            let Some(neuf) = boite.copy_to(rang, demande.to.as_bytes()) else {
                // **ON DÉFAIT CE QU'ON A FAIT** : les UID attribués sont
                // strictement croissants, et forment donc une seule plage.
                if let (Some(premier), Some(dernier)) = (
                    faits.iter().map(|(_, _, neuf)| *neuf).min(),
                    faits.iter().map(|(_, _, neuf)| *neuf).max(),
                ) {
                    boite.undo_copies(demande.to.as_bytes(), premier, dernier);
                }
                return notre_faute();
            };
            faits.push((*uid, rang, neuf));
        }
        if deplacer {
            let mut rangs: Vec<u32> = faits.iter().map(|(_, rang, _)| *rang).collect();
            rangs.sort_unstable_by(|a, b| b.cmp(a));
            for rang in rangs {
                // Un original qui a disparu entre-temps n'est plus à retirer :
                // la copie, elle, est faite, et c'est ce qu'on rend.
                let _ = boite.remove(rang);
            }
        }
        let paires: Vec<(u32, u32)> = faits.iter().map(|(uid, _, neuf)| (*uid, *neuf)).collect();
        rendre(render::write_transfer(validite, &paires, &absents, sortie))
    }

    /// Pose et ôte des drapeaux sur un message.
    fn drapeaux<'o>(
        &self,
        compte: &str,
        nom: &str,
        uid: u64,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        // **LE CORPS SE LIT AVANT D'OUVRIR QUOI QUE CE SOIT** : un corps refusé
        // ne doit pas laisser deviner si la boîte existe.
        let Ok(demande) = render::read_flag_patch(corps) else {
            return corps_refuse(sortie);
        };
        let Some(mut boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };
        let Some(rang) = Self::rang_de(&boite, uid) else {
            return absente(sortie);
        };
        // **AJOUTER PUIS RETIRER**, et l'ordre compte : `read_flag_patch` refuse
        // déjà qu'un même drapeau figure des deux côtés, mais si cela changeait,
        // le retrait doit l'emporter — c'est le sens le moins surprenant.
        if demande.add != ams_proto_imap::Flags::NONE
            && boite
                .store_flags(rang, ams_proto_imap::StoreMode::Add, demande.add)
                .is_none()
        {
            return notre_faute();
        }
        if demande.remove != ams_proto_imap::Flags::NONE
            && boite
                .store_flags(rang, ams_proto_imap::StoreMode::Remove, demande.remove)
                .is_none()
        {
            return notre_faute();
        }
        // **ON REND LE MESSAGE TEL QU'IL EST DEVENU.** Un `204` obligerait le
        // client à relire pour savoir ce qu'il a obtenu, et deux clients qui
        // modifient le même message verraient chacun ce qu'il a demandé plutôt
        // que ce qui est.
        let Some(info) = boite.info(rang) else {
            return notre_faute();
        };
        rendre_le_message(&boite, rang, info, sortie)
    }

    /// Efface un message, pour de bon.
    fn effacer_le_message<'o>(
        &self,
        compte: &str,
        nom: &str,
        uid: u64,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let Some(mut boite) = self.boites.open(compte.as_bytes(), nom.as_bytes()) else {
            return absente(sortie);
        };
        let Some(rang) = Self::rang_de(&boite, uid) else {
            return absente(sortie);
        };
        // ── MARQUER, PUIS EFFACER : LES DEUX GESTES D'IMAP, EN UN SEUL VERBE ─
        //
        // `expunge` REFUSE d'effacer un message qui ne porte pas `\Deleted` sur
        // le disque, et cette garde n'est pas une formalité : la session
        // demande d'effacer ce que SON instantané croyait marqué, pris
        // peut-être des heures plus tôt. Effacer sur cette croyance-là, c'est
        // perdre du courrier que personne n'a demandé de perdre.
        //
        // Un `DELETE` REST est un geste unique pour le client ; il en vaut
        // deux ici, et c'est à nous de les composer plutôt que de contourner la
        // garde.
        if boite
            .store_flags(
                rang,
                ams_proto_imap::StoreMode::Add,
                ams_proto_imap::Flags::DELETED,
            )
            .is_none()
        {
            return notre_faute();
        }
        if !boite.expunge(rang) {
            return notre_faute();
        }
        sans_contenu()
    }

    /// Crée une boîte.
    fn creer_la_boite<'o>(&self, compte: &str, nom: &str, sortie: &'o mut [u8]) -> Served<'o> {
        use ams_session::imap::Creation;

        match self.boites.create(
            compte.as_bytes(),
            nom.as_bytes(),
            ams_proto_imap::SpecialUse::NONE,
        ) {
            // **`PUT` EST IDEMPOTENT** (§9.3.4 de RFC 9110) : une boîte qui
            // existait déjà n'est pas une faute, c'est l'état demandé.
            Creation::Faite | Creation::DejaLa => sans_contenu(),
            Creation::Refusee => notre_faute(),
            _ => corps_refuse(sortie),
        }
    }

    /// Efface une boîte et ce qu'elle contient.
    fn effacer_la_boite<'o>(&self, compte: &str, nom: &str, sortie: &'o mut [u8]) -> Served<'o> {
        use ams_session::imap::Deletion;

        match self.boites.delete(compte.as_bytes(), nom.as_bytes()) {
            // **`Videe` N'EST PAS UN ÉCHEC** : la boîte avait des filles, son
            // courrier est parti et son nom demeure pour les porter. C'est ce
            // que §6.3.5 de RFC 9051 prescrit, et le client n'a rien à y faire.
            Deletion::Faite | Deletion::Videe => sans_contenu(),
            Deletion::Absente => absente(sortie),
            Deletion::Refusee => notre_faute(),
        }
    }

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
        rendre_le_message(&boite, sequence, info, sortie)
    }
}

impl Api for ApiMaildir {
    fn serve<'o>(
        &self,
        resource: Resource<'_>,
        method: Method,
        account: &str,
        appel: ams_loop_tokio::http::Appel<'_>,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let ams_loop_tokio::http::Appel {
            body,
            query,
            range: portee,
            content_range,
            idempotency_key,
            owner,
            nonce,
            source,
        } = appel;
        // **UNE BOÎTE D'AUTRUI : LA TABLE DÉCIDE, À CHAQUE REQUÊTE.** Le jeton dit
        // QUI appelle ; le chemin dit la boîte de QUI ; la table dit si le
        // premier peut toucher à la seconde, et pour quoi faire. Sans le droit,
        // la réponse est celle d'une boîte qui n'existe pas : un `403`
        // apprendrait que le compte existe, et laisserait les énumérer.
        let acteur = account;
        let account = match owner {
            None => account,
            Some(titulaire) if titulaire == account => account,
            Some(titulaire) => {
                let requis = droit_requis(resource, method);
                let permis = self
                    .delegations
                    .as_ref()
                    .and_then(|table| table.droits(acteur, titulaire))
                    .is_some_and(|droits| droits.contains(requis));
                if !permis {
                    return absente(sortie);
                }
                // **CHAQUE ÉCRITURE DIT QUI L'A FAITE.** Trois personnes qui se
                // partagent support@ ne doivent pas former un seul coupable
                // anonyme.
                if requis == ams_config::Rights::WRITE {
                    eprintln!(
                        "air-mail-server : délégation — `{acteur}` écrit dans la boîte de \
                         `{titulaire}` : {method:?} {resource:?}"
                    );
                }
                titulaire
            }
        };
        // **L'ESPACE `Partagés` EST CELUI D'IMAP, PAS DE L'API.** L'API nomme la
        // boîte d'autrui par `/v1/accounts/{compte}/mailboxes/…`, sous le
        // contrôle et le journal ci-dessus ; la laisser aussi atteindre
        // `Partagés/support/INBOX` par les routes personnelles ferait deux
        // chemins pour une boîte, dont un qu'on n'éprouve pas.
        if boite_de(&resource)
            .is_some_and(|boite| ams_proto_imap::shared_name(boite.as_bytes()).is_some())
        {
            return absente(sortie);
        }
        // **UNE CLÉ D'IDEMPOTENCE SE PRÉSENTE AVANT D'AGIR** : rejouée, elle
        // rend la première réponse sans rien refaire — c'est tout son objet.
        // Seules les requêtes qui ÉCRIVENT un message la regardent.
        let ecrit_un_message = matches!(method, Method::Post)
            && matches!(
                resource,
                Resource::Submissions
                    | Resource::DraftSend { .. }
                    | Resource::DraftStore { .. }
                    | Resource::Messages { .. }
            );
        let mut retenir = None;
        if let (true, Some(champ), Some(registre)) =
            (ecrit_un_message, idempotency_key, self.idempotence.as_ref())
        {
            let Some(cle) = crate::idempotence::cle_du_champ(champ) else {
                return probleme(
                    ams_api::Reason::BadIdempotencyKey,
                    ams_api::Reason::BadIdempotencyKey.status(),
                    sortie,
                );
            };
            let empreinte =
                crate::idempotence::empreinte(&format!("{method:?} {resource:?}"), body);
            match registre.commencer(acteur, cle, &empreinte, crate::maintenant()) {
                Ok(crate::idempotence::Debut::Neuve) => retenir = Some((registre, cle, empreinte)),
                Ok(crate::idempotence::Debut::Rejouer {
                    status,
                    media,
                    corps,
                }) => return rejouer(status, &media, &corps, sortie),
                Ok(crate::idempotence::Debut::AutreRequete) => {
                    return probleme(
                        ams_api::Reason::IdempotencyKeyReused,
                        ams_api::Reason::IdempotencyKeyReused.status(),
                        sortie,
                    );
                }
                Ok(crate::idempotence::Debut::EnCours) => {
                    return probleme(
                        ams_api::Reason::IdempotencyInFlight,
                        ams_api::Reason::IdempotencyInFlight.status(),
                        sortie,
                    );
                }
                Err(_) => return indisponible(sortie),
            }
        }
        let servi = match resource {
            Resource::Health => rendre(render::write_health(sortie)),
            Resource::Metrics => rendre(render::write_metrics(
                &[
                    ("mailboxes", self.compte_des_boites(account)),
                    // **CE QU'UN COMPTE TIENT OUVERT SE VOIT.** Un plafond qu'on
                    // ne peut pas observer est un plafond dont on n'apprend
                    // l'existence qu'en le heurtant.
                    (
                        "sessions",
                        u64::try_from(self.sessions.combien(account, microsecondes()))
                            .unwrap_or(u64::MAX),
                    ),
                    // **CE QUE LE RÉVEIL A FAIT POUR SES APPAREILS** : décidé,
                    // transmis, échoué. Sans transport, les premiers seuls
                    // bougent.
                    ("wakeupsPrepared", self.bilan_du_reveil(account).prepares),
                    ("wakeupsSent", self.bilan_du_reveil(account).transmis),
                    ("wakeupsFailed", self.bilan_du_reveil(account).echoues),
                    // **CE QUE LE DÉBIT A REFUSÉ SE VOIT** (phase 6) : une
                    // application qui ralentit sans raison apparente a peut-être
                    // heurté son seau, et c'est ici qu'on le lit.
                    ("requestsThrottled", self.debits.refusees(account)),
                ],
                sortie,
            )),
            Resource::Mailboxes => self.mailboxes(account, sortie),
            // ── LE VERBE DÉCIDE, ET IL ÉTAIT IGNORÉ ─────────────────────────
            //
            // Ces quatre bras servaient la LECTURE quel que soit le verbe : un
            // `DELETE` de boîte rendait son état avec `200`, un `PATCH` de
            // drapeaux rendait le message inchangé. Le routage les déclarait,
            // le contrôle d'accès exigeait le droit d'écrire, et rien n'écrivait.
            //
            // **C'ÉTAIT PIRE QU'UN `501`** : le client croyait avoir écrit, et
            // aucune réponse ne le détrompait. Trouvé le 2026-09-23 en
            // documentant l'API — le code n'avait jamais menti à un essai,
            // faute d'essai qui le regarde.
            Resource::Mailbox { boite } if matches!(method, Method::Put) => {
                self.creer_la_boite(account, boite, sortie)
            }
            Resource::Mailbox { boite } if matches!(method, Method::Delete) => {
                self.effacer_la_boite(account, boite, sortie)
            }
            Resource::Mailbox { boite } => self.mailbox(account, boite, sortie),
            Resource::Messages { boite } if matches!(method, Method::Post) => {
                self.ajouter_un_message(account, boite, body, sortie)
            }
            Resource::Messages { boite } => self.messages(account, boite, query, sortie),
            Resource::Changes { boite } => self.changements(account, boite, query, sortie),
            Resource::Message { boite, uid } if matches!(method, Method::Patch) => {
                self.drapeaux(account, boite, uid, body, sortie)
            }
            Resource::Message { boite, uid } if matches!(method, Method::Delete) => {
                self.effacer_le_message(account, boite, uid, sortie)
            }
            Resource::Message { boite, uid } => self.message(account, boite, uid, sortie),
            Resource::MessageRaw { boite, uid } => {
                self.message_brut(account, boite, uid, portee, sortie)
            }
            Resource::MessagePart { boite, uid, partie } => {
                self.partie_de_message(account, boite, uid, partie, portee, sortie)
            }
            Resource::Search { boite } => self.search(account, boite, body, sortie),
            Resource::Copy { boite } => self.transferer(account, boite, body, false, sortie),
            Resource::Drafts => self.creer_un_brouillon(account, body, sortie),
            Resource::Draft { id } if matches!(method, Method::Delete) => {
                self.sur_un_brouillon(sortie, |brouillons, maintenant| {
                    brouillons.supprimer(account, id, maintenant).map(|()| None)
                })
            }
            Resource::Draft { id } => self.etat_du_brouillon(account, id, sortie),
            Resource::DraftAttachments { id } => self.declarer_une_piece(account, id, body, sortie),
            Resource::DraftAttachment { id, piece } if matches!(method, Method::Delete) => self
                .sur_un_brouillon(sortie, |brouillons, maintenant| {
                    brouillons
                        .retirer(account, id, piece, maintenant)
                        .map(|()| None)
                }),
            Resource::DraftAttachment { id, piece } => {
                self.poser_un_morceau(account, id, piece, content_range, body, sortie)
            }
            Resource::DraftSend { id } => self.envoyer_le_brouillon(account, id, sortie),
            Resource::DraftStore { id } => self.ranger_le_brouillon(account, id, body, sortie),
            Resource::Move { boite } => self.transferer(account, boite, body, true, sortie),
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
            Resource::OwnPassword => self.poser_mon_secret(account, body, sortie),
            Resource::Invitations => self.frapper_une_invitation(body, source, sortie),
            Resource::OwnDevices if matches!(method, Method::Post) => {
                self.appairer(account, body, source, sortie)
            }
            Resource::OwnDevices => self.mes_appareils(account, sortie),
            Resource::OwnDevice { id } => {
                self.revoquer_des_appareils(account, Some(id), "self", source, sortie)
            }
            // **LA VOIE DE SECOURS** (0.2.41) : l'administration voit et révoque
            // les appareils d'un compte — tous, pour pouvoir le réinviter.
            Resource::AccountDevices { compte } if matches!(method, Method::Delete) => {
                self.revoquer_des_appareils(compte, None, "admin", source, sortie)
            }
            Resource::AccountDevices { compte } => self.mes_appareils(compte, sortie),
            Resource::AccountDevice { compte, id } => {
                self.revoquer_des_appareils(compte, Some(id), "admin", source, sortie)
            }
            // **L'APPAREIL DE QUI APPELLE, PAR SA SESSION** — `acteur`, et non
            // un titulaire : un abonnement n'est jamais celui d'un autre.
            Resource::OwnPush if matches!(method, Method::Put) => {
                self.abonner(acteur, nonce, body, source, sortie)
            }
            Resource::OwnPush if matches!(method, Method::Delete) => {
                self.desabonner(acteur, nonce, source, sortie)
            }
            Resource::OwnPush => self.mon_abonnement(acteur, nonce, sortie),
            Resource::OwnAppPasswords if matches!(method, Method::Post) => {
                self.creer_un_applicatif(account, body, source, sortie)
            }
            Resource::OwnAppPasswords => self.mes_applicatifs(account, sortie),
            Resource::OwnAppPassword { id } => self.revoquer_un_applicatif(account, id, sortie),
            Resource::OwnDelegations => self.mes_delegations(account, sortie),
            // **SON PROPRE JOURNAL, PAR `acteur`** : celui du titulaire d'une
            // boîte déléguée n'est pas à qui l'atteint.
            Resource::OwnAudit => self.journal_d_audit(acteur, query.limit, sortie),
            Resource::AccountAudit { compte } => self.journal_d_audit(compte, query.limit, sortie),
            Resource::Delegates { compte } => self.delegues_de(compte, sortie),
            Resource::Delegate { compte, delegue } if matches!(method, Method::Delete) => {
                self.retirer_une_delegation(compte, delegue, sortie)
            }
            Resource::Delegate { compte, delegue } => {
                self.poser_une_delegation(compte, delegue, body, sortie)
            }
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
        };
        if servi.status.class() == 2 {
            self.noter_ce_que_le_chemin_dit(acteur, resource, method, source);
        }
        if let Some((registre, cle, empreinte)) = retenir {
            // **CE QUI ÉCHOUE DE NOTRE FAIT NE SE REJOUE PAS** : un `503` rejoué
            // interdirait au client de réessayer. La clé s'oublie, et le
            // prochain essai s'exécute.
            if servi.status.class() >= 5 {
                registre.abandonner(acteur, cle);
            } else if registre
                .finir(
                    acteur,
                    cle,
                    &empreinte,
                    servi.status.value(),
                    servi.media,
                    servi.body,
                )
                .is_err()
            {
                eprintln!(
                    "air-mail-server : idempotence — la réponse n'a pas pu être retenue ; un \
                     nouvel essai sous la même clé s'exécuterait de nouveau"
                );
            }
        }
        servi
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
        ouvre.then_some(PORTEE_DE_SESSION)
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
    fn open_session(
        &self,
        login: &str,
        nonce: u64,
        expiry: u64,
        maintenant: u64,
        device: Option<&str>,
        source: ams_guard::Source,
    ) {
        self.sessions
            .ouvrir(login, nonce, expiry, maintenant, device);
        self.noter(
            login,
            crate::audit::Evenement::SessionOuverte { appareil: device },
            Some(source),
        );
    }

    /// # UN COMPTE INCONNU NE S'ÉCRIT PAS, ET CELA NE SE VOIT PAS AU TEMPS
    ///
    /// La recherche du compte se fait dans la vue en mémoire, et l'écriture
    /// part dans la file du journal : ni l'une ni l'autre ne pèse à côté de
    /// l'Argon2id qui vient d'être payé — le même pour un compte inconnu.
    fn refused(&self, account: &str, door: ams_loop_tokio::http::Door, source: ams_guard::Source) {
        if self.audit.is_none()
            || !self
                .comptes
                .vue()
                .iter()
                .any(|connu| connu.login == account)
        {
            return;
        }
        let porte = match door {
            ams_loop_tokio::http::Door::Password => "password",
            ams_loop_tokio::http::Door::Device => "device",
        };
        self.noter(
            account,
            crate::audit::Evenement::Refus { porte },
            Some(source),
        );
    }

    /// # LA SESSION D'ABORD, LE DÉBIT ENSUITE
    ///
    /// Une session fermée ne prend pas de jeton : son seau n'a pas à payer ce
    /// que son jeton ne vaut plus. Et le seau est celui de l'APPAREIL qui a
    /// ouvert la session — ou celui du compte, pour un mot de passe.
    fn admit(&self, login: &str, nonce: u64, maintenant: u64) -> Admission {
        let Some(appareil) = self.sessions.vivante(login, nonce, maintenant) else {
            return Admission::Closed;
        };
        // **UN APPAREIL QUI N'EST PLUS AU MAGASIN N'A PLUS DE SESSION** (0.2.41).
        // L'API ferme les sessions de ce qu'elle révoque ; mais le magasin se
        // modifie aussi hors d'elle — `air-mail-admin device revoke`, qui
        // l'écrit directement. Sans ce contrôle, ses jetons vaudraient encore
        // jusqu'à leur quart d'heure.
        if let (Some(id), Some(magasin)) = (appareil.as_deref(), self.appareils.as_ref())
            && !magasin
                .vue()
                .iter()
                .any(|connu| connu.login == login && connu.id == id)
        {
            self.sessions.fermer_l_appareil(login, id);
            return Admission::Closed;
        }
        match self.debits.prendre(login, appareil.as_deref(), maintenant) {
            true => Admission::Open,
            false => Admission::Throttled,
        }
    }

    fn verify_device(
        &self,
        account: &str,
        device: &str,
        issued_at_ms: u64,
        challenge: &str,
        signature: &str,
    ) -> Option<Scope> {
        self.verifier_un_appareil(account, device, issued_at_ms, challenge, signature)
    }

    fn enrol<'o>(
        &self,
        account: &str,
        public_key: &str,
        name: &str,
        invitation: &str,
        attestation: Option<&str>,
        source: ams_guard::Source,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        self.enroler(
            account,
            public_key,
            name,
            invitation,
            attestation,
            source,
            sortie,
        )
    }

    fn close_session(&self, login: &str, nonce: u64) -> bool {
        self.sessions.fermer(login, nonce)
    }

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
            let Some(vue) = self.boites.name(compte.as_bytes(), rang, &mut place) else {
                break;
            };
            // L'espace `Partagés` n'est pas à lui : on ne le compte pas.
            if ams_proto_imap::shared_name(vue.name).is_none() {
                combien = combien.saturating_add(1);
            }
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

/// Un message, son enveloppe et sa structure — ou ce qui en tient.
///
/// # LE MESSAGE D'ABORD, LE RESTE S'IL TIENT
///
/// Un en-tête peut peser soixante-quatre kibioctets, et ses noms grandir au
/// décodage : l'enveloppe entière peut dépasser la réponse, et la structure
/// s'y ajoute. Rendre `500` pour cela priverait le client du message entier —
/// ses drapeaux, son sujet — pour une liste de destinataires trop longue. On
/// renonce donc dans l'ordre : l'enveloppe d'abord, qui est la plus grosse et
/// que le message brut redit, puis la structure. `null` dit au client ce qui
/// lui manque.
fn rendre_le_message<'o>(
    boite: &crate::imap::BoiteImap,
    sequence: u32,
    info: ams_session::imap::MessageInfo,
    sortie: &'o mut [u8],
) -> Served<'o> {
    let resume = resumer(boite, sequence, info);
    let ligne = ligne_de(&resume);
    let entete = boite.entete(sequence);
    let structure = boite.structure(sequence);
    let validite = boite.uid_validity();
    for (avec_entete, avec_structure) in [(true, true), (false, true)] {
        let tente = render::write_message(
            &ligne,
            entete.as_deref().filter(|_| avec_entete),
            structure.as_deref().filter(|_| avec_structure),
            validite,
            sortie,
        )
        .map(<[u8]>::len);
        if let Ok(ecrits) = tente {
            return rendre(Ok(sortie.get(..ecrits).unwrap_or_default()));
        }
    }
    rendre(render::write_message(&ligne, None, None, validite, sortie))
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
/// Ce qui a créé une ressource (§15.3.2 de RFC 9110).
fn cree(ecrit: Result<&[u8], ams_api::Error>) -> Served<'_> {
    match ecrit {
        Ok(corps) => Served {
            status: StatusCode::CREATED,
            media: ams_api::JSON_MEDIA_TYPE,
            body: corps,
            ..Served::default()
        },
        Err(_) => notre_faute(),
    }
}

/// L'heure en MICROSECONDES depuis l'époque.
///
/// **L'UNITÉ N'EST PAS CELLE DE `crate::maintenant`**, qui rend des secondes :
/// les jetons et les sessions comptent en microsecondes, et confondre les deux
/// ferait expirer une session un million de fois trop tôt — ou jamais.
fn microsecondes() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |depuis| {
            u64::try_from(depuis.as_micros()).unwrap_or(u64::MAX)
        })
}

/// L'heure, en millisecondes depuis l'époque — l'unité du défi et de la date
/// de dernière session d'un appareil.
/// L'instant, en secondes depuis l'époque, signé — ce que compare une date de
/// certificat.
fn maintenant_i64() -> i64 {
    i64::try_from(crate::maintenant()).unwrap_or(i64::MAX)
}

fn millisecondes() -> u64 {
    microsecondes() / 1_000
}

/// Pourquoi un défi signé n'a pas été consommé.
///
/// **LA PREUVE ET CE QU'ELLE AUTORISE ÉCHOUENT POUR DES RAISONS DIFFÉRENTES**, et
/// le client doit les lire différemment : un `401` lui dit de redemander un
/// défi, un `409` que sa demande n'a pas de sens.
enum Refus {
    /// Appareil introuvable, ou défi déjà consommé.
    Preuve,
    /// La clef à enrôler l'est déjà sur ce compte.
    Doublon,
    /// Le compte a atteint [`APPAREILS_PAR_COMPTE`].
    Plein,
    /// Le magasin n'a pas voulu écrire.
    Magasin(crate::appareils::Faute),
}

/// Le droit qu'une requête exige sur une boîte d'autrui.
///
/// **LA LECTURE POUR CE QUI NE MODIFIE RIEN** — `GET`, `HEAD`, et la recherche,
/// qui passe par un `POST` sans rien écrire —, l'écriture pour le reste : poser
/// des drapeaux, ranger, supprimer, créer ou effacer une boîte.
fn droit_requis(resource: Resource<'_>, method: Method) -> ams_config::Rights {
    if matches!(method, Method::Get | Method::Head) || matches!(resource, Resource::Search { .. }) {
        ams_config::Rights::READ
    } else {
        ams_config::Rights::WRITE
    }
}

/// Ce qu'une session ouverte par cette API accorde.
///
/// **LA MÊME POUR UN MOT DE PASSE ET POUR UNE CLEF D'APPAREIL**, et écrite UNE
/// fois : deux endroits qui accorderaient « la même chose » finiraient par ne
/// plus accorder la même, et l'un des deux ouvrirait ce que l'autre ferme.
///
/// **ELLE N'OUVRE JAMAIS L'ADMINISTRATION.** Ni un mot de passe ni un téléphone
/// ne valent l'autorité de l'exploitant : celle-ci se frappe depuis la machine,
/// par qui lit le secret de scellement. C'est ce qui fait qu'un compte compromis
/// ne devient jamais le serveur entier.
const PORTEE_DE_SESSION: Scope = Scope::one(ams_api::Area::Mail, ams_api::Rights::Write)
    .with(ams_api::Area::Submit, ams_api::Rights::Write)
    .with(ams_api::Area::Observe, ams_api::Rights::Read);

/// Combien d'appareils un compte peut enrôler.
///
/// **UN PLAFOND EXISTE PARCE QUE L'APPAIRAGE S'AUTO-ALIMENTE** : un appareil
/// enrôlé peut en approuver un autre, qui peut en approuver un autre. Sans
/// borne, une clef compromise en sèmerait autant qu'elle veut, et la liste que
/// son propriétaire doit lire pour s'en apercevoir deviendrait illisible.
///
/// Douze. Un téléphone, une tablette, deux postes, et de la marge pour les
/// remplacer sans révoquer d'abord.
const APPAREILS_PAR_COMPTE: usize = 12;

/// Combien de temps une invitation vaut, quand personne ne le dit.
///
/// Vingt-quatre heures. **ASSEZ POUR QU'UN COURRIEL SOIT LU LE LENDEMAIN**, et
/// moitié moins que le plafond du format : l'exploitant qui veut davantage le
/// demande, celui qui ne se pose pas la question obtient une durée qu'il n'aura
/// pas à regretter.
const INVITATION_MINUTES: u64 = 24 * 60;

/// Ce que ces octets s'écrivent en hexadécimal minuscule.
///
/// **LA CASSE EST FIXÉE**, et ce n'est pas cosmétique : cet hexadécimal devient
/// un identifiant d'appareil, donc un segment d'URL que l'on compare. Deux
/// écritures du même condensat en feraient deux appareils.
fn en_hexadecimal(octets: &[u8]) -> String {
    use core::fmt::Write as _;

    let mut texte = String::with_capacity(octets.len().saturating_mul(2));
    for octet in octets {
        // L'écriture dans une `String` ne peut pas échouer ; l'ignorer
        // explicitement vaut mieux qu'un `unwrap` que personne ne relit.
        let _ = write!(texte, "{octet:02x}");
    }
    texte
}

/// Ce qu'on répond à une clef publique qu'on ne sait pas lire.
///
/// **QUI LA REÇOIT EST AUTORISÉ** : il a présenté une invitation que notre clé a
/// scellée. Lui répondre « aucune ressource ici » l'enverrait chercher un défaut
/// de chemin ; ce qu'il doit corriger est son corps.
fn corps_de_l_enrolement_refuse(sortie: &mut [u8]) -> Served<'_> {
    match ams_api::problem(ams_api::Reason::BadJsonBody, sortie) {
        Ok(corps) => Served {
            status: StatusCode::BAD_REQUEST,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: corps,
            // **CELLE-CI COMPTE CONTRE LE PAIR** : cette porte s'ouvre sans
            // jeton, et sans cela elle offrirait des essais illimités.
            peer_fault: true,
            ..Served::default()
        },
        Err(_) => notre_faute(),
    }
}

/// Ce qu'on répond à un appairage que rien n'autorise.
///
/// **LE MÊME REFUS POUR TOUTES LES CAUSES** : défi forgé, expiré, appareil
/// approbateur inconnu, signature fausse, rejeu, ou défi émis pour un autre
/// compte. Les distinguer dirait à qui essaie jusqu'où il est allé.
///
/// **ET CELLE-CI COMPTE CONTRE LE PAIR** : elle s'atteint avec un jeton valide,
/// mais approuver un appairage demande davantage — sans cela, un jeton volé
/// offrirait des essais illimités sur des signatures forgées.
fn refus_d_appairage(sortie: &mut [u8]) -> Served<'_> {
    match ams_api::problem(ams_api::Reason::BadToken, sortie) {
        Ok(corps) => Served {
            status: StatusCode::UNAUTHORIZED,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: corps,
            peer_fault: true,
            ..Served::default()
        },
        Err(_) => notre_faute(),
    }
}

/// Ce qu'on répond quand le compte a atteint son plafond d'appareils.
///
/// **CE N'EST PAS UNE FAUTE DU PAIR** : la demande est légitime, le compte est
/// simplement plein. Ce qu'il doit faire est précis — révoquer un appareil qu'il
/// n'emploie plus —, et la liste qu'il lit pour choisir porte la date de
/// dernière session de chacun.
fn trop_d_appareils(sortie: &mut [u8]) -> Served<'_> {
    match ams_api::problem(ams_api::Reason::AlreadyEnrolled, sortie) {
        Ok(corps) => Served {
            status: ams_api::Reason::AlreadyEnrolled.status(),
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: corps,
            ..Served::default()
        },
        Err(_) => notre_faute(),
    }
}

/// Ce qu'on répond quand le compte a déjà un appareil.
///
/// §15.5.10 de RFC 9110 : « the request could not be completed due to a conflict
/// with the current state of the target resource ». C'est exactement cela, et le
/// dire précisément est ce qui permet à l'application d'afficher la seule chose
/// utile — « demandez à votre exploitant de révoquer l'ancien ».
///
/// **CE N'EST PAS UNE FAUTE DU PAIR** : présenter une invitation légitime dont
/// l'heure est passée par les faits n'est pas un essai d'intrusion.
fn deja_enrole(sortie: &mut [u8]) -> Served<'_> {
    match ams_api::problem(ams_api::Reason::AlreadyEnrolled, sortie) {
        Ok(corps) => Served {
            status: ams_api::Reason::AlreadyEnrolled.status(),
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: corps,
            ..Served::default()
        },
        Err(_) => notre_faute(),
    }
}

/// Un corps qu'on refuse de lire.
///
/// **LA MÊME RÉPONSE QU'UN MESSAGE ILLISIBLE** : dire lequel des deux a cloché
/// apprendrait à qui sonde ce que le serveur a reconnu.
/// Ce qui écoule un message, morceau par morceau, dans l'écrivain qu'on lui
/// donne — et rend `false` si l'un des deux a lâché.
type Composeur<'a> = dyn FnMut(&mut dyn FnMut(&[u8]) -> bool) -> bool + 'a;

/// Rend une réponse retenue, telle quelle.
fn rejouer<'o>(status: u16, media: &str, corps: &[u8], sortie: &'o mut [u8]) -> Served<'o> {
    let Ok(status) = StatusCode::new(status) else {
        return notre_faute();
    };
    let Some(place) = sortie.get_mut(..corps.len()) else {
        return notre_faute();
    };
    place.copy_from_slice(corps);
    // Le type revient à sa constante : `Served` n'en porte que de statiques.
    let media = [
        ams_api::JSON_MEDIA_TYPE,
        ams_api::PROBLEM_MEDIA_TYPE,
        ams_api::MESSAGE_MEDIA_TYPE,
    ]
    .into_iter()
    .find(|connu| *connu == media)
    .unwrap_or(ams_api::JSON_MEDIA_TYPE);
    Served {
        status,
        media,
        body: sortie.get(..corps.len()).unwrap_or_default(),
        ..Served::default()
    }
}

/// Ce qu'une faute de brouillon rend.
fn faute_de_brouillon(faute: crate::brouillons::Faute, sortie: &mut [u8]) -> Served<'_> {
    use crate::brouillons::Faute;
    match faute {
        Faute::Introuvable => absente(sortie),
        Faute::Refus => corps_refuse(sortie),
        Faute::TropGros => probleme(
            ams_api::Reason::BodyTooLarge,
            ams_api::Reason::BodyTooLarge.status(),
            sortie,
        ),
        Faute::Conflit => probleme(
            ams_api::Reason::DraftConflict,
            ams_api::Reason::DraftConflict.status(),
            sortie,
        ),
        Faute::Disque => indisponible(sortie),
    }
}

/// Une pièce, telle que le JSON la rend.
fn ligne_de_piece(piece: &crate::brouillons::Piece) -> render::AttachmentRow<'_> {
    render::AttachmentRow {
        piece: piece.numero,
        name: &piece.nom,
        media: &piece.media,
        size: piece.taille,
        received: &piece.recu,
    }
}

/// Seize octets tirés du noyau : l'identifiant d'un brouillon.
fn seize_octets() -> Option<[u8; 16]> {
    use std::io::Read as _;
    let mut octets = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut octets))
        .ok()?;
    Some(octets)
}

fn corps_refuse(sortie: &mut [u8]) -> Served<'_> {
    match ams_api::problem(ams_api::Reason::BadJsonBody, sortie) {
        Ok(corps) => Served {
            status: StatusCode::BAD_REQUEST,
            media: ams_api::PROBLEM_MEDIA_TYPE,
            body: corps,
            ..Served::default()
        },
        Err(_) => notre_faute(),
    }
}

/// Ce qui a réussi et n'a rien à rendre (§15.3.5 de RFC 9110).
const fn sans_contenu<'o>() -> Served<'o> {
    Served {
        status: StatusCode::NO_CONTENT,
        media: ams_api::PROBLEM_MEDIA_TYPE,
        disposition: None,
        body: &[],
        ranges: false,
        range: None,
        peer_fault: false,
    }
}

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

/// Le nom de boîte que la ressource désigne, s'il y en a un.
fn boite_de<'r>(resource: &Resource<'r>) -> Option<&'r str> {
    match *resource {
        Resource::Mailbox { boite }
        | Resource::Messages { boite }
        | Resource::Message { boite, .. }
        | Resource::MessageRaw { boite, .. }
        | Resource::MessagePart { boite, .. }
        | Resource::Changes { boite }
        | Resource::Search { boite } => Some(boite),
        _ => None,
    }
}

/// Le `From:` du message appartient-il à ce compte ?
fn ecrit_bien_en_son_nom<'m>(
    comptes: &[Account],
    compte: &str,
    peut_envoyer_pour: impl Fn(&str) -> bool,
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
        .is_some_and(|vu| vu.login == compte || peut_envoyer_pour(&vu.login))
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
/// Une adresse, telle que le journal d'audit l'écrit.
///
/// **UNE ADRESSE IPv4 MAPPÉE S'ÉCRIT EN IPv4** : `::ffff:192.0.2.1` et
/// `192.0.2.1` sont le même pair, et un exploitant qui cherche l'une ne doit
/// pas manquer l'autre.
pub(crate) fn texte_de_source(source: ams_guard::Source) -> String {
    match source {
        ams_guard::Source::V4(octets) => std::net::Ipv4Addr::from(octets).to_string(),
        ams_guard::Source::V6(octets) => {
            let adresse = std::net::Ipv6Addr::from(octets);
            adresse
                .to_ipv4_mapped()
                .map_or_else(|| adresse.to_string(), |v4| v4.to_string())
        }
    }
}

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

/// La place qu'une partie servie réserve à ses deux champs d'en-tête.
const TETE_DE_PARTIE: usize = render::PART_MEDIA_MAX + render::PART_DISPOSITION_MAX;

/// Sert le contenu DÉCODÉ d'une partie, sous son type et sa disposition.
///
/// # CE QUE LE CLIENT DEMANDE, C'EST LE FICHIER
///
/// `BODY[1]` d'IMAP rend les octets du message ; une application veut le PDF.
/// On défait donc le `Content-Transfer-Encoding` — base64, quoted-printable —,
/// et la portée de §14 de RFC 9110 se compte sur le contenu décodé : c'est le
/// seul rang que le client connaît. Un encodage qu'on ne sait pas défaire rend
/// `422` plutôt que des octets encodés qu'on ferait passer pour le contenu.
///
/// # LE TYPE ET LE NOM VIENNENT DU MESSAGE, ET ILS SONT FILTRÉS
///
/// Voir [`render::write_part_media`] et [`render::write_part_disposition`]. Le
/// type et le nom s'écrivent en tête du tampon, le corps derrière : les trois
/// vivent aussi longtemps que la réponse.
fn servir_decodee<'o>(
    boite: &crate::imap::BoiteImap,
    sequence: u32,
    entete: &ams_mime::PartHeader<'_>,
    partie: &ams_mime::BodyPart<'_>,
    portee: Option<&[u8]>,
    sortie: &'o mut [u8],
) -> Served<'o> {
    if sortie.len() <= TETE_DE_PARTIE {
        return probleme(
            ams_api::Reason::BufferTooSmall,
            StatusCode::INTERNAL_SERVER_ERROR,
            sortie,
        );
    }
    let (tete, corps) = sortie.split_at_mut(TETE_DE_PARTIE);
    let (place_du_type, place_du_nom) = tete.split_at_mut(render::PART_MEDIA_MAX);
    let media = render::write_part_media(entete, place_du_type);
    let disposition = render::write_part_disposition(entete, place_du_nom);
    let fenetre = corps.len().min(FENETRE_MAX);
    let decoder =
        |debut: u64, combien: usize| boite.partie_decodee(sequence, partie, debut, combien);

    // SANS PORTÉE, on recueille une fenêtre et un octet de plus : la taille dit
    // si tout tient, sans seconde passe.
    let demandee = match portee {
        None => None,
        Some(valeur) => match decoder(0, 0) {
            Err(faute) => return refus_de_decodage(faute, corps),
            Ok((_, total)) => Some((ams_proto_http::parse_range(valeur, total), total)),
        },
    };
    let (debut, combien, partiel) = match demandee {
        // §15.5.17 : ce qui commence au-delà ne peut pas être satisfait.
        Some((Err(ams_proto_http::RangeFault::Unsatisfiable), total)) => {
            return hors_bornes(total, corps);
        }
        Some((Ok(voulue), _)) => {
            let combien = usize::try_from(voulue.octets())
                .unwrap_or(usize::MAX)
                .min(fenetre);
            (voulue.first, combien, true)
        }
        // §14.2 : un champ qu'on ne comprend pas s'ignore.
        Some((Err(ams_proto_http::RangeFault::Ignored), _)) | None => {
            (0, fenetre.saturating_add(1), false)
        }
    };
    let (octets, total) = match decoder(debut, combien) {
        Ok(lu) => lu,
        Err(faute) => return refus_de_decodage(faute, corps),
    };
    if !partiel && octets.len() > fenetre {
        return trop_grand(corps);
    }
    let place = corps.get_mut(..octets.len()).unwrap_or_default();
    place.copy_from_slice(&octets);
    let rendu = corps.get(..octets.len()).unwrap_or_default();
    let dernier = debut
        .saturating_add(u64::try_from(octets.len()).unwrap_or(0))
        .saturating_sub(1);
    Served {
        status: match partiel {
            true => StatusCode::PARTIAL_CONTENT,
            false => StatusCode::OK,
        },
        media,
        disposition: Some(disposition),
        body: rendu,
        ranges: true,
        range: partiel.then_some(ams_loop_tokio::http::ContentRange {
            part: Some((debut, dernier)),
            complete: total,
        }),
        peer_fault: false,
    }
}

/// Une partie qui ne se décode pas : absente, ou d'un encodage inconnu.
fn refus_de_decodage(faute: crate::imap::Decodage, sortie: &mut [u8]) -> Served<'_> {
    match faute {
        crate::imap::Decodage::Absente => absente(sortie),
        crate::imap::Decodage::EncodageInconnu => probleme(
            ams_api::Reason::UnknownEncoding,
            StatusCode::UNPROCESSABLE_CONTENT,
            sortie,
        ),
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
        crate::comptes::Faute::Introuvable(_) => absente(sortie),
        crate::comptes::Faute::Refuse(_) => refus_de_compte(sortie),
    }
}

/// Un corps qu'on ne sait pas lire.
/// **UN MOT DE PASSE VIDE N'EN EST PAS UN.**
///
/// # L'OUTIL LE REFUSAIT, L'API L'ACCEPTAIT — DANS CE SENS-LÀ
///
/// `air-mail-admin` refuse depuis toujours un secret vide sur l'entrée standard.
/// Les trois routes qui posent un secret, elles, le hachaient sans rien dire :
/// le compte s'ouvrait ensuite avec `""`, et rien dans le magasin ne distinguait
/// ce compte-là des autres.
///
/// Le laxisme était donc du côté que des PROGRAMMES appellent, et la rigueur du
/// côté qu'un humain tape. C'est l'inverse de ce qu'il faut : une faute de
/// frappe au terminal se voit, un champ vide dans un corps JSON ne se voit pas.
///
/// Il n'y a volontairement pas de longueur minimale ici. Refuser le vide écarte
/// l'accident ; poser un seuil serait une politique, et une politique se règle
/// (C8) plutôt qu'elle ne se grave.
///
/// # ET UN SECRET QUI A LA FORME D'UN MOT DE PASSE APPLICATIF EST REFUSÉ
///
/// La vérification choisit son chemin sur la forme : `amsp-…` ne s'essaie QUE
/// comme mot de passe applicatif. Un mot de passe principal de cette forme
/// n'ouvrirait donc jamais rien, et son propriétaire croirait l'avoir posé.
fn secret_recevable(secret: &str) -> bool {
    !secret.is_empty() && ams_auth::identifiant_applicatif(secret.as_bytes()).is_none()
}

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
        disposition: None,
        body: &[],
        // **ÉCRITS À LA MAIN, ET NON `..Default::default()`** : cette fonction
        // est `const`, et un `Default` ne l'est pas. C'est le seul endroit du
        // fichier où la liste se répète, et elle tient sur deux lignes.
        ranges: false,
        range: None,
        // **NOTRE FAUTE N'EST PAS CELLE DU PAIR** : bannir quelqu'un pour un
        // tampon que nous n'avons pas su écrire serait le punir de notre bogue.
        peer_fault: false,
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
    // **LE MOTIF DOIT PORTER LE MÊME CODE QUE LA RÉPONSE.** Il portait
    // `NoSuchResource`, dont le statut vaut 404, sous une ligne de statut à 501 :
    // le document disait donc `"status":404` quand le serveur disait 501, et
    // §3.1 de RFC 9457 demande que les deux coïncident. Le défaut était invisible
    // tant que ce bras n'était atteint par aucune route ; `/v1/me/devices` l'a
    // rendu visible en production.
    match ams_api::problem(ams_api::Reason::NotImplemented, sortie) {
        Ok(corps) => Served {
            status: ams_api::Reason::NotImplemented.status(),
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
        ecrit_bien_en_son_nom(&comptes(), compte, |_| false, &message).is_some()
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

    use super::{Account, ApiMaildir};
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
                None,
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

    /// **UN MESSAGE REMIS PAR L'API RÉVEILLE LES APPAREILS ABONNÉS** de son
    /// destinataire, et `/v1/metrics` le compte.
    #[tokio::test(flavor = "multi_thread")]
    async fn une_remise_reveille_et_se_compte() {
        use ams_api::Resource;
        use ams_loop_tokio::http::Api as _;
        use ams_proto_http::Method;
        use ams_proto_http::StatusCode;

        struct Temoin(std::sync::Mutex<std::vec::Vec<std::string::String>>);
        impl crate::reveil::Envoyeur for Temoin {
            fn envoyer<'a>(
                &'a self,
                appareil: &'a ams_config::Device,
                _: &'a ams_config::Push,
                compte: &'a str,
            ) -> crate::reveil::EnvoiEnCours<'a> {
                self.0
                    .lock()
                    .expect("verrou")
                    .push(std::format!("{}:{compte}", appareil.id));
                Box::pin(core::future::ready(crate::reveil::Envoi::Transmis))
            }
        }
        const CLE: [u8; 65] = [
            0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63,
            0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39,
            0x45, 0xD8, 0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E,
            0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E,
            0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
        ];
        let (ephemere, api, _) = api("reveil");
        let appareils = Arc::new(crate::appareils::Appareils::new(
            ephemere.0.join("appareils.bin"),
            std::vec![ams_config::Device {
                login: std::string::String::from("jean"),
                id: std::string::String::from("tel"),
                name: std::string::String::new(),
                public_key: ams_auth::Cle::lire(&CLE).expect("le point générateur"),
                enrolled: 1,
                last_seen: 0,
                attestation: None,
                push: Some(
                    ams_config::Push::new(
                        ams_config::PushChannel::Fcm,
                        std::string::String::from("jeton"),
                        std::vec::Vec::new(),
                        std::vec::Vec::new(),
                        1,
                    )
                    .expect("recevable"),
                ),
            }],
        ));
        let temoin = Arc::new(Temoin(std::sync::Mutex::default()));
        let reveil = crate::reveil::demarrer(crate::reveil::Sources {
            appareils,
            delegations: None,
            envoyeur: Arc::clone(&temoin) as Arc<dyn crate::reveil::Envoyeur>,
        });
        let api = api.avec_reveil(reveil);
        let lettre = b"From: jean@example.com\r\nTo: jean@example.com\r\n\r\nbonjour\r\n";
        let mut sortie = std::vec![0_u8; 4096];
        let rendu = api.submissions("jean", lettre, &mut sortie);
        assert_eq!(rendu.status, StatusCode::OK);
        let mut vus = std::vec::Vec::new();
        for _ in 0..500 {
            vus = temoin.0.lock().expect("verrou").clone();
            if !vus.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(vus, ["tel:jean"]);
        let mut place = std::vec![0_u8; 4096];
        let servi = api.serve(
            Resource::Metrics,
            Method::Get,
            "jean",
            ams_loop_tokio::http::Appel {
                body: b"",
                query: ams_api::Query::default(),
                range: None,
                content_range: None,
                idempotency_key: None,
                owner: None,
                nonce: 0,
                source: ams_guard::Source::V4([192, 0, 2, 1]),
            },
            &mut place,
        );
        let corps = std::string::String::from_utf8_lossy(servi.body).into_owned();
        assert!(corps.contains(r#""wakeupsPrepared":1"#), "{corps}");
        assert!(corps.contains(r#""wakeupsSent":1"#), "{corps}");
        assert!(corps.contains(r#""wakeupsFailed":0"#), "{corps}");
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

/// Les écritures sur le courrier, éprouvées par leur EFFET.
///
/// # POURQUOI CE BANC EXISTE
///
/// Le répartiteur servait la lecture quel que soit le verbe : un `DELETE` de
/// boîte rendait son état avec `200`, un `PATCH` de drapeaux rendait le message
/// inchangé. Aucun essai ne le voyait, parce qu'aucun essai ne regardait
/// l'EFFET d'une écriture — ils regardaient le code de retour, et il était bon.
///
/// **Chacun de ces essais relit le magasin après coup.** C'est la seule façon
/// de distinguer « a répondu 200 » de « a fait ce qu'on lui demandait », et
/// c'est précisément la distinction qui manquait.
#[cfg(test)]
mod ecritures {
    use super::{Api as _, ApiMaildir, BoitesImap, Resource};
    use ams_loop_tokio::http::Served;
    use ams_proto_http::{Method, StatusCode};
    use ams_session::imap::{Mailbox as _, Mailboxes as _};
    use std::string::String;
    use std::sync::Arc;

    /// Un répertoire qui s'efface quand l'essai finit.
    struct Ephemere(std::path::PathBuf);

    impl Ephemere {
        fn neuf() -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |depuis| depuis.as_nanos());
            let chemin = std::env::temp_dir().join(std::format!(
                "ams-api-ecritures-{unique}-{:?}",
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&chemin).expect("créable");
            Self(chemin)
        }
    }

    impl Drop for Ephemere {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Une API servant un seul compte, `marie`, avec sa boîte de réception.
    fn api(racine: &std::path::Path) -> (Arc<BoitesImap>, ApiMaildir) {
        let boite = ams_store::Maildir::open(
            racine.join("marie"),
            b"mail.exemple.test",
            ams_store::fresh_uid_validity(),
        )
        .expect("ouvrable");
        let mut carte = std::collections::BTreeMap::new();
        carte.insert(String::from("marie"), Arc::new(boite));
        let comptes = Arc::new(crate::comptes::Comptes::new(
            racine.join("comptes.bin"),
            std::vec![ams_auth::Account {
                login: String::from("marie"),
                hash: String::new(),
                addresses: std::vec![String::from("marie@exemple.test")],
            }],
        ));
        let remise = Arc::new(crate::delivery::Boites::new(
            carte,
            racine.to_path_buf(),
            b"mail.exemple.test".to_vec(),
            Arc::clone(&comptes),
        ));
        let boites = Arc::new(BoitesImap::new(
            Arc::clone(&remise),
            b"mail.exemple.test",
            None,
        ));
        let api = ApiMaildir::new(
            Arc::clone(&boites),
            comptes,
            remise,
            Arc::new(std::vec![String::from("exemple.test")]),
            Arc::new(ams_loop_tokio::SharedGuard::new(
                4,
                ams_guard::Thresholds::DEFAULT,
            )),
            Arc::new(crate::incidents::Incidents::new()),
        );
        (boites, api)
    }

    /// Sert une requête et rend son code et son corps.
    fn servir(
        api: &ApiMaildir,
        resource: Resource<'_>,
        method: Method,
        corps: &[u8],
    ) -> (StatusCode, String) {
        servir_avec(api, resource, method, corps, ams_api::Query::default())
    }

    /// Sert une ressource AVEC ces paramètres, et rend (statut, corps).
    fn servir_avec(
        api: &ApiMaildir,
        resource: Resource<'_>,
        method: Method,
        corps: &[u8],
        query: ams_api::Query,
    ) -> (StatusCode, String) {
        let mut place = std::vec![0_u8; 64 * 1024];
        let Served { status, body, .. } = api.serve(
            resource,
            method,
            "marie",
            ams_loop_tokio::http::Appel {
                body: corps,
                query,
                range: None,
                content_range: None,
                idempotency_key: None,
                owner: None,
                nonce: 0,
                source: ams_guard::Source::V4([192, 0, 2, 1]),
            },
            &mut place,
        );
        (status, String::from_utf8_lossy(body).into_owned())
    }

    /// Range un message dans `INBOX` et rend son UID.
    fn ranger(api: &ApiMaildir, sujet: &str) -> u64 {
        let message = std::format!(
            "From: marie@exemple.test\r\nTo: marie@exemple.test\r\n\
             Subject: {sujet}\r\n\r\nLe corps.\r\n"
        );
        let (status, corps) = servir(
            api,
            Resource::Messages { boite: "INBOX" },
            Method::Post,
            message.as_bytes(),
        );
        assert_eq!(status, StatusCode::CREATED, "{corps}");
        corps
            .trim_start_matches("{\"uid\":")
            .trim_end_matches('}')
            .parse()
            .expect("un UID")
    }

    /// Les drapeaux que porte ce message, relus DANS LE MAGASIN.
    fn drapeaux_du_magasin(boites: &BoitesImap, uid: u64) -> ams_proto_imap::Flags {
        let boite = boites.open(b"marie", b"INBOX").expect("ouvrable");
        let voulu = u32::try_from(uid).expect("tient");
        (1..=boite.exists())
            .filter_map(|rang| boite.info(rang))
            .find(|info| info.uid == voulu)
            .expect("le message est là")
            .flags
    }

    // ── L'AJOUT ────────────────────────────────────────────────────────────

    /// **UN MESSAGE RANGÉ EXISTE VRAIMENT**, et son UID est celui qu'on rend.
    #[test]
    fn un_message_range_se_retrouve_dans_la_boite() {
        let temporaire = Ephemere::neuf();
        let (boites, api) = api(&temporaire.0);
        let uid = ranger(&api, "bonjour");

        let boite = boites.open(b"marie", b"INBOX").expect("ouvrable");
        assert_eq!(boite.exists(), 1, "le message doit être dans la boîte");
        assert_eq!(u64::from(boite.info(1).expect("présent").uid), uid);
    }

    /// **CE QU'ON NE SAIT PAS RELIRE NE SE RANGE PAS.** Une boîte qui porterait
    /// un message illisible ne serait plus servie par IMAP.
    #[test]
    fn un_message_illisible_est_refuse() {
        let temporaire = Ephemere::neuf();
        let (boites, api) = api(&temporaire.0);
        let (status, _) = servir(
            &api,
            Resource::Messages { boite: "INBOX" },
            Method::Post,
            b"ceci n'est pas un message",
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let boite = boites.open(b"marie", b"INBOX").expect("ouvrable");
        assert_eq!(boite.exists(), 0, "rien ne doit avoir été rangé");
    }

    // ── LA DÉLÉGATION ──────────────────────────────────────────────────────

    /// Une API sur deux comptes : `marie`, et la boîte partagée `support`.
    fn api_partagee(
        racine: &std::path::Path,
    ) -> (ApiMaildir, Arc<crate::delegations::Delegations>) {
        let mut carte = std::collections::BTreeMap::new();
        for nom in ["marie", "support"] {
            let boite = ams_store::Maildir::open(
                racine.join(nom),
                b"mail.exemple.test",
                ams_store::fresh_uid_validity(),
            )
            .expect("ouvrable");
            carte.insert(String::from(nom), Arc::new(boite));
        }
        let comptes = Arc::new(crate::comptes::Comptes::new(
            racine.join("comptes.bin"),
            ["marie", "support"]
                .into_iter()
                .map(|nom| ams_auth::Account {
                    login: String::from(nom),
                    hash: String::new(),
                    addresses: std::vec![std::format!("{nom}@exemple.test")],
                })
                .collect(),
        ));
        let remise = Arc::new(crate::delivery::Boites::new(
            carte,
            racine.to_path_buf(),
            b"mail.exemple.test".to_vec(),
            Arc::clone(&comptes),
        ));
        let table = Arc::new(crate::delegations::Delegations::new(
            racine.join("delegations.bin"),
            Vec::new(),
        ));
        // **LA MÊME TABLE POUR IMAP ET POUR L'API**, comme en production : c'est
        // ce qui permet de vérifier que l'espace `Partagés` d'IMAP ne fuit pas
        // dans les routes personnelles.
        let boites = Arc::new(BoitesImap::new(
            Arc::clone(&remise),
            b"mail.exemple.test",
            Some(Arc::clone(&table)),
        ));
        let api = ApiMaildir::new(
            boites,
            comptes,
            remise,
            Arc::new(std::vec![String::from("exemple.test")]),
            Arc::new(ams_loop_tokio::SharedGuard::new(
                4,
                ams_guard::Thresholds::DEFAULT,
            )),
            Arc::new(crate::incidents::Incidents::new()),
        )
        .avec_delegations(Arc::clone(&table));
        (api, table)
    }

    /// Sert une requête au nom de `qui`, sur la boîte de `titulaire` s'il y en
    /// a un.
    fn servir_pour(
        api: &ApiMaildir,
        qui: &str,
        titulaire: Option<&str>,
        resource: Resource<'_>,
        method: Method,
        corps: &[u8],
    ) -> (StatusCode, String) {
        let mut place = std::vec![0_u8; 64 * 1024];
        let Served { status, body, .. } = api.serve(
            resource,
            method,
            qui,
            ams_loop_tokio::http::Appel {
                body: corps,
                query: ams_api::Query::default(),
                range: None,
                content_range: None,
                idempotency_key: None,
                owner: titulaire,
                nonce: 0,
                source: ams_guard::Source::V4([192, 0, 2, 1]),
            },
            &mut place,
        );
        (status, String::from_utf8_lossy(body).into_owned())
    }

    /// **LA DÉLÉGATION, DE BOUT EN BOUT** : l'administration la pose, le
    /// délégué atteint la boîte dans la mesure de ses droits, et la retirer
    /// vaut tout de suite.
    /// **COPIER ET DÉPLACER, EN GROUPE ET TOUT OU RIEN** : chaque message dit
    /// son nouvel UID, ce qui manque se dit à part, et un déplacement retire
    /// les originaux — sans décaler les rangs de ceux qui restent.
    #[tokio::test(flavor = "multi_thread")]
    async fn copier_et_deplacer_des_messages() {
        let temporaire = Ephemere::neuf();
        let (api, _) = api_partagee(&temporaire.0);
        let boite = Resource::Messages { boite: "INBOX" };
        let mut uids = Vec::new();
        for rang in 1..=4 {
            let lettre = std::format!("From: a@ailleurs.test\r\nSubject: n{rang}\r\n\r\nc\r\n");
            let (status, corps) = servir(&api, boite, Method::Post, lettre.as_bytes());
            assert_eq!(status, StatusCode::CREATED, "{corps}");
            let uid: u32 = corps
                .trim_start_matches("{\"uid\":")
                .trim_end_matches('}')
                .parse()
                .expect("un UID");
            uids.push(uid);
        }
        let (status, _) = servir(
            &api,
            Resource::Mailbox { boite: "Archives" },
            Method::Put,
            b"",
        );
        assert!(
            matches!(status, StatusCode::CREATED | StatusCode::NO_CONTENT),
            "{status:?}"
        );

        // Déplacer le 2e et le 4e, plus un UID qui n'existe pas.
        let corps = std::format!(
            r#"{{"to":"Archives","uids":[{},{},999]}}"#,
            uids[1],
            uids[3]
        );
        let (status, rendu) = servir(
            &api,
            Resource::Move { boite: "INBOX" },
            Method::Post,
            corps.as_bytes(),
        );
        assert_eq!(status, StatusCode::OK, "{rendu}");
        assert!(rendu.contains(r#""missing":[999]"#), "{rendu}");
        assert_eq!(rendu.matches(r#""from":"#).count(), 2, "{rendu}");
        let (_, liste) = servir(&api, boite, Method::Get, b"");
        assert_eq!(
            liste.matches(r#""uid":"#).count(),
            2,
            "la source garde deux : {liste}"
        );
        assert!(liste.contains("n1") && liste.contains("n3"), "{liste}");
        let (_, archives) = servir(
            &api,
            Resource::Messages { boite: "Archives" },
            Method::Get,
            b"",
        );
        assert!(
            archives.contains("n2") && archives.contains("n4"),
            "{archives}"
        );

        // Copier laisse l'original.
        let corps = std::format!(r#"{{"to":"Archives","uids":[{}]}}"#, uids[0]);
        let (status, rendu) = servir(
            &api,
            Resource::Copy { boite: "INBOX" },
            Method::Post,
            corps.as_bytes(),
        );
        assert_eq!(status, StatusCode::OK, "{rendu}");
        let (_, liste) = servir(&api, boite, Method::Get, b"");
        assert_eq!(liste.matches(r#""uid":"#).count(), 2, "{liste}");
        let (_, archives) = servir(
            &api,
            Resource::Messages { boite: "Archives" },
            Method::Get,
            b"",
        );
        assert_eq!(archives.matches(r#""uid":"#).count(), 3, "{archives}");

        // Ce qui se refuse.
        let un = std::format!(r#"{{"to":"INBOX","uids":[{}]}}"#, uids[0]);
        let (status, _) = servir(
            &api,
            Resource::Move { boite: "INBOX" },
            Method::Post,
            un.as_bytes(),
        );
        assert_eq!(status, StatusCode::BAD_REQUEST, "déplacer vers soi-même");
        for destination in ["Inconnue", "Partagés/support/INBOX"] {
            let corps = std::format!(r#"{{"to":"{destination}","uids":[{}]}}"#, uids[0]);
            let (status, _) = servir(
                &api,
                Resource::Copy { boite: "INBOX" },
                Method::Post,
                corps.as_bytes(),
            );
            assert_eq!(status, StatusCode::NOT_FOUND, "{destination}");
        }
        let (status, _) = servir(
            &api,
            Resource::Copy { boite: "Inconnue" },
            Method::Post,
            br#"{"to":"Archives","uids":[1]}"#,
        );
        assert_eq!(status, StatusCode::NOT_FOUND, "source absente");
        let (status, _) = servir(&api, Resource::Copy { boite: "INBOX" }, Method::Post, b"{}");
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Sert une requête de `marie` qui porte ce champ `Idempotency-Key`.
    fn servir_une_fois(
        api: &ApiMaildir,
        resource: Resource<'_>,
        corps: &[u8],
        cle: &[u8],
    ) -> (StatusCode, String) {
        let mut place = std::vec![0_u8; 64 * 1024];
        let Served { status, body, .. } = api.serve(
            resource,
            Method::Post,
            "marie",
            ams_loop_tokio::http::Appel {
                body: corps,
                query: ams_api::Query::default(),
                range: None,
                content_range: None,
                idempotency_key: Some(cle),
                owner: None,
                nonce: 0,
                source: ams_guard::Source::V4([192, 0, 2, 1]),
            },
            &mut place,
        );
        (status, String::from_utf8_lossy(body).into_owned())
    }

    /// **UNE REQUÊTE REJOUÉE SOUS LA MÊME CLÉ NE SE REFAIT PAS** : la même
    /// réponse revient, et rien ne s'ajoute ; la même clé pour une autre
    /// requête se refuse.
    #[tokio::test(flavor = "multi_thread")]
    async fn une_cle_d_idempotence_ne_double_rien() {
        let temporaire = Ephemere::neuf();
        let (api, _) = api_partagee(&temporaire.0);
        let api = api.avec_idempotence(Arc::new(crate::idempotence::Idempotence::new(
            temporaire.0.join("cles"),
        )));
        let boite = Resource::Messages { boite: "INBOX" };
        let lettre = b"From: a@ailleurs.test\r\nSubject: une fois\r\n\r\nc\r\n";
        let (status, premier) = servir_une_fois(&api, boite, lettre, b"\"k-1\"");
        assert_eq!(status, StatusCode::CREATED, "{premier}");
        let (status, second) = servir_une_fois(&api, boite, lettre, b"\"k-1\"");
        assert_eq!(
            (status, second.clone()),
            (StatusCode::CREATED, premier),
            "rejouée"
        );
        let (_, liste) = servir(&api, boite, Method::Get, b"");
        assert_eq!(
            liste.matches(r#""uid":"#).count(),
            1,
            "rien ne s'est ajouté : {liste}"
        );

        let (status, corps) =
            servir_une_fois(&api, boite, b"From: a@b.test\r\n\r\nautre\r\n", b"\"k-1\"");
        assert_eq!(status, StatusCode::UNPROCESSABLE_CONTENT, "{corps}");
        assert!(corps.contains("idempotency-key-reused"), "{corps}");
        let (status, _) = servir_une_fois(&api, boite, lettre, b"sans-guillemets");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Une autre clé s'exécute.
        let (status, _) = servir_une_fois(&api, boite, lettre, b"\"k-2\"");
        assert_eq!(status, StatusCode::CREATED);
        // Une lecture ne regarde pas la clé.
        let mut place = std::vec![0_u8; 64 * 1024];
        let servi = api.serve(
            boite,
            Method::Get,
            "marie",
            ams_loop_tokio::http::Appel {
                body: b"",
                query: ams_api::Query::default(),
                range: None,
                content_range: None,
                idempotency_key: Some(b"mal formee"),
                owner: None,
                nonce: 0,
                source: ams_guard::Source::V4([192, 0, 2, 1]),
            },
            &mut place,
        );
        assert_eq!(servi.status, StatusCode::OK);
    }

    /// **CE QUI PART PAR L'API SE RANGE DANS « ENVOYÉS »**, marqué lu — et la
    /// boîte naît, avec son usage, quand le compte n'en a pas désigné.
    #[tokio::test(flavor = "multi_thread")]
    async fn une_soumission_se_copie_dans_envoyes() {
        let temporaire = Ephemere::neuf();
        let (api, _) = api_partagee(&temporaire.0);
        let lettre = b"From: marie@exemple.test\r\nTo: support@exemple.test\r\n\
            Bcc: support@exemple.test\r\nSubject: copie\r\n\r\nc\r\n";
        for _ in 0..2 {
            let (status, corps) = servir(&api, Resource::Submissions, Method::Post, lettre);
            assert_eq!(status, StatusCode::OK, "{corps}");
        }
        let (_, envoyes) = servir(
            &api,
            Resource::Messages { boite: "Envoyés" },
            Method::Get,
            b"",
        );
        assert_eq!(envoyes.matches(r#""uid":"#).count(), 2, "{envoyes}");
        assert!(envoyes.contains("\\\\Seen"), "{envoyes}");
        // L'usage est posé : IMAP la rend `\\Sent`, et c'est par lui que les
        // clients la trouvent.
        let usages: Vec<_> = (0..)
            .map_while(|rang| {
                let mut place = [0_u8; 256];
                api.boites
                    .name(b"marie", rang, &mut place)
                    .map(|vue| (vue.name.to_vec(), vue.special))
            })
            .collect();
        assert!(
            usages
                .iter()
                .any(|(nom, usage)| nom.as_slice() == "Envoyés".as_bytes()
                    && usage.contains(ams_proto_imap::SpecialUse::SENT)),
            "{usages:?}"
        );
    }

    /// **L'ESPACE `Partagés` EST CELUI D'IMAP** : les routes personnelles de
    /// l'API ne le listent pas et ne l'ouvrent pas — la boîte d'autrui s'y
    /// nomme par `/v1/accounts/{compte}/mailboxes/…`, et par là seulement.
    #[tokio::test(flavor = "multi_thread")]
    async fn l_espace_partage_d_imap_ne_fuit_pas_dans_l_api() {
        let temporaire = Ephemere::neuf();
        let (api, _) = api_partagee(&temporaire.0);
        let cible = Resource::Delegate {
            compte: "support",
            delegue: "marie",
        };
        let (status, corps) = servir(&api, cible, Method::Put, br#"{"rights":["write"]}"#);
        assert_eq!(status, StatusCode::CREATED, "{corps}");

        let (status, corps) =
            servir_pour(&api, "marie", None, Resource::Mailboxes, Method::Get, b"");
        assert_eq!(status, StatusCode::OK, "{corps}");
        assert!(!corps.contains("Partag"), "l'espace d'IMAP a fui : {corps}");
        for ressource in [
            Resource::Mailbox {
                boite: "Partagés/support/INBOX",
            },
            Resource::Messages {
                boite: "Partagés/support/INBOX",
            },
            Resource::Mailbox { boite: "Partagés" },
        ] {
            for methode in [Method::Get, Method::Put, Method::Delete] {
                let (status, _) = servir_pour(&api, "marie", None, ressource, methode, b"");
                assert_eq!(status, StatusCode::NOT_FOUND, "{ressource:?} {methode:?}");
            }
        }
        // Et la voie prévue, elle, mène bien à la boîte.
        let (status, _) = servir_pour(
            &api,
            "marie",
            Some("support"),
            Resource::Mailbox { boite: "INBOX" },
            Method::Get,
            b"",
        );
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn une_delegation_ouvre_la_boite_d_autrui_dans_la_mesure_de_ses_droits() {
        let temporaire = Ephemere::neuf();
        let (api, _) = api_partagee(&temporaire.0);
        let boite = Resource::Messages { boite: "INBOX" };
        let lettre = b"From: client@ailleurs.test\r\nSubject: au support\r\n\r\naide\r\n";
        // support@ reçoit un message, par sa propre voie.
        let (status, corps) = servir_pour(&api, "support", None, boite, Method::Post, lettre);
        assert_eq!(status, StatusCode::CREATED, "{corps}");

        // ── SANS DÉLÉGATION : LA BOÎTE D'AUTRUI N'EXISTE PAS ───────────────
        let (status, _) = servir_pour(&api, "marie", Some("support"), boite, Method::Get, b"");
        assert_eq!(status, StatusCode::NOT_FOUND, "sans délégation, rien");

        // ── L'ADMINISTRATION ACCORDE LA LECTURE ─────────────────────────────
        let cible = Resource::Delegate {
            compte: "support",
            delegue: "marie",
        };
        let (status, corps) = servir(&api, cible, Method::Put, br#"{"rights":["read"]}"#);
        assert_eq!(status, StatusCode::CREATED, "{corps}");
        assert!(corps.contains(r#""rights":["read"]"#), "{corps}");

        let (status, corps) = servir_pour(&api, "marie", Some("support"), boite, Method::Get, b"");
        assert_eq!(status, StatusCode::OK, "{corps}");
        assert!(
            corps.contains("au support"),
            "marie lit la boîte de support : {corps}"
        );
        // Mais elle n'y écrit pas.
        let (status, _) = servir_pour(&api, "marie", Some("support"), boite, Method::Post, lettre);
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "la lecture n'ouvre pas l'écriture"
        );

        // ── ELLE VOIT SES DÉLÉGATIONS ───────────────────────────────────────
        let (_, corps) = servir_pour(
            &api,
            "marie",
            None,
            Resource::OwnDelegations,
            Method::Get,
            b"",
        );
        assert_eq!(
            corps,
            r#"{"delegations":[{"account":"support","rights":["read"]}]}"#
        );

        // ── L'ÉCRITURE, PUIS L'ENVOI AU NOM DE SUPPORT@ ────────────────────
        let (status, corps) = servir(&api, cible, Method::Put, br#"{"rights":["write"]}"#);
        assert_eq!(status, StatusCode::OK, "remplacée, pas créée : {corps}");
        assert!(
            corps.contains(r#""rights":["read","write"]"#),
            "écrire implique lire : {corps}"
        );
        let (status, _) = servir_pour(&api, "marie", Some("support"), boite, Method::Post, lettre);
        assert_eq!(status, StatusCode::CREATED, "l'écriture ouvre le dépôt");

        let reponse =
            b"From: support@exemple.test\r\nTo: support@exemple.test\r\nSubject: re\r\n\r\nok\r\n";
        let (status, _) = servir_pour(
            &api,
            "marie",
            None,
            Resource::Submissions,
            Method::Post,
            reponse,
        );
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "sans `send`, pas au nom de support@"
        );
        servir(&api, cible, Method::Put, br#"{"rights":["write","send"]}"#);
        let (status, corps) = servir_pour(
            &api,
            "marie",
            None,
            Resource::Submissions,
            Method::Post,
            reponse,
        );
        assert_eq!(
            status,
            StatusCode::OK,
            "avec `send`, au nom de support@ : {corps}"
        );

        // ── LA LISTE DE L'ADMINISTRATION ────────────────────────────────────
        let (_, corps) = servir(
            &api,
            Resource::Delegates { compte: "support" },
            Method::Get,
            b"",
        );
        assert_eq!(
            corps,
            r#"{"delegates":[{"login":"marie","rights":["read","write","send"]}]}"#
        );

        // ── RETIRÉE, ELLE CESSE DE VALOIR À LA REQUÊTE SUIVANTE ────────────
        let (status, _) = servir(&api, cible, Method::Delete, b"");
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = servir_pour(&api, "marie", Some("support"), boite, Method::Get, b"");
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = servir(&api, cible, Method::Delete, b"");
        assert_eq!(status, StatusCode::NOT_FOUND, "retirer deux fois rend 404");
    }

    /// **CE QU'UNE DÉLÉGATION NE PEUT PAS ÊTRE SE REFUSE.**
    #[tokio::test(flavor = "multi_thread")]
    async fn une_delegation_mal_formee_se_refuse() {
        let temporaire = Ephemere::neuf();
        let (api, _) = api_partagee(&temporaire.0);
        let vers = |compte, delegue, corps: &[u8]| {
            servir(
                &api,
                Resource::Delegate { compte, delegue },
                Method::Put,
                corps,
            )
            .0
        };
        assert_eq!(
            vers("support", "marie", br#"{"rights":["admin"]}"#),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            vers("support", "marie", br#"{"rights":[]}"#),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            vers("marie", "marie", br#"{"rights":["read"]}"#),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            vers("support", "fantome", br#"{"rights":["read"]}"#),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            vers("fantome", "marie", br#"{"rights":["read"]}"#),
            StatusCode::NOT_FOUND
        );
        let (status, _) = servir(
            &api,
            Resource::Delegates { compte: "fantome" },
            Method::Get,
            b"",
        );
        assert_eq!(status, StatusCode::NOT_FOUND);
        // Sa propre boîte, nommée par le chemin d'autrui, s'atteint sans délégation.
        let (status, _) = servir_pour(
            &api,
            "marie",
            Some("marie"),
            Resource::Mailboxes,
            Method::Get,
            b"",
        );
        assert_eq!(status, StatusCode::OK);
    }

    /// **SANS MAGASIN DE DÉLÉGATIONS**, les routes d'administration le disent,
    /// et aucune boîte d'autrui ne s'atteint.
    #[test]
    fn sans_magasin_pas_de_delegation() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        let (status, _) = servir(
            &api,
            Resource::Delegates { compte: "marie" },
            Method::Get,
            b"",
        );
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        let (status, corps) = servir(&api, Resource::OwnDelegations, Method::Get, b"");
        assert_eq!(
            (status, corps.as_str()),
            (StatusCode::OK, r#"{"delegations":[]}"#)
        );
        let (status, _) = servir_pour(
            &api,
            "marie",
            Some("support"),
            Resource::Mailboxes,
            Method::Get,
            b"",
        );
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── LA PAGINATION ──────────────────────────────────────────────────────

    /// Les UID d'une page, dans l'ordre où elle les rend, et son curseur.
    fn page(api: &ApiMaildir, query: ams_api::Query) -> (StatusCode, Vec<u64>, Option<u64>) {
        let (status, corps) = servir_avec(
            api,
            Resource::Messages { boite: "INBOX" },
            Method::Get,
            b"",
            query,
        );
        let uids = corps
            .split("\"uid\":")
            .skip(1)
            .filter_map(|reste| {
                reste
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|chiffres| chiffres.parse().ok())
            })
            .collect();
        let suivant = corps.split_once("\"next\":").and_then(|(_, reste)| {
            reste
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|chiffres| chiffres.parse().ok())
        });
        (status, uids, suivant)
    }

    /// **LES PLUS RÉCENTS D'ABORD, ET LE CURSEUR SE RENVOIE TEL QUEL.**
    ///
    /// Jusqu'en 0.2.17, la liste rendait les cinquante plus ANCIENS, et le
    /// curseur ne pouvait pas revenir : la chaîne de requête était jetée. On
    /// parcourt ici une boîte de cinq messages par pages de deux, en renvoyant
    /// chaque fois `next` en `before` — exactement ce que fera un client.
    #[test]
    fn la_liste_se_parcourt_des_plus_recents_aux_plus_anciens() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        let uids: Vec<u64> = (1..=5)
            .map(|n| ranger(&api, &std::format!("n{n}")))
            .collect();
        let recents: Vec<u64> = uids.iter().rev().copied().collect();

        // Sans paramètre : tout, du plus récent au plus ancien, et rien après.
        assert_eq!(
            page(&api, ams_api::Query::default()),
            (StatusCode::OK, recents.clone(), None)
        );

        // Par pages de deux, en suivant le curseur.
        let mut vus = Vec::new();
        let mut avant = None;
        loop {
            let (status, lus, suivant) = page(
                &api,
                ams_api::Query {
                    before: avant.map(|uid: u64| u32::try_from(uid).expect("tient")),
                    limit: Some(2),
                    since: None,
                },
            );
            assert_eq!(status, StatusCode::OK);
            assert!(lus.len() <= 2);
            vus.extend(lus.iter().copied());
            match suivant {
                // Le curseur est le DERNIER rendu : le renvoyer n'omet rien et
                // ne répète rien.
                Some(curseur) => {
                    assert_eq!(Some(&curseur), lus.last());
                    avant = Some(curseur);
                }
                None => break,
            }
        }
        assert_eq!(vus, recents, "chaque message une fois, dans l'ordre");

        // Avant le plus ancien : une page vide, sans curseur.
        let plus_ancien = u32::try_from(*uids.first().expect("un")).expect("tient");
        assert_eq!(
            page(
                &api,
                ams_api::Query {
                    before: Some(plus_ancien),
                    ..ams_api::Query::default()
                }
            ),
            (StatusCode::OK, Vec::new(), None)
        );
    }

    /// **UN `limit` AU-DELÀ DE LA BORNE EST REFUSÉ**, et non ramené en silence :
    /// le client croirait avoir tout ce qu'il a demandé.
    #[test]
    fn un_limit_trop_grand_est_refuse() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        let trop = u16::try_from(super::PAGE_MAX + 1).expect("tient");
        let (status, _, _) = page(
            &api,
            ams_api::Query {
                limit: Some(trop),
                ..ams_api::Query::default()
            },
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let juste = u16::try_from(super::PAGE_MAX).expect("tient");
        let (status, _, _) = page(
            &api,
            ams_api::Query {
                limit: Some(juste),
                ..ams_api::Query::default()
            },
        );
        assert_eq!(status, StatusCode::OK);
    }

    // ── LE JOURNAL DES CHANGEMENTS ─────────────────────────────────────────

    /// Un nombre écrit après `"clef":` dans un corps JSON.
    fn nombre(corps: &str, clef: &str) -> Option<u64> {
        corps
            .split_once(&std::format!("\"{clef}\":"))
            .and_then(|(_, reste)| {
                reste
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|chiffres| chiffres.parse().ok())
            })
    }

    /// Les UID d'un tableau `"clef":[…]` — des objets `{"uid":…}` ou des
    /// nombres nus.
    fn uids_de(corps: &str, clef: &str) -> Vec<u64> {
        let Some((_, reste)) = corps.split_once(&std::format!("\"{clef}\":[")) else {
            return Vec::new();
        };
        let mut profondeur = 0_i32;
        let mut fin = reste.len();
        for (rang, c) in reste.char_indices() {
            match c {
                '[' | '{' => profondeur = profondeur.saturating_add(1),
                ']' | '}' if profondeur > 0 => profondeur = profondeur.saturating_sub(1),
                ']' => {
                    fin = rang;
                    break;
                }
                _ => {}
            }
        }
        let tableau = &reste[..fin];
        if tableau.contains("\"uid\":") {
            tableau
                .split("\"uid\":")
                .skip(1)
                .filter_map(|morceau| {
                    morceau
                        .split(|c: char| !c.is_ascii_digit())
                        .next()
                        .and_then(|chiffres| chiffres.parse().ok())
                })
                .collect()
        } else {
            tableau
                .split(',')
                .filter_map(|nombre| nombre.trim().parse().ok())
                .collect()
        }
    }

    /// Demande le delta depuis ce point.
    fn changements(api: &ApiMaildir, since: u64, limit: Option<u16>) -> (StatusCode, String) {
        servir_avec(
            api,
            Resource::Changes { boite: "INBOX" },
            Method::Get,
            b"",
            ams_api::Query {
                since: Some(since),
                limit,
                before: None,
            },
        )
    }

    /// **L'ENVELOPPE SE LIT SUR LE DISQUE**, décodée, dans le GET comme dans le
    /// PATCH — les deux rendent la même représentation.
    #[tokio::test(flavor = "multi_thread")]
    async fn un_message_rend_son_enveloppe() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        let message = "Date: Sat, 29 Aug 2026 11:08:31 +0200\r\n\
             From: =?utf-8?Q?Marie_Cur=C3=A9?= <marie@exemple.test>\r\n\
             To: Jean <jean@exemple.test>, paul@exemple.test\r\n\
             Message-ID: <un@exemple.test>\r\n\
             Subject: bonjour\r\n\r\nLe corps.\r\n";
        let (status, corps) = servir(
            &api,
            Resource::Messages { boite: "INBOX" },
            Method::Post,
            message.as_bytes(),
        );
        assert_eq!(status, StatusCode::CREATED, "{corps}");
        let uid: u64 = corps
            .trim_start_matches("{\"uid\":")
            .trim_end_matches('}')
            .parse()
            .expect("un UID");
        for (methode, demande) in [
            (Method::Get, &b""[..]),
            (Method::Patch, br#"{"add":["\\Seen"]}"#),
        ] {
            let (status, corps) = servir(
                &api,
                Resource::Message {
                    boite: "INBOX",
                    uid,
                },
                methode,
                demande,
            );
            assert_eq!(status, StatusCode::OK, "{corps}");
            assert!(
                corps.contains(r#""date":1787994511,"dateZone":"+0200""#),
                "{corps}"
            );
            assert!(
                corps.contains(r#""from":[{"name":"Marie Curé","email":"marie@exemple.test"}]"#),
                "{corps}"
            );
            assert!(
                corps.contains(concat!(
                    r#""to":[{"name":"Jean","email":"jean@exemple.test"},"#,
                    r#"{"name":null,"email":"paul@exemple.test"}]"#
                )),
                "{corps}"
            );
            assert!(
                corps.contains(r#""messageId":"un@exemple.test""#),
                "{corps}"
            );
            assert!(corps.contains(r#""complete":true"#), "{corps}");
            assert!(
                corps.contains(r#""structure":{"part":"1","type":"text/plain""#),
                "{corps}"
            );
        }
    }

    /// **UNE ENVELOPPE QUI NE TIENT PAS N'EMPORTE PAS LE MESSAGE** : il est
    /// rendu, avec `"envelope": null`, et non un `500`.
    #[tokio::test(flavor = "multi_thread")]
    async fn une_enveloppe_trop_grande_devient_null() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        // Chaque `<` s'écrit `\u003c` en JSON : six octets pour un. Vingt noms
        // de neuf cents chevrons dépassent de loin les 64 Kio de la réponse.
        let nom = "<".repeat(900);
        let mut message = std::string::String::from("From: marie@exemple.test\r\nTo: ");
        for rang in 0..20 {
            message.push_str(&std::format!("\"{nom}\" <a{rang}@exemple.test>,\r\n "));
        }
        message.push_str("fin@exemple.test\r\nSubject: long\r\n\r\nLe corps.\r\n");
        let (status, corps) = servir(
            &api,
            Resource::Messages { boite: "INBOX" },
            Method::Post,
            message.as_bytes(),
        );
        assert_eq!(status, StatusCode::CREATED, "{corps}");
        let uid: u64 = corps
            .trim_start_matches("{\"uid\":")
            .trim_end_matches('}')
            .parse()
            .expect("un UID");
        let (status, corps) = servir(
            &api,
            Resource::Message {
                boite: "INBOX",
                uid,
            },
            Method::Get,
            b"",
        );
        assert_eq!(status, StatusCode::OK, "{corps}");
        assert!(corps.contains(r#""subject":"long""#), "{corps}");
        // L'enveloppe a cédé ; la structure, petite, est restée.
        assert!(
            corps.contains(r#""envelope":null,"structure":{"part":"1""#),
            "{corps}"
        );
    }

    /// **UNE STRUCTURE QUI NE TIENT PAS CÈDE À SON TOUR** : le message reste.
    #[tokio::test(flavor = "multi_thread")]
    async fn une_structure_trop_grande_devient_null() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        // Quarante parties dont le nom fait neuf cents chevrons — une ligne
        // sous les 998 octets de la RFC 5322 : six octets de JSON par chevron,
        // bien au-delà des 64 Kio de la réponse.
        let nom = "<".repeat(900);
        let mut message = std::string::String::from(
            "From: marie@exemple.test\r\nSubject: pieces\r\n\
             Content-Type: multipart/alternative; boundary=a\r\n\r\n",
        );
        for _ in 0..40 {
            message.push_str(&std::format!(
                "--a\r\nContent-Type: text/plain;\r\n name=\"{nom}\"\r\n\r\nx\r\n"
            ));
        }
        message.push_str("--a--\r\n");
        // DÉPOSÉ COMME PAR SMTP, et non par l'API : un dépôt REST exige un
        // brouillon pour ce qui porte des parties nommées (phase 4b), mais un
        // message reçu arrive tel que l'expéditeur l'a écrit.
        let neuf = temporaire.0.join("marie").join("new");
        std::fs::create_dir_all(&neuf).expect("new/");
        std::fs::write(neuf.join("1.essai.local"), message.as_bytes()).expect("déposé");
        let (status, corps) = servir(
            &api,
            Resource::Messages { boite: "INBOX" },
            Method::Get,
            b"",
        );
        assert_eq!(status, StatusCode::OK, "{corps}");
        let uid: u64 = corps
            .split(r#""uid":"#)
            .nth(1)
            .and_then(|reste| reste.split(',').next())
            .and_then(|nombre| nombre.parse().ok())
            .expect("un UID");
        let (status, corps) = servir(
            &api,
            Resource::Message {
                boite: "INBOX",
                uid,
            },
            Method::Get,
            b"",
        );
        assert_eq!(status, StatusCode::OK, "{corps}");
        assert!(corps.contains(r#""subject":"pieces""#), "{corps}");
        assert!(
            corps.ends_with(r#""envelope":null,"structure":null}}"#),
            "{corps}"
        );
    }

    /// Ce qu'une partie servie rend : statut, type, disposition, corps, portée.
    type PartieServie = (
        StatusCode,
        String,
        Option<String>,
        std::vec::Vec<u8>,
        Option<ams_loop_tokio::http::ContentRange>,
    );

    /// Dépose un message comme SMTP le ferait, et rend son UID.
    fn deposer(temporaire: &Ephemere, api: &ApiMaildir, message: &[u8]) -> u64 {
        let neuf = temporaire.0.join("marie").join("new");
        std::fs::create_dir_all(&neuf).expect("new/");
        let nom = std::format!(
            "{}.essai.local",
            std::fs::read_dir(&neuf).map_or(0, Iterator::count)
        );
        std::fs::write(neuf.join(nom), message).expect("déposé");
        let (status, corps) = servir(api, Resource::Messages { boite: "INBOX" }, Method::Get, b"");
        assert_eq!(status, StatusCode::OK, "{corps}");
        // Les plus récents d'abord : le premier UID de la page est le dernier
        // arrivé.
        corps
            .split(r#""uid":"#)
            .nth(1)
            .and_then(|reste| reste.split(',').next())
            .and_then(|nombre| nombre.parse().ok())
            .expect("un UID")
    }

    /// Sert une partie, avec ou sans portée.
    fn partie(api: &ApiMaildir, uid: u64, chemin: &str, portee: Option<&str>) -> PartieServie {
        let mut place = std::vec![0_u8; 64 * 1024];
        let servi = api.serve(
            Resource::MessagePart {
                boite: "INBOX",
                uid,
                partie: chemin,
            },
            Method::Get,
            "marie",
            ams_loop_tokio::http::Appel {
                body: b"",
                query: ams_api::Query::default(),
                range: portee.map(str::as_bytes),
                content_range: None,
                idempotency_key: None,
                owner: None,
                nonce: 0,
                source: ams_guard::Source::V4([192, 0, 2, 1]),
            },
            &mut place,
        );
        (
            servi.status,
            servi.media.to_string(),
            servi.disposition.map(str::to_string),
            servi.body.to_vec(),
            servi.range,
        )
    }

    /// **UNE PARTIE SE SERT DÉCODÉE**, sous son type, et un `multipart` n'a pas
    /// de contenu à lui.
    #[tokio::test(flavor = "multi_thread")]
    async fn une_partie_se_sert_decodee() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        let uid = deposer(
            &temporaire,
            &api,
            b"From: marie@exemple.test\r\nSubject: parties\r\n\
              Content-Type: multipart/mixed; boundary=a\r\n\r\n\
              --a\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n\
              --b\r\nContent-Type: text/plain; charset=utf-8\r\n\
              Content-Transfer-Encoding: quoted-printable\r\n\r\nd=C3=A9j=\r\n=C3=A0\r\n\
              --b--\r\n\
              --a\r\nContent-Type: application/octet-stream; name=\"x.bin\"\r\n\
              Content-Transfer-Encoding: base64\r\n\r\nAAECAwQFBgcICQ==\r\n\
              --a\r\nContent-Type: application/x-bizarre\r\n\
              Content-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 x\r\n\
              --a\r\nContent-Type: message/rfc822\r\n\r\nSubject: dedans\r\n\r\ncorps\r\n\
              --a--\r\n",
        );
        // Le quoted-printable défait, coupure molle comprise.
        let (status, media, disposition, corps, portee) = partie(&api, uid, "1.1", None);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(media, "text/plain; charset=utf-8");
        assert_eq!(disposition.as_deref(), Some("attachment"));
        assert_eq!(corps, "déjà".as_bytes());
        assert_eq!(portee, None);
        // Le base64 défait, et le nom dit.
        let (status, media, disposition, corps, _) = partie(&api, uid, "2", None);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(media, "application/octet-stream");
        assert_eq!(
            disposition.as_deref(),
            Some("attachment; filename=\"x.bin\"; filename*=UTF-8''x.bin")
        );
        assert_eq!(corps, (0_u8..10).collect::<std::vec::Vec<_>>());
        // UNE PORTÉE SE COMPTE SUR LE DÉCODÉ.
        let (status, _, _, corps, portee) = partie(&api, uid, "2", Some("bytes=2-4"));
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(corps, [2, 3, 4]);
        assert_eq!(
            portee,
            Some(ams_loop_tokio::http::ContentRange {
                part: Some((2, 4)),
                complete: 10
            })
        );
        let (status, _, _, corps, _) = partie(&api, uid, "2", Some("bytes=-3"));
        assert_eq!(
            (status, corps),
            (StatusCode::PARTIAL_CONTENT, std::vec![7, 8, 9])
        );
        // Au-delà : `416`, et la taille décodée.
        let (status, _, _, _, portee) = partie(&api, uid, "2", Some("bytes=10-"));
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(portee.map(|p| p.complete), Some(10));
        // Un champ qu'on ne comprend pas s'ignore : tout part.
        let (status, _, _, corps, _) = partie(&api, uid, "2", Some("octets=0-1"));
        assert_eq!((status, corps.len()), (StatusCode::OK, 10));
        // UN ENCODAGE INCONNU NE PASSE PAS POUR LE CONTENU, avec ou sans portée.
        for portee in [None, Some("bytes=0-1")] {
            let (status, _, _, corps, _) = partie(&api, uid, "3", portee);
            assert_eq!(status, StatusCode::UNPROCESSABLE_CONTENT);
            assert!(String::from_utf8_lossy(&corps).contains("unknown-encoding"));
        }
        // Un `multipart` n'a pas de contenu à lui ; un chemin absent non plus.
        assert_eq!(partie(&api, uid, "1", None).0, StatusCode::NOT_FOUND);
        assert_eq!(partie(&api, uid, "9", None).0, StatusCode::NOT_FOUND);
        assert_eq!(partie(&api, uid, "1.x", None).0, StatusCode::NOT_FOUND);
        // Un message transféré se rend tel qu'il est.
        let (status, media, disposition, corps, _) = partie(&api, uid, "4", None);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(media, ams_api::MESSAGE_MEDIA_TYPE);
        assert_eq!(disposition, None);
        assert!(corps.starts_with(b"Subject: dedans"), "{corps:?}");
    }

    /// **UNE PARTIE TROP GRANDE SANS PORTÉE DIT `413`**, et la porte des
    /// portées ; avec une portée, elle se lit par morceaux.
    #[tokio::test(flavor = "multi_thread")]
    async fn une_grande_partie_se_lit_par_portees() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        let donnees: std::vec::Vec<u8> = (0..100_000_u32).map(|i| (i % 251) as u8).collect();
        let mut message = b"From: marie@exemple.test\r\nSubject: grand\r\n\
            Content-Type: application/octet-stream\r\n\
            Content-Transfer-Encoding: base64\r\n\r\n"
            .to_vec();
        for morceau in donnees.chunks(57) {
            let mut ligne = [0_u8; 128];
            let dite = ams_mime::encode_base64_line(morceau, &mut ligne).expect("encodable");
            message.extend_from_slice(dite);
        }
        let uid = deposer(&temporaire, &api, &message);
        let (status, _, _, _, _) = partie(&api, uid, "1", None);
        assert_eq!(status, StatusCode::CONTENT_TOO_LARGE);
        let mut relu = std::vec::Vec::new();
        while relu.len() < donnees.len() {
            let debut = relu.len();
            let (status, _, _, corps, portee) = partie(
                &api,
                uid,
                "1",
                Some(&std::format!(
                    "bytes={debut}-{}",
                    debut.saturating_add(29_999)
                )),
            );
            assert_eq!(status, StatusCode::PARTIAL_CONTENT);
            assert_eq!(portee.map(|p| p.complete), Some(100_000));
            relu.extend_from_slice(&corps);
        }
        assert!(relu == donnees, "la partie relue n'est pas celle déposée");
    }

    /// **LA SYNCHRONISATION INCRÉMENTALE, DE BOUT EN BOUT, SUR UNE VRAIE BOÎTE.**
    ///
    /// Le client prend `highestModseq`, puis la boîte change par les chemins
    /// ordinaires — un message arrive, un autre est lu, un troisième est
    /// supprimé —, et le delta rend exactement cela. Aucun de ces chemins
    /// n'écrit au journal : c'est la comparaison qui l'a vu.
    #[tokio::test(flavor = "multi_thread")]
    async fn le_delta_rend_exactement_ce_qui_a_change() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        let premier = ranger(&api, "un");
        let deuxieme = ranger(&api, "deux");
        let troisieme = ranger(&api, "trois");

        // ── LE POINT DE DÉPART ─────────────────────────────────────────────
        let (status, etat) = servir(&api, Resource::Mailbox { boite: "INBOX" }, Method::Get, b"");
        assert_eq!(status, StatusCode::OK, "{etat}");
        let depart = nombre(&etat, "highestModseq").expect("un point de départ");
        assert!(
            temporaire
                .0
                .join("marie")
                .join(crate::journal::NOM)
                .exists(),
            "le journal vit dans le répertoire de la boîte"
        );

        // Rien n'a changé : un delta vide, au même point.
        let (status, corps) = changements(&api, depart, None);
        assert_eq!(status, StatusCode::OK, "{corps}");
        assert!(uids_de(&corps, "changed").is_empty(), "{corps}");
        assert!(uids_de(&corps, "vanished").is_empty(), "{corps}");
        assert_eq!(nombre(&corps, "modseq"), Some(depart));

        // ── LA BOÎTE CHANGE, PAR SES CHEMINS ORDINAIRES ────────────────────
        let quatrieme = ranger(&api, "quatre");
        let (status, _) = servir(
            &api,
            Resource::Message {
                boite: "INBOX",
                uid: deuxieme,
            },
            Method::Patch,
            br#"{"add":["\\Seen"]}"#,
        );
        assert_eq!(status, StatusCode::OK);
        let (status, _) = servir(
            &api,
            Resource::Message {
                boite: "INBOX",
                uid: premier,
            },
            Method::Delete,
            b"",
        );
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, corps) = changements(&api, depart, None);
        assert_eq!(status, StatusCode::OK, "{corps}");
        let mut changes = uids_de(&corps, "changed");
        changes.sort_unstable();
        assert_eq!(changes, [deuxieme, quatrieme], "{corps}");
        assert_eq!(uids_de(&corps, "vanished"), [premier], "{corps}");
        assert!(
            corps.contains("\\\\Seen"),
            "le message lu porte son drapeau : {corps}"
        );
        assert!(
            !corps.contains(&std::format!("\"uid\":{troisieme},")),
            "{corps}"
        );
        let apres = nombre(&corps, "modseq").expect("un curseur");
        assert!(apres > depart);
        assert!(corps.contains("\"more\":false"), "{corps}");

        // Depuis ce curseur : plus rien.
        let (_, corps) = changements(&api, apres, None);
        assert!(uids_de(&corps, "changed").is_empty(), "{corps}");
        assert!(uids_de(&corps, "vanished").is_empty(), "{corps}");

        // ── PAR PAGES D'UN ─────────────────────────────────────────────────
        let (mut curseur, mut vus, mut pages) = (depart, Vec::new(), 0);
        loop {
            let (status, corps) = changements(&api, curseur, Some(1));
            assert_eq!(status, StatusCode::OK, "{corps}");
            vus.extend(uids_de(&corps, "changed"));
            vus.extend(uids_de(&corps, "vanished"));
            curseur = nombre(&corps, "modseq").expect("un curseur");
            pages += 1;
            if corps.contains("\"more\":false") {
                break;
            }
            assert!(pages < 10, "la pagination ne converge pas");
        }
        vus.sort_unstable();
        assert_eq!(vus, [premier, deuxieme, quatrieme]);
        assert_eq!(curseur, apres);
        assert!(pages > 1);
    }

    /// **UN CURSEUR QUE LE JOURNAL NE SERT PAS REND `410`** — trop ancien, ou
    /// venu d'ailleurs — et une requête sans point de départ, `400`.
    #[tokio::test(flavor = "multi_thread")]
    async fn un_curseur_perime_rend_410() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        ranger(&api, "un");
        let (_, etat) = servir(&api, Resource::Mailbox { boite: "INBOX" }, Method::Get, b"");
        let depart = nombre(&etat, "highestModseq").expect("un point");
        for perime in [0, depart - 1, depart + 1_000] {
            let (status, corps) = changements(&api, perime, None);
            assert_eq!(status, StatusCode::GONE, "{perime} : {corps}");
            assert!(corps.contains("/problems/gone"), "{corps}");
        }
        // Sans `since`, ou avec une page trop grande : la requête est mal faite.
        let (status, _) = servir_avec(
            &api,
            Resource::Changes { boite: "INBOX" },
            Method::Get,
            b"",
            ams_api::Query::default(),
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = changements(
            &api,
            depart,
            Some(u16::try_from(super::PAGE_MAX + 1).expect("tient")),
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Et une boîte qui n'existe pas n'a pas de journal.
        let (status, _) = servir_avec(
            &api,
            Resource::Changes {
                boite: "Nulle-part",
            },
            Method::Get,
            b"",
            ams_api::Query {
                since: Some(depart),
                ..ams_api::Query::default()
            },
        );
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── LES DRAPEAUX ───────────────────────────────────────────────────────

    /// **UN `PATCH` POSE VRAIMENT LE DRAPEAU**, et le magasin s'en souvient.
    ///
    /// C'est l'essai qui manquait : le répartiteur servait la lecture, rendait
    /// `200` avec le message inchangé, et rien ne le disait.
    #[test]
    fn un_patch_pose_le_drapeau_dans_le_magasin() {
        let temporaire = Ephemere::neuf();
        let (boites, api) = api(&temporaire.0);
        let uid = ranger(&api, "à lire");
        assert_eq!(
            drapeaux_du_magasin(&boites, uid),
            ams_proto_imap::Flags::NONE,
            "un message rangé ne porte aucun drapeau"
        );

        let (status, corps) = servir(
            &api,
            Resource::Message {
                boite: "INBOX",
                uid,
            },
            Method::Patch,
            br#"{"add":["\\Seen"]}"#,
        );
        assert_eq!(status, StatusCode::OK, "{corps}");
        // **LE MAGASIN, ET NON LA RÉPONSE.** Une réponse peut mentir ; le
        // fichier sur le disque, non.
        assert_eq!(
            drapeaux_du_magasin(&boites, uid),
            ams_proto_imap::Flags::SEEN
        );
        // Et la réponse dit ce qui est.
        assert!(corps.contains(r"\\Seen"), "{corps}");
    }

    /// **ET IL L'ÔTE AUSSI.**
    #[test]
    fn un_patch_ote_le_drapeau() {
        let temporaire = Ephemere::neuf();
        let (boites, api) = api(&temporaire.0);
        let uid = ranger(&api, "déjà lu");
        let cible = Resource::Message {
            boite: "INBOX",
            uid,
        };
        servir(&api, cible, Method::Patch, br#"{"add":["\\Seen"]}"#);
        assert_eq!(
            drapeaux_du_magasin(&boites, uid),
            ams_proto_imap::Flags::SEEN
        );

        servir(&api, cible, Method::Patch, br#"{"remove":["\\Seen"]}"#);
        assert_eq!(
            drapeaux_du_magasin(&boites, uid),
            ams_proto_imap::Flags::NONE
        );
    }

    /// Un corps refusé ne touche à rien, et ne dit pas si la boîte existe.
    #[test]
    fn un_patch_illisible_ne_change_rien() {
        let temporaire = Ephemere::neuf();
        let (boites, api) = api(&temporaire.0);
        let uid = ranger(&api, "intact");
        let (status, _) = servir(
            &api,
            Resource::Message {
                boite: "INBOX",
                uid,
            },
            Method::Patch,
            br#"{"add":["\\PasUnDrapeau"]}"#,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            drapeaux_du_magasin(&boites, uid),
            ams_proto_imap::Flags::NONE
        );
    }

    // ── L'EFFACEMENT ───────────────────────────────────────────────────────

    /// **UN `DELETE` EFFACE POUR DE BON.**
    #[test]
    fn un_delete_retire_le_message_du_magasin() {
        let temporaire = Ephemere::neuf();
        let (boites, api) = api(&temporaire.0);
        let uid = ranger(&api, "à jeter");

        let (status, _) = servir(
            &api,
            Resource::Message {
                boite: "INBOX",
                uid,
            },
            Method::Delete,
            &[],
        );
        assert_eq!(status, StatusCode::NO_CONTENT);
        let boite = boites.open(b"marie", b"INBOX").expect("ouvrable");
        assert_eq!(boite.exists(), 0, "le message doit avoir disparu");
    }

    /// Un UID qu'on ne connaît pas ne dit pas si la boîte existe.
    #[test]
    fn un_delete_d_un_uid_inconnu_rend_404() {
        let temporaire = Ephemere::neuf();
        let (_boites, api) = api(&temporaire.0);
        let (status, _) = servir(
            &api,
            Resource::Message {
                boite: "INBOX",
                uid: 9999,
            },
            Method::Delete,
            &[],
        );
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── LES BOÎTES ─────────────────────────────────────────────────────────

    /// **UN `PUT` CRÉE LA BOÎTE, ET IL EST IDEMPOTENT** (§9.3.4 de RFC 9110).
    #[test]
    fn un_put_cree_la_boite_et_se_rejoue_sans_faute() {
        let temporaire = Ephemere::neuf();
        let (boites, api) = api(&temporaire.0);
        let cible = Resource::Mailbox { boite: "Archives" };

        let (status, _) = servir(&api, cible, Method::Put, &[]);
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            boites.open(b"marie", b"Archives").is_some(),
            "la boîte doit exister"
        );

        // **REJOUÉ, IL NE FAUTE PAS** : l'état demandé est déjà celui qui est.
        let (status, _) = servir(&api, cible, Method::Put, &[]);
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    /// **UN `DELETE` EFFACE LA BOÎTE.**
    #[test]
    fn un_delete_efface_la_boite() {
        let temporaire = Ephemere::neuf();
        let (boites, api) = api(&temporaire.0);
        let cible = Resource::Mailbox { boite: "Archives" };
        servir(&api, cible, Method::Put, &[]);
        assert!(boites.open(b"marie", b"Archives").is_some());

        let (status, _) = servir(&api, cible, Method::Delete, &[]);
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            boites.open(b"marie", b"Archives").is_none(),
            "la boîte doit avoir disparu"
        );
    }

    /// **UN FICHIER DÉPOSÉ APRÈS L'OUVERTURE, SANS UID, SE VOIT À LA LECTURE
    /// SUIVANTE.**
    ///
    /// Jusqu'en 0.2.19, l'adoption n'avait lieu qu'à l'ouverture de la boîte —
    /// une fois au démarrage pour une arrivée —, et un message déposé ensuite
    /// par un autre programme restait invisible jusqu'au redémarrage.
    #[test]
    fn un_fichier_depose_apres_l_ouverture_se_voit() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        let avant = ranger(&api, "déjà là");
        // Un autre programme dépose un message, sans UID, comme le ferait un
        // `procmail` ou une copie à la main.
        std::fs::write(
            temporaire
                .0
                .join("marie")
                .join("new")
                .join("1790000000.M1P2.ailleurs"),
            "From: autre@exemple.test\r\nSubject: déposé à côté\r\n\r\ncorps\r\n",
        )
        .expect("dépôt");
        let (status, uids, _) = page(&api, ams_api::Query::default());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(uids.len(), 2, "le message déposé doit se voir : {uids:?}");
        assert!(
            uids.iter().any(|&uid| uid > avant),
            "il reçoit un UID après ceux déjà donnés : {uids:?}"
        );
        // Et son nom porte désormais son UID.
        let noms: Vec<String> = std::fs::read_dir(temporaire.0.join("marie").join("new"))
            .expect("lisible")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            noms.iter().all(|nom| nom.contains(",U=")),
            "un nom est resté sans UID : {noms:?}"
        );
    }

    /// **UNE BOÎTE DONT ON A CONSULTÉ LE JOURNAL S'EFFACE ENTIÈREMENT.**
    ///
    /// La 0.2.19 laissait `ams-journal.bin` et son verrou derrière elle : le
    /// répertoire n'était plus vide, ne se retirait pas, et une vraie boîte de
    /// production a gardé ce résidu après une suppression qui répondait `204`.
    #[tokio::test(flavor = "multi_thread")]
    async fn une_boite_consultee_s_efface_sans_residu() {
        let temporaire = Ephemere::neuf();
        let (_, api) = api(&temporaire.0);
        let cible = Resource::Mailbox { boite: "Archives" };
        servir(&api, cible, Method::Put, &[]);
        // Consulter la boîte tient son journal, donc le crée sur le disque.
        let (status, etat) = servir(&api, cible, Method::Get, &[]);
        assert_eq!(status, StatusCode::OK, "{etat}");
        let repertoire = temporaire.0.join("marie").join(".Archives");
        assert!(repertoire.join(crate::journal::NOM).exists());

        let (status, _) = servir(&api, cible, Method::Delete, &[]);
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            !repertoire.exists(),
            "le répertoire de la boîte est resté : {:?}",
            std::fs::read_dir(&repertoire)
                .map(|entrees| entrees.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
        );
    }

    /// Effacer ce qui n'existe pas rend `404`, et non un succès silencieux.
    #[test]
    fn effacer_une_boite_absente_rend_404() {
        let temporaire = Ephemere::neuf();
        let (_boites, api) = api(&temporaire.0);
        let (status, _) = servir(
            &api,
            Resource::Mailbox { boite: "Jamais" },
            Method::Delete,
            &[],
        );
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── ET LA LECTURE N'A PAS BOUGÉ ────────────────────────────────────────

    /// **UN `GET` REND TOUJOURS LA LECTURE.** Le câblage du verbe ne doit pas
    /// avoir détourné le chemin ordinaire.
    #[test]
    fn la_lecture_sert_toujours_la_lecture() {
        let temporaire = Ephemere::neuf();
        let (_boites, api) = api(&temporaire.0);
        ranger(&api, "présent");
        let (status, corps) = servir(
            &api,
            Resource::Messages { boite: "INBOX" },
            Method::Get,
            &[],
        );
        assert_eq!(status, StatusCode::OK);
        assert!(corps.contains("\"messages\""), "{corps}");
        assert!(corps.contains("présent"), "{corps}");
    }
}
