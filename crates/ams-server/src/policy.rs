//! Qui a le droit de recevoir du courrier ici.

use std::sync::{Condvar, Mutex};

use ams_proto_smtp::Path;
use ams_sasl::Credentials;
use ams_session::{Authenticator, Policy, RecipientVerdict};

/// Combien de vérifications Argon2id peuvent avoir lieu EN MÊME TEMPS.
///
/// # Ce chiffre est une borne de mémoire, pas un réglage de confort
///
/// Une vérification coûte 19 Mio et quelques dizaines de millisecondes. C'est
/// **le but** : voilà ce qui rend une attaque par dictionnaire coûteuse. C'est
/// aussi une amplification offerte à qui envoie des `AUTH` — quelques octets sur
/// le fil deviennent 19 Mio chez nous.
///
/// Sans borne, deux cent cinquante-six connexions simultanées demanderaient
/// **cinq gibioctets**. Avec quatre, le pire cas tient dans 76 Mio, et les
/// tentatives excédentaires attendent leur tour sur un fil bloquant plutôt que
/// d'étouffer le serveur.
///
/// Quatre, et pas plus : au-delà, on n'accélère plus rien qu'une attaque.
const VERIFICATIONS_SIMULTANEES: usize = 4;

/// Un compteur de places, bloquant.
///
/// # Pourquoi un verrou de la bibliothèque standard dans un serveur asynchrone
///
/// Parce qu'on l'attend **sous `block_in_place`**, c'est-à-dire sur un fil que
/// tokio a déjà sorti de son ordonnanceur. Un sémaphore asynchrone ne servirait
/// à rien ici : la vérification qui suit est bloquante de toute façon, et c'est
/// justement pour cela qu'elle a quitté le fil de l'ordonnanceur.
pub struct Places {
    libres: Mutex<usize>,
    liberee: Condvar,
}

impl Places {
    pub fn new(total: usize) -> Self {
        Self {
            libres: Mutex::new(total),
            liberee: Condvar::new(),
        }
    }

    /// Attend une place, l'occupe, et la rend à la fin du bloc.
    pub fn occuper<T>(&self, travail: impl FnOnce() -> T) -> T {
        {
            let mut libres = self
                .libres
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while *libres == 0 {
                libres = self
                    .liberee
                    .wait(libres)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            *libres = libres.saturating_sub(1);
        }
        let resultat = travail();
        {
            let mut libres = self
                .libres
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *libres = libres.saturating_add(1);
        }
        self.liberee.notify_one();
        resultat
    }
}

/// N'accepte que les adresses qu'un compte déclare.
///
/// # Elle n'implémente PAS `Debug`, et c'est voulu
///
/// Elle porte les empreintes des comptes. Un `{:?}` dans une trace les
/// déposerait dans un journal, un rapport d'incident, un ticket. Le plus sûr
/// est qu'il n'y ait rien à imprimer.
///
/// # C'est ici que le relais ouvert se ferme, aussi
///
/// C6 l'exclut, et `ams-session` refuse de se construire sans politique
/// justement pour qu'on ne puisse pas l'oublier. Celle-ci répond `RelayDenied`
/// pour tout ce qui n'est pas hébergé — **y compris quand la liste est vide**,
/// auquel cas le serveur n'accepte de courrier pour personne. C'est le seul
/// défaut qui ne relaie rien.
///
/// # ET LE RELAIS QUI S'OUVRE, LUI, EXIGE DEUX CHOSES
///
/// Depuis que la file de réémission existe, une adresse qui n'est pas d'ici peut
/// être acceptée. Il faut pour cela que **l'exploitant l'ait demandé**
/// ([`BoitesConnues::qui_relaie`]) ET que **ce pair-ci se soit authentifié**.
///
/// L'une sans l'autre est un relais ouvert : sans le drapeau, on émettrait sans
/// que personne l'ait décidé ; sans l'authentification, on émettrait pour
/// n'importe qui. La conjonction est écrite à UN SEUL endroit — deux
/// vérifications à deux endroits finissent par ne plus dire la même chose.
pub struct BoitesConnues {
    comptes: std::sync::Arc<crate::comptes::Comptes>,
    /// L'adresse du postmaster de ce serveur, composée une fois.
    postmaster: String,
    /// Les domaines que ce serveur DÉCLARE servir, en minuscules.
    ///
    /// # CE N'EST PAS UNE LISTE D'ACCEPTATION, C'EST UNE LISTE DE RESPONSABILITÉ
    ///
    /// Ce qui accepte reste le magasin de comptes, adresse par adresse. Cette
    /// liste-ci ne sert qu'à savoir COMMENT REFUSER : une adresse d'un domaine
    /// qu'on héberge et qui ne route nulle part est une boîte qui n'existe pas
    /// (`5.1.1`) ; une adresse d'ailleurs est un relais qu'on nie (`5.7.1`).
    ///
    /// La différence n'est pas cosmétique. Le rebond qui remonte à un être
    /// humain porte l'un ou l'autre : « cette personne n'est pas ici », qui
    /// invite à vérifier l'adresse, ou « vous n'avez pas le droit d'envoyer
    /// ici », qui envoie chercher une autorisation qui n'a jamais manqué.
    heberges: std::vec::Vec<String>,
    places: Places,
    /// L'exploitant a-t-il demandé qu'on émette ? Voir
    /// [`BoitesConnues::qui_relaie`].
    relaie: bool,
}

impl BoitesConnues {
    /// Construit la politique.
    ///
    /// `postmaster` est l'adresse que `<Postmaster>` désigne — composée par
    /// l'appelant, qui connaît le domaine annoncé.
    #[must_use]
    pub fn new(
        comptes: std::sync::Arc<crate::comptes::Comptes>,
        postmaster: String,
        heberges: &[String],
    ) -> Self {
        Self {
            comptes,
            postmaster,
            // **EN MINUSCULES UNE FOIS**, plutôt qu'à chaque `RCPT` : un nom de
            // domaine se compare sans égard à la casse (RFC 5321 §2.4), et le
            // faire à la volée referait le même travail pour chaque
            // destinataire de chaque message.
            heberges: heberges.iter().map(|nom| nom.to_lowercase()).collect(),
            places: Places::new(VERIFICATIONS_SIMULTANEES),
            // ON N'ÉMET PAS, SAUF DEMANDE EXPRESSE. Le constructeur ne prend pas
            // ce drapeau : un argument booléen de plus se passe à l'envers sans
            // que le compilateur bronche, et celui-ci ouvre un relais.
            relaie: false,
        }
    }

    /// Ouvre l'émission vers l'extérieur, POUR LES COMPTES AUTHENTIFIÉS.
    ///
    /// # C'EST LA SEULE FAÇON D'OUVRIR CE RELAIS, ET ELLE SE VOIT
    ///
    /// Une politique se construit fermée. L'ouvrir demande d'appeler ceci, ce qui
    /// laisse une ligne à lire dans le démarrage du serveur — là où un champ posé
    /// dans un constructeur à sept arguments se serait glissé sans qu'on le
    /// remarque.
    ///
    /// **Elle n'ouvre rien à un pair anonyme** : `accepts_recipient` exige les
    /// deux, le drapeau ET l'authentification.
    #[must_use]
    pub fn qui_relaie(mut self) -> Self {
        self.relaie = true;
        self
    }

    /// Ce serveur se déclare-t-il responsable de ce domaine ?
    ///
    /// **La comparaison porte sur le domaine SEUL**, celui qui suit la dernière
    /// arobase. Une adresse sans arobase n'a pas de domaine, et n'est donc
    /// hébergée nulle part — la session l'a déjà refusée, et ce chemin est la
    /// ceinture de cette bretelle.
    fn est_heberge(&self, adresse: &str) -> bool {
        let Some((_, domaine)) = adresse.rsplit_once('@') else {
            return false;
        };
        self.heberges
            .iter()
            .any(|connu| connu.eq_ignore_ascii_case(domaine))
    }

    /// Y a-t-il des comptes ?
    ///
    /// **Ce n'est PAS « `AUTH` est-il annoncé »** : l'annonce demande aussi du
    /// chiffrement, et c'est l'appelant qui compose les deux. Le nom précédent
    /// disait `authentifie`, et le message de démarrage annonçait `AUTH PLAIN
    /// offert` sur un serveur en clair qui ne l'offrait pas.
    #[must_use]
    pub fn a_des_comptes(&self) -> bool {
        !self.comptes.vue().is_empty()
    }
}

impl Authenticator for BoitesConnues {
    /// # Deux précautions, et aucune n'est facultative
    ///
    /// 1. **`block_in_place`** : Argon2id est délibérément lent. L'exécuter sur
    ///    un fil de l'ordonnanceur y bloquerait toutes les autres connexions
    ///    pendant des dizaines de millisecondes. `block_in_place` sort le fil
    ///    courant de l'ordonnanceur, qui en promeut un autre — c'est déjà ce que
    ///    la remise Maildir fait pour ses `fsync`.
    /// 2. **Une borne sur le nombre de vérifications simultanées** : sans elle,
    ///    chaque connexion pourrait réclamer 19 Mio en même temps. Voir
    ///    [`VERIFICATIONS_SIMULTANEES`].
    ///
    /// Le reste — le compte inconnu qui coûte le même temps, l'identité
    /// d'autorisation étrangère qu'on refuse — vit dans `ams-auth`, qui est
    /// couvert à 100 %.
    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        tokio::task::block_in_place(|| {
            self.places
                .occuper(|| ams_auth::authenticate(&self.comptes.vue(), credentials))
        })
    }
}

impl Policy for BoitesConnues {
    /// # Ce n'est plus « le domaine est-il hébergé », mais « la boîte
    /// existe-t-elle »
    ///
    /// Accepter tout ce qui arrive dans un domaine hébergé faisait de ce serveur
    /// un **fourre-tout** : `n.importe.qui@example.com` était accepté, écrit sur
    /// le disque, et jamais lu par personne. C'est ainsi qu'on remplit un disque
    /// avec du courrier que rien n'attend.
    ///
    /// La liste des domaines hébergés n'a pas disparu : elle est vérifiée **au
    /// démarrage**, où chaque adresse de compte doit s'y rattacher. Ce qui était
    /// une seconde règle d'acceptation est devenu une déclaration contrôlée une
    /// fois, ce qui est exactement ce qu'elle voulait dire.
    fn accepts_recipient(&self, forward_path: &Path<'_>, submitter: bool) -> RecipientVerdict {
        let adresse = match forward_path {
            // RFC 5321 §4.1.1.3 : `<Postmaster>` sans domaine désigne le
            // postmaster de CE serveur. L'adresse composée vient de l'appelant,
            // qui la compose une fois — la session en fait autant de son côté
            // pour la remise, et les deux doivent dire la même chose.
            Path::Postmaster => self.postmaster.clone(),
            Path::Mailbox(boite) => format!(
                "{}@{}",
                String::from_utf8_lossy(boite.local_part().as_bytes()),
                String::from_utf8_lossy(boite.domain().as_bytes())
            ),
            // `<>` n'est pas un destinataire ; la session le refuse déjà, et ce
            // bras est la ceinture de cette bretelle.
            Path::Null => return RecipientVerdict::RejectPermanent,
        };

        if ams_auth::route(&self.comptes.vue(), adresse.as_bytes()).is_some() {
            return RecipientVerdict::Accept;
        }
        // **LES DEUX CONDITIONS, ET PAS UNE SEULE.** Le drapeau dit que cet
        // exploitant a demandé à émettre ; l'authentification dit que ce pair-ci
        // en a le droit. L'une sans l'autre est un relais ouvert : sans le
        // drapeau, on émettrait sans que personne l'ait décidé ; sans
        // l'authentification, on émettrait pour n'importe qui.
        //
        // Le `&&` est écrit ici, à un seul endroit, et c'est voulu : deux
        // vérifications à deux endroits finissent par ne plus dire la même chose.
        if self.relaie && submitter {
            return RecipientVerdict::Accept;
        }
        // **DEUX REFUS, ET ILS NE DISENT PAS LA MÊME CHOSE.** Les deux rendent
        // `550`, mais l'état étendu diffère — et c'est lui que le rapport de
        // non-remise porte jusqu'à un être humain.
        //
        // Ce bras rendait `RelayDenied` pour TOUT, y compris pour une adresse
        // d'un domaine qu'on héberge. Le pair recevait alors « Relay access
        // denied » (`5.7.1`) pour `inconnu@essai.test` : « vous n'avez pas le
        // droit d'envoyer ici », quand la vérité est « cette personne n'est pas
        // ici ». L'expéditeur cherchait une autorisation qui ne lui a jamais
        // manqué, au lieu de relire l'adresse.
        match self.est_heberge(&adresse) {
            true => RecipientVerdict::RejectPermanent,
            false => RecipientVerdict::RelayDenied,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BoitesConnues;
    use ams_auth::{Account, DUMMY_HASH};
    use ams_proto_smtp::{Command, Limits, Path};
    use ams_session::{Policy, RecipientVerdict};
    use std::sync::Arc;

    /// Le chemin d'un `RCPT TO:` réel, décodé par le codec.
    fn destinataire(ligne: &[u8]) -> Path<'_> {
        match Command::parse(ligne, &Limits::DEFAULT).expect("recevable") {
            Command::Rcpt { forward_path, .. } => forward_path,
            autre => panic!("attendu `RCPT`, obtenu {autre:?}"),
        }
    }

    fn politique(adresses: &[&str]) -> BoitesConnues {
        let comptes = if adresses.is_empty() {
            Vec::new()
        } else {
            vec![Account {
                login: String::from("jean"),
                hash: String::from(DUMMY_HASH),
                addresses: adresses.iter().map(|a| (*a).to_string()).collect(),
            }]
        };
        // Le chemin ne sert pas : cet essai ne modifie rien, il interroge.
        BoitesConnues::new(
            Arc::new(crate::comptes::Comptes::new(
                std::path::PathBuf::from("/nulle-part/comptes.bin"),
                comptes,
            )),
            String::from("postmaster@mail.example.com"),
            // Les deux domaines que ce serveur déclare servir. `ailleurs.example`
            // n'en est PAS, et c'est ce qui distingue les deux refus.
            &[
                String::from("example.com"),
                String::from("mail.example.com"),
            ],
        )
    }

    #[test]
    fn seule_une_adresse_declaree_est_acceptee() {
        // CE N'EST PLUS UN FOURRE-TOUT. Avant, tout ce qui arrivait dans un
        // domaine hébergé était accepté, écrit sur le disque, et jamais lu par
        // personne.
        let politique = politique(&["jean@example.com"]);
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@example.com>\r\n"), false),
            RecipientVerdict::Accept
        );
        // **UN DOMAINE QU'ON HÉBERGE : LA BOÎTE N'EXISTE PAS** (`5.1.1`), et
        // non un relais nié (`5.7.1`). Le rebond qui remonte à un humain porte
        // l'un ou l'autre, et « vous n'avez pas le droit d'envoyer ici » est
        // faux quand la vérité est « cette personne n'est pas ici ».
        assert_eq!(
            politique
                .accepts_recipient(&destinataire(b"RCPT TO:<personne@example.com>\r\n"), false),
            RecipientVerdict::RejectPermanent
        );
        assert_eq!(
            politique
                .accepts_recipient(&destinataire(b"RCPT TO:<jean@ailleurs.example>\r\n"), false),
            RecipientVerdict::RelayDenied
        );
    }

    #[test]
    fn la_comparaison_ignore_la_casse_des_deux_cotes() {
        let politique = politique(&["Jean@Example.COM"]);
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@example.com>\r\n"), false),
            RecipientVerdict::Accept
        );
    }

    #[test]
    fn le_postmaster_nu_suit_la_meme_regle_que_les_autres() {
        // RFC 5321 §4.5.1 : il DOIT être joignable, et c'est par là qu'on
        // signale qu'un serveur va mal. Mais l'accepter sans boîte reviendrait à
        // dire `250` pour un message qu'on n'a nulle part où mettre : le serveur
        // avertit au démarrage plutôt que de mentir à chaque message.
        // Et le refus dit LA BOÎTE, non le relais : `<Postmaster>` désigne le
        // postmaster de CE serveur, dont le domaine est évidemment le nôtre.
        // Répondre « Relay access denied » à qui écrit à notre propre postmaster
        // serait absurde.
        let sans = politique(&["jean@example.com"]);
        assert_eq!(
            sans.accepts_recipient(&destinataire(b"RCPT TO:<Postmaster>\r\n"), false),
            RecipientVerdict::RejectPermanent
        );

        let avec = politique(&["postmaster@mail.example.com"]);
        assert_eq!(
            avec.accepts_recipient(&destinataire(b"RCPT TO:<Postmaster>\r\n"), false),
            RecipientVerdict::Accept
        );
        // Et sous sa forme complète, évidemment.
        assert_eq!(
            avec.accepts_recipient(
                &destinataire(b"RCPT TO:<postmaster@mail.example.com>\r\n"),
                false
            ),
            RecipientVerdict::Accept
        );
    }

    #[test]
    fn sans_compte_rien_n_est_accepte() {
        // Le seul défaut qui ne relaie rien — et qui ne remplit aucun disque.
        let politique = politique(&[]);
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@example.com>\r\n"), false),
            RecipientVerdict::RejectPermanent
        );
        // Et hors de nos domaines, c'est bien un relais qu'on nie.
        assert_eq!(
            politique
                .accepts_recipient(&destinataire(b"RCPT TO:<jean@ailleurs.example>\r\n"), false),
            RecipientVerdict::RelayDenied
        );
        assert!(!politique.a_des_comptes());
    }

    #[test]
    fn un_chemin_nul_n_est_pas_un_destinataire() {
        let politique = politique(&[]);
        assert_eq!(
            politique.accepts_recipient(&Path::Null, false),
            RecipientVerdict::RejectPermanent
        );
    }

    #[test]
    fn la_politique_ne_se_debogue_pas_et_c_est_voulu() {
        // Ce test n'est qu'un commentaire exécutable : il n'y a rien à appeler,
        // puisque `Debug` n'existe pas. Elle porte les empreintes des comptes,
        // et un `{:?}` dans une trace les y déposerait — dans un journal, dans
        // un rapport d'incident, dans un ticket. Le plus sûr est qu'il n'y ait
        // rien à imprimer.
        assert!(politique(&["jean@example.com"]).a_des_comptes());
    }

    // ── Le relais, et les DEUX conditions qui l'ouvrent ─────────────────────

    /// **NI L'UNE NI L'AUTRE SEULE.**
    ///
    /// Sans le drapeau, on émettrait sans que personne l'ait décidé ; sans
    /// l'authentification, on émettrait pour n'importe qui. Ce test énumère les
    /// quatre cas plutôt que les deux qui arrangent.
    #[test]
    fn le_relais_exige_le_drapeau_et_l_authentification() {
        let ailleurs = destinataire(b"RCPT TO:<marie@ailleurs.example>\r\n");
        for (relaie, authentifie, attendu) in [
            (false, false, RecipientVerdict::RelayDenied),
            (false, true, RecipientVerdict::RelayDenied),
            (true, false, RecipientVerdict::RelayDenied),
            (true, true, RecipientVerdict::Accept),
        ] {
            let politique = politique(&["jean@example.com"]);
            let politique = if relaie {
                politique.qui_relaie()
            } else {
                politique
            };
            assert_eq!(
                politique.accepts_recipient(&ailleurs, authentifie),
                attendu,
                "drapeau {relaie}, authentifié {authentifie}"
            );
        }
    }

    /// **UNE ADRESSE D'ICI RESTE D'ICI**, relais ou non.
    ///
    /// Elle ne doit surtout pas partir sur le réseau parce qu'on a ouvert
    /// l'émission : elle a une boîte, et c'est là qu'elle va.
    #[test]
    fn une_adresse_d_ici_ne_passe_pas_par_le_relais() {
        let politique = politique(&["jean@example.com"]).qui_relaie();
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@example.com>\r\n"), true),
            RecipientVerdict::Accept
        );
        // Et sans authentification non plus : recevoir n'a jamais demandé de
        // s'authentifier, et l'exiger fermerait le courrier entrant.
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@example.com>\r\n"), false),
            RecipientVerdict::Accept
        );
    }

    /// **UN CHEMIN NUL N'EST PAS UN DESTINATAIRE**, même pour un déposant
    /// authentifié sur un serveur qui relaie.
    #[test]
    fn le_relais_n_accepte_pas_un_chemin_nul() {
        let politique = politique(&["jean@example.com"]).qui_relaie();
        assert_eq!(
            politique.accepts_recipient(&Path::Null, true),
            RecipientVerdict::RejectPermanent
        );
    }
}
