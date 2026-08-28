//! Qui a le droit de recevoir du courrier ici.

use std::sync::{Condvar, Mutex};

use ams_auth::Account;
use ams_proto_smtp::Path;
use ams_sasl::Credentials;
use ams_session::{Policy, RecipientVerdict};

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
struct Places {
    libres: Mutex<usize>,
    liberee: Condvar,
}

impl Places {
    fn new(total: usize) -> Self {
        Self {
            libres: Mutex::new(total),
            liberee: Condvar::new(),
        }
    }

    /// Attend une place, l'occupe, et la rend à la fin du bloc.
    fn occuper<T>(&self, travail: impl FnOnce() -> T) -> T {
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

/// N'accepte que les domaines hébergés.
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
pub struct DomainesHeberges {
    domaines: Vec<Vec<u8>>,
    comptes: Vec<Account>,
    places: Places,
}

impl DomainesHeberges {
    /// Construit la politique.
    #[must_use]
    pub fn new(domaines: &[String], comptes: Vec<Account>) -> Self {
        Self {
            domaines: domaines
                .iter()
                .map(|domaine| domaine.as_bytes().to_vec())
                .collect(),
            comptes,
            places: Places::new(VERIFICATIONS_SIMULTANEES),
        }
    }

    /// Y a-t-il quelqu'un à qui répondre oui ?
    #[must_use]
    pub fn authentifie(&self) -> bool {
        !self.comptes.is_empty()
    }
}

impl Policy for DomainesHeberges {
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
                .occuper(|| ams_auth::authenticate(&self.comptes, credentials))
        })
    }

    fn accepts_recipient(&self, forward_path: &Path<'_>) -> RecipientVerdict {
        match forward_path {
            // RFC 5321 §4.5.1 : tout serveur DOIT accepter le courrier destiné à
            // `<Postmaster>`. C'est par là qu'on signale qu'un serveur va mal, et
            // le refuser rendrait ce signal impossible.
            Path::Postmaster => RecipientVerdict::Accept,
            Path::Mailbox(boite) => {
                // Les noms de domaine sont insensibles à la casse.
                let domaine = boite.domain().as_bytes();
                if self
                    .domaines
                    .iter()
                    .any(|heberge| heberge.eq_ignore_ascii_case(domaine))
                {
                    RecipientVerdict::Accept
                } else {
                    RecipientVerdict::RelayDenied
                }
            }
            // `<>` n'est pas un destinataire ; la session le refuse déjà, et ce
            // bras est la ceinture de cette bretelle.
            Path::Null => RecipientVerdict::RejectPermanent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DomainesHeberges;
    use ams_proto_smtp::{Command, Limits, Path};
    use ams_session::{Policy, RecipientVerdict};

    /// Le chemin d'un `RCPT TO:` réel, décodé par le codec.
    fn destinataire(ligne: &[u8]) -> Path<'_> {
        match Command::parse(ligne, &Limits::DEFAULT).expect("recevable") {
            Command::Rcpt { forward_path, .. } => forward_path,
            autre => panic!("attendu `RCPT`, obtenu {autre:?}"),
        }
    }

    #[test]
    fn seuls_les_domaines_heberges_sont_acceptes() {
        let politique = DomainesHeberges::new(&[String::from("example.com")], Vec::new());
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@example.com>\r\n")),
            RecipientVerdict::Accept
        );
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@ailleurs.example>\r\n")),
            RecipientVerdict::RelayDenied
        );
    }

    #[test]
    fn la_comparaison_de_domaine_ignore_la_casse() {
        let politique = DomainesHeberges::new(&[String::from("Example.COM")], Vec::new());
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@example.com>\r\n")),
            RecipientVerdict::Accept
        );
    }

    #[test]
    fn postmaster_est_toujours_accepte() {
        // RFC 5321 §4.5.1 : c'est par là qu'on signale qu'un serveur va mal.
        let politique = DomainesHeberges::new(&[], Vec::new());
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<Postmaster>\r\n")),
            RecipientVerdict::Accept
        );
    }

    #[test]
    fn sans_domaine_heberge_rien_n_est_relaye() {
        // Le seul défaut qui ne relaie rien.
        let politique = DomainesHeberges::new(&[], Vec::new());
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@example.com>\r\n")),
            RecipientVerdict::RelayDenied
        );
    }

    #[test]
    fn un_chemin_nul_n_est_pas_un_destinataire() {
        let politique = DomainesHeberges::new(&[], Vec::new());
        assert_eq!(
            politique.accepts_recipient(&Path::Null),
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
        let politique = DomainesHeberges::new(&[], Vec::new());
        assert!(!politique.authentifie());
    }
}
