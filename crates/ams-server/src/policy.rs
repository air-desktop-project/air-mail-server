//! Qui a le droit de recevoir du courrier ici.

use ams_proto_smtp::Path;
use ams_session::{Policy, RecipientVerdict};

/// N'accepte que les domaines hébergés.
///
/// # C'est ici que le relais ouvert se ferme
///
/// C6 l'exclut, et `ams-session` refuse de se construire sans politique
/// justement pour qu'on ne puisse pas l'oublier. Celle-ci répond `RelayDenied`
/// pour tout ce qui n'est pas hébergé — **y compris quand la liste est vide**,
/// auquel cas le serveur n'accepte de courrier pour personne. C'est le seul
/// défaut qui ne relaie rien.
#[derive(Debug, Clone)]
pub struct DomainesHeberges {
    domaines: Vec<Vec<u8>>,
}

impl DomainesHeberges {
    /// Construit la politique.
    #[must_use]
    pub fn new(domaines: &[String]) -> Self {
        Self {
            domaines: domaines
                .iter()
                .map(|domaine| domaine.as_bytes().to_vec())
                .collect(),
        }
    }
}

impl Policy for DomainesHeberges {
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
        let politique = DomainesHeberges::new(&[String::from("example.com")]);
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
        let politique = DomainesHeberges::new(&[String::from("Example.COM")]);
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@example.com>\r\n")),
            RecipientVerdict::Accept
        );
    }

    #[test]
    fn postmaster_est_toujours_accepte() {
        // RFC 5321 §4.5.1 : c'est par là qu'on signale qu'un serveur va mal.
        let politique = DomainesHeberges::new(&[]);
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<Postmaster>\r\n")),
            RecipientVerdict::Accept
        );
    }

    #[test]
    fn sans_domaine_heberge_rien_n_est_relaye() {
        // Le seul défaut qui ne relaie rien.
        let politique = DomainesHeberges::new(&[]);
        assert_eq!(
            politique.accepts_recipient(&destinataire(b"RCPT TO:<jean@example.com>\r\n")),
            RecipientVerdict::RelayDenied
        );
    }

    #[test]
    fn un_chemin_nul_n_est_pas_un_destinataire() {
        let politique = DomainesHeberges::new(&[]);
        assert_eq!(
            politique.accepts_recipient(&Path::Null),
            RecipientVerdict::RejectPermanent
        );
        assert!(!format!("{politique:?}").is_empty());
    }
}
