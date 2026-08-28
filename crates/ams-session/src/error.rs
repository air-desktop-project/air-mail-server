//! Ce que la session refuse à son APPELANT.

use core::fmt;

/// Ce que la session refuse à son appelant.
///
/// # Ces erreurs ne sont pas des refus de protocole
///
/// Un pair qui envoie n'importe quoi obtient une **réponse** — 500, 503, 538 —
/// jamais une erreur. Ces variantes-ci désignent une faute de l'appelant : un
/// tampon trop petit, une commande soumise alors que la session attend autre
/// chose. Confondre les deux ferait fermer une connexion pour une commande
/// invalide, là où le protocole demande de répondre et de continuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// L'encodage de la réponse a échoué.
    ///
    /// En pratique, uniquement
    /// [`BufferTooSmall`](ams_proto_smtp::Error::BufferTooSmall) : la session ne
    /// compose jamais une réponse que l'encodeur refuserait — elle n'y met que
    /// des textes constants ou son propre domaine, déjà validé. Le fuzz le
    /// vérifie plutôt que de le supposer.
    Reply(ams_proto_smtp::Error),

    /// Une commande a été soumise alors que la session n'attend pas de commande.
    ///
    /// Après `354`, elle attend le message ; après un `AUTH` accepté, elle attend
    /// que l'appelant conduise l'échange SASL et en rende le verdict.
    NotInCommandPhase,

    /// Une commande a été soumise après `QUIT`.
    ///
    /// L'appelant devait fermer la connexion en voyant
    /// [`Action::Close`](crate::Action::Close).
    SessionClosed,

    /// Des octets de message ont été fournis hors de la phase de données.
    NotInDataPhase,

    /// Une réponse SASL a été fournie alors qu'aucun défi n'est en attente.
    ///
    /// L'appelant n'a pas vu passer
    /// [`Action::ReadAuthResponse`](crate::Action::ReadAuthResponse), ou l'a vue
    /// deux fois. Distinct de [`Error::NotInCommandPhase`] : ce n'est pas une
    /// commande de trop, c'est une réponse qui n'a pas de question.
    NotInAuthExchange,

    /// Les données du message ont été refusées.
    ///
    /// Le pair a envoyé quelque chose que la grammaire n'accepte pas — un `CR`
    /// isolé, une ligne trop longue, un message trop gros. L'appelant doit
    /// **cesser de lire** et appeler
    /// [`on_data_settled`](crate::SmtpSession::on_data_settled), qui rendra la
    /// réponse correspondante. **Le verdict qu'il y passera ne sera pas
    /// consulté** : un message refusé par la grammaire ne peut pas être accepté
    /// par l'appelant.
    DataRefused,

    /// Le domaine annoncé par le serveur n'est pas un domaine.
    ///
    /// Refusé à la **construction** : un serveur qui se nomme mal le fait dans
    /// chaque bannière et chaque `EHLO`, et le découvrir en production coûte plus
    /// cher que de refuser de démarrer.
    ServerDomainInvalid(ams_proto_smtp::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Reply(cause) => write!(f, "réponse inencodable : {cause}"),
            Error::NotInCommandPhase => {
                f.write_str("la session n'attend pas de commande à cet instant")
            }
            Error::SessionClosed => f.write_str("la session est close depuis `QUIT`"),
            Error::NotInDataPhase => {
                f.write_str("des données ont été fournies hors de la phase de données")
            }
            Error::NotInAuthExchange => {
                f.write_str("une réponse SASL a été fournie hors d'un échange d'authentification")
            }
            Error::DataRefused => {
                f.write_str("les données du message sont refusées ; conclure la transaction")
            }
            Error::ServerDomainInvalid(cause) => {
                write!(f, "le domaine du serveur est invalide : {cause}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    const TOUTES: &[Error] = &[
        Error::Reply(ams_proto_smtp::Error::BufferTooSmall { needed: 40 }),
        Error::NotInCommandPhase,
        Error::SessionClosed,
        Error::NotInDataPhase,
        Error::NotInAuthExchange,
        Error::DataRefused,
        Error::ServerDomainInvalid(ams_proto_smtp::Error::MalformedDomain),
    ];

    #[test]
    fn chaque_variante_s_affiche_et_dit_quelque_chose() {
        for erreur in TOUTES {
            let texte = std::format!("{erreur}");
            assert!(
                texte.len() > 10,
                "{erreur:?} : « {texte} » est trop laconique"
            );
        }
    }

    #[test]
    fn les_variantes_sont_deux_a_deux_distinctes() {
        for (rang, erreur) in TOUTES.iter().enumerate() {
            for (autre_rang, autre) in TOUTES.iter().enumerate() {
                if rang == autre_rang {
                    assert_eq!(erreur, autre);
                } else {
                    assert_ne!(erreur, autre);
                }
            }
        }
    }

    #[test]
    fn une_erreur_se_copie_et_se_debogue() {
        let erreur = Error::SessionClosed;
        let copie = erreur;
        assert_eq!(copie, erreur);
        assert!(!std::format!("{erreur:?}").is_empty());
    }
}
