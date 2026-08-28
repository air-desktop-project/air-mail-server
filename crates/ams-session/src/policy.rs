//! La décision que la session ne prend pas.

use ams_proto_smtp::Path;

/// Ce qu'un serveur décide d'un destinataire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientVerdict {
    /// Accepté.
    Accept,
    /// Refusé **définitivement** : la boîte n'existe pas, ou n'accepte rien.
    RejectPermanent,
    /// Refusé **pour l'instant** : réessayer plus tard a un sens.
    RejectTemporary,
    /// Ce serveur ne relaie pas vers ce destinataire.
    ///
    /// Distinct de [`RecipientVerdict::RejectPermanent`] alors que les deux
    /// rendent `550` : un expéditeur légitime qui se trompe de serveur doit
    /// pouvoir le comprendre sans lire les journaux d'en face.
    RelayDenied,
}

/// Qui décide des destinataires.
///
/// # Pourquoi ce trait existe, et pourquoi il n'est pas facultatif
///
/// Un serveur qui accepterait tout destinataire est un **relais ouvert**, que C6
/// exclut. La session ne prend pas cette décision — elle n'en a pas les moyens,
/// n'ayant ni table de domaines ni comptes — et elle ne l'invente donc pas : elle
/// **exige** qu'on la lui fournisse. On ne peut pas construire une session sans
/// politique, et c'est ce qui rend le relais ouvert inexprimable plutôt
/// qu'improbable.
///
/// # La décision doit être PURE, et rendue immédiatement
///
/// Pas d'entrée-sortie : ni requête LDAP, ni base de données, ni résolution DNS.
/// C1 l'interdit, et ce n'est pas la seule raison — une décision qui attend est
/// une décision qu'un pair peut faire attendre, et cent connexions qui attendent
/// ensemble sont un déni de service. La table des domaines et des boîtes doit
/// être en mémoire au moment où `RCPT` arrive.
pub trait Policy {
    /// Ce destinataire est-il acceptable ?
    ///
    /// Appelé une fois par `RCPT TO:`, avec le chemin **déjà validé**
    /// grammaticalement.
    fn accepts_recipient(&self, forward_path: &Path<'_>) -> RecipientVerdict;
}

/// Une référence partagée est une politique.
///
/// Une boucle qui sert mille connexions n'a qu'UNE table de domaines : sans cette
/// implémentation, chaque session en exigerait une copie, ou l'appelant devrait
/// écrire ce même relais à la main.
impl<T: Policy + ?Sized> Policy for &T {
    fn accepts_recipient(&self, forward_path: &Path<'_>) -> RecipientVerdict {
        (**self).accepts_recipient(forward_path)
    }
}

#[cfg(test)]
mod tests {
    use super::{Policy, RecipientVerdict};
    use ams_proto_smtp::Path;

    struct Toujours(RecipientVerdict);

    impl Policy for Toujours {
        fn accepts_recipient(&self, _forward_path: &Path<'_>) -> RecipientVerdict {
            self.0
        }
    }

    /// Interroge une politique **par générique**.
    ///
    /// L'appel direct sur une référence ne prouverait rien : l'auto-déréférence
    /// irait chercher l'implémentation concrète, et l'implémentation générique
    /// resterait morte. Il faut que `P` VAILLE `&Toujours` pour l'emprunter.
    fn interroger<P: Policy>(politique: P) -> RecipientVerdict {
        politique.accepts_recipient(&Path::Null)
    }

    #[test]
    fn une_reference_partagee_est_une_politique() {
        let politique = Toujours(RecipientVerdict::RelayDenied);
        assert_eq!(interroger(&politique), RecipientVerdict::RelayDenied);
        // Et la politique elle-même en est une, évidemment.
        assert_eq!(
            interroger(Toujours(RecipientVerdict::Accept)),
            RecipientVerdict::Accept
        );
    }
}
