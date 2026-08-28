//! La décision que la session ne prend pas.

use ams_proto_smtp::Path;
use ams_sasl::Credentials;

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

    /// Ces identifiants ouvrent-ils une session ?
    ///
    /// # Pourquoi CELUI-CI a un défaut alors que l'autre n'en a pas
    ///
    /// Ce n'est pas une inconséquence, c'est le SENS du défaut qui diffère. Pour
    /// les destinataires, le seul défaut concevable serait « accepter », c'est-à-
    /// dire un relais ouvert : il n'y en a donc pas. Ici, le défaut REFUSE, et un
    /// défaut qui refuse ne peut ouvrir aucune porte. Une politique qui oublie
    /// d'implémenter cette méthode alors que sa configuration annonce `AUTH`
    /// obtient un serveur où personne ne peut se connecter — c'est bruyant,
    /// immédiat, et sans danger.
    ///
    /// # Ce qu'elle doit faire, et ce qu'elle ne doit pas
    ///
    /// La comparaison du mot de passe doit être **à temps constant** : une
    /// comparaison qui s'arrête au premier octet différent se mesure, et se
    /// mesure d'autant mieux qu'on peut la répéter. Les identifiants arrivent
    /// **tels que le pair les a envoyés** — ni normalisés, ni validés en UTF-8
    /// (voir [`ams_sasl`] pour ce que SASLprep aurait changé).
    ///
    /// Pure, comme l'autre : pas de requête à un annuaire, pas de lecture de
    /// fichier. Une décision qui attend est une décision qu'un pair peut faire
    /// attendre.
    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        let _ = credentials;
        false
    }
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

    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        (**self).authenticate(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::{Policy, RecipientVerdict};
    use ams_proto_smtp::Path;
    use ams_sasl::Credentials;

    /// Une politique qui rend toujours le même verdict, **et n'implémente pas
    /// `authenticate`** : c'est tout l'objet de l'un des tests ci-dessous.
    struct Toujours(RecipientVerdict);

    impl Policy for Toujours {
        fn accepts_recipient(&self, _forward_path: &Path<'_>) -> RecipientVerdict {
            self.0
        }
    }

    /// Des identifiants qui seraient justes, si quelqu'un les connaissait.
    const IDENTIFIANTS: Credentials<'static> = Credentials {
        authorization_identity: b"",
        authentication_identity: b"jean",
        password: b"ouvre-toi",
    };

    /// Interroge l'authentification **par générique**, pour la même raison.
    fn authentifier<P: Policy>(politique: P) -> bool {
        politique.authenticate(&IDENTIFIANTS)
    }

    #[test]
    fn le_defaut_refuse_tout_le_monde() {
        // UNE POLITIQUE QUI N'IMPLÉMENTE RIEN N'OUVRE RIEN. C'est ce qui rend ce
        // défaut acceptable là où celui des destinataires ne le serait pas :
        // celui-ci ne peut ouvrir aucune porte, il ne peut que les fermer toutes.
        assert!(!authentifier(Toujours(RecipientVerdict::Accept)));
    }

    #[test]
    fn une_reference_partagee_authentifie_comme_sa_cible() {
        // Sans l'implémentation générique, une politique passée par référence
        // retomberait sur le défaut — c'est-à-dire refuserait tout le monde,
        // en silence, alors que sa cible sait ouvrir.
        struct Ouvre;
        impl Policy for Ouvre {
            fn accepts_recipient(&self, _forward_path: &Path<'_>) -> RecipientVerdict {
                RecipientVerdict::Accept
            }
            fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
                credentials.authentication_identity == b"jean"
            }
        }
        let politique = Ouvre;
        assert!(authentifier(&politique));
        assert!(authentifier(Ouvre));
        // Et la MÊME référence sert les deux méthodes : c'est ce qu'une boucle
        // qui partage une table de domaines entre mille sessions demande.
        assert_eq!(interroger(&politique), RecipientVerdict::Accept);
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
