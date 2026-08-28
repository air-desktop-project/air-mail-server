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
