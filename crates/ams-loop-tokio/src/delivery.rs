//! Où va le message.

/// Pourquoi une remise a échoué.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryFailure {
    /// Définitif : réessayer à l'identique n'a aucun sens.
    Permanent,
    /// Temporaire : réessayer plus tard en a un.
    Temporary,
}

/// Ce qui reçoit un message.
///
/// # Elle est appelée depuis la tâche de connexion, et ne doit pas s'attarder
///
/// Un `append` qui bloque bloque l'ordonnanceur, et mille connexions qui bloquent
/// ensemble sont un déni de service. Une écriture Maildir — un tampon, puis un
/// `rename()` — est assez brève pour cela ; tout ce qui l'est moins doit passer
/// par `spawn_blocking`, et c'est à l'implémentation de le savoir.
///
/// # Elle voit les octets DÉ-ÉCHAPPÉS
///
/// Les points échappés ont déjà été retirés et le terminateur n'est pas transmis :
/// ce qui arrive est le message, pas ce qui est passé sur le fil. Le ré-émettre
/// demandera de le ré-échapper.
pub trait Delivery {
    /// Reçoit un morceau du message.
    ///
    /// # Errors
    ///
    /// [`DeliveryFailure`]. La boucle **continue alors de lire** jusqu'à la fin du
    /// message avant de répondre : s'arrêter en cours laisserait la connexion
    /// désynchronisée, et le reste du message serait lu comme des commandes.
    fn append(&mut self, chunk: &[u8]) -> Result<(), DeliveryFailure>;

    /// Le message est complet et doit être pris en charge.
    ///
    /// # Errors
    ///
    /// [`DeliveryFailure`].
    fn finish(&mut self) -> Result<(), DeliveryFailure>;

    /// La transaction est abandonnée : rien ne doit en subsister.
    fn abort(&mut self);
}
