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
    /// Ouvre la remise vers **un** destinataire accepté.
    ///
    /// Appelée une fois par destinataire, juste avant le premier
    /// [`Delivery::append`], et avec l'adresse sous sa forme `locale@domaine` —
    /// le `<Postmaster>` nu a déjà été résolu par la session, qui est le seul
    /// endroit à connaître le domaine du serveur.
    ///
    /// # Pourquoi ici, et pas au `RCPT`
    ///
    /// Parce que la boucle ne voit pas les `RCPT` : elle ne connaît aucun
    /// protocole. C'est la session qui retient les destinataires acceptés — et
    /// qui les oublie sur `RSET`, sur `EHLO`, à la fin d'un message et après une
    /// poignée de main TLS. Une liste tenue ici survivrait à ces cinq
    /// événements, et livrerait le message suivant aux destinataires du
    /// précédent.
    ///
    /// # Errors
    ///
    /// [`DeliveryFailure`] — par exemple une boîte qu'on ne peut pas ouvrir. La
    /// boucle refuse alors le message entier : accepter un message qu'on ne
    /// peut remettre qu'à une partie des destinataires obligerait à en avertir
    /// l'expéditeur, ce qui demande une file d'attente qui n'existe pas.
    fn add_recipient(&mut self, address: &[u8]) -> Result<(), DeliveryFailure>;

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
