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
    /// Le message qui commence, et l'adresse à laquelle en rendre compte.
    ///
    /// Appelée **une fois par transaction**, avant le premier
    /// [`Delivery::add_recipient`]. `return_path` est le `MAIL FROM:` tel que le
    /// pair l'a écrit, ou `None` pour un chemin nul — une notification, qui n'en
    /// engendre pas une autre.
    ///
    /// # LE DÉFAUT NE FAIT RIEN, ET IL NE PEUT QUE FERMER DES PORTES
    ///
    /// Une remise qui ne fait que déposer localement n'a que faire d'un chemin
    /// de retour : c'est le pair d'en face qui rend compte, pas nous. Ne pas
    /// l'implémenter revient donc à ne rien pouvoir mettre en file de
    /// réémission — puisqu'on ne saurait à qui rendre compte d'un échec — et
    /// c'est le bon sens du défaut.
    fn begin(&mut self, return_path: Option<&[u8]>) {
        let _ = return_path;
    }

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
    /// boucle refuse alors le message ENTIER.
    ///
    /// # ET ELLE LE REFUSE ENCORE, MAINTENANT QUE LA FILE EXISTE
    ///
    /// L'argument était que rendre compte à l'expéditeur d'une remise partielle
    /// demanderait une file d'attente. Elle existe depuis le 2026-09-01, et ce
    /// n'est plus l'argument — mais la réponse ne change pas, pour une raison
    /// meilleure : **la file sert à ce qui SORT**, et un `4yz` rendu au pair
    /// laisse la responsabilité du message chez lui, où elle est bien. Prendre
    /// le message en charge pour le rendre en partie ferait porter à ce serveur
    /// un échec que le pair sait mieux traiter — c'est LUI qui a l'expéditeur au
    /// bout du fil.
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
