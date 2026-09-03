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

    /// Le compte qui s'est authentifié, quand il y en a un.
    ///
    /// Appelée juste après [`Delivery::begin`], et **seulement si un pair s'est
    /// authentifié**. Une transaction anonyme n'appelle pas ceci — et une remise
    /// qui ne l'a pas vue ne doit rien émettre au nom de personne.
    ///
    /// # POURQUOI LE NOM, ET NON UN BOOLÉEN
    ///
    /// « Authentifié » suffit à décider si l'on relaie. Il ne suffit pas à
    /// décider au nom de QUI : un compte qui écrit `From: patron@example.com`
    /// obtiendrait, sans cela, notre signature DKIM sur une adresse qui n'est
    /// pas la sienne — c'est-à-dire un hameçonnage interne que nous aurions
    /// authentifié.
    ///
    /// **LE DÉFAUT L'OUBLIE**, ce qui ne peut que refuser davantage : une remise
    /// qui ne retient rien ne saura affirmer aucune identité.
    fn submitter(&mut self, login: &[u8]) {
        let _ = login;
    }

    /// Combien d'octets réserver en tête pour un en-tête de trace.
    ///
    /// Appelée **avant** le premier [`Delivery::add_recipient`], et suivie d'un
    /// [`Delivery::trace`] avant [`Delivery::finish`].
    ///
    /// # POURQUOI RÉSERVER, PLUTÔT QU'ÉCRIRE DANS L'ORDRE
    ///
    /// Un en-tête de trace doit précéder ce que le pair écrit. Or DKIM ne se
    /// juge qu'une fois le CORPS entier lu — son condensat porte dessus — et
    /// DMARC en dépend : le verdict arrive APRÈS que le message a été diffusé.
    ///
    /// Rassembler le message coûterait sa taille en mémoire par connexion, ce
    /// que C3 interdit ; le recopier coûterait une seconde écriture disque par
    /// message. Réserver coûte une taille FIXE, une fois.
    ///
    /// **LE DÉFAUT NE RÉSERVE RIEN**, et ne peut donc que priver d'un en-tête —
    /// jamais en fabriquer un faux.
    fn reserve_trace(&mut self, combien: usize) {
        let _ = combien;
    }

    /// L'en-tête de trace, une fois les verdicts connus.
    ///
    /// **IL DOIT FAIRE EXACTEMENT la taille réservée** : un octet de trop
    /// écraserait le premier en-tête du pair, un de moins laisserait un trou au
    /// milieu du message.
    fn trace(&mut self, entete: &[u8]) {
        let _ = entete;
    }

    /// **Met ce message de côté** : une politique DMARC le met en quarantaine.
    ///
    /// Appelée entre le dernier [`Delivery::append`] et [`Delivery::finish`] —
    /// le verdict dépend de DKIM, dont la signature couvre le corps, et n'existe
    /// donc pas plus tôt.
    ///
    /// # ELLE REND CE QU'ELLE A FAIT, ET NON CE QU'ON LUI A DEMANDÉ
    ///
    /// `true` seulement si la remise a bien un endroit où mettre ce message de
    /// côté. C'est ce que le rapport agrégé écrira (RFC 7489 §7.2) : un message
    /// que `p=quarantine` visait et que ce serveur a remis dans la boîte de
    /// réception se rapporte `none`, parce que c'est la vérité. Écrire
    /// `quarantine` ferait croire à un domaine qu'il est protégé là où il ne
    /// l'est pas.
    ///
    /// **LE DÉFAUT NE MET RIEN DE CÔTÉ, ET LE DIT.**
    fn quarantine(&mut self) -> bool {
        false
    }

    /// L'identifiant d'enveloppe que le déposant a donné (RFC 3461 §4.4).
    ///
    /// Appelée après [`Delivery::begin`], et seulement si le pair en a donné un.
    /// Il ressort tel quel dans le rapport, en `Original-Envelope-Id` : c'est ce
    /// qui permet au déposant de rattacher un rapport à son envoi sans lire le
    /// message.
    ///
    /// **LE DÉFAUT L'OUBLIE**, et ne peut donc que priver d'un champ — jamais en
    /// fabriquer un faux.
    fn envelope_id(&mut self, id: &[u8]) {
        let _ = id;
    }

    /// Ce que le DERNIER destinataire accepté a demandé (RFC 3461 §4.1, §4.2).
    ///
    /// Appelée juste après un [`Delivery::add_recipient`] qui a réussi.
    ///
    /// # POURQUOI PAR DESTINATAIRE
    ///
    /// Deux `RCPT` d'une même transaction peuvent demander deux choses
    /// différentes — l'un le silence, l'autre un rapport de succès —, et c'est
    /// tout l'objet de §4.1. Une seule valeur par transaction ferait honorer
    /// celle du dernier `RCPT` pour tout le monde.
    ///
    /// **LE DÉFAUT NE RETIENT RIEN**, ce qui vaut le comportement de §4.1 en
    /// l'absence du paramètre : un rapport en cas d'échec, et rien d'autre.
    fn recipient_report(&mut self, never: bool, on_success: bool, on_delay: bool, original: &[u8]) {
        let _ = (never, on_success, on_delay, original);
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

    /// Reçoit un en-tête qui ne vaut QUE pour la remise finale.
    ///
    /// # POURQUOI CE N'EST PAS UN `append`
    ///
    /// Une transaction peut à la fois remettre ici et relayer ailleurs. Ce que
    /// [`Delivery::append`] reçoit va aux DEUX — c'est ce qu'il faut pour la
    /// trace `Received:`, qu'un relais doit poser aussi.
    ///
    /// Le `Return-Path:` de §4.4, lui, appartient au serveur qui fait la remise
    /// FINALE. L'envoyer avec un message qu'on relaie ferait porter au saut
    /// suivant un en-tête de notre main, au-dessus duquel il posera le sien : le
    /// message arriverait avec deux, et le second serait périmé.
    ///
    /// **LE DÉFAUT L'ÉCRIT COMME LE RESTE**, ce qui vaut pour une remise qui
    /// n'est que locale — le cas le plus courant, et celui où la distinction ne
    /// change rien.
    ///
    /// # Errors
    ///
    /// [`DeliveryFailure`], comme [`Delivery::append`].
    fn append_final(&mut self, chunk: &[u8]) -> Result<(), DeliveryFailure> {
        self.append(chunk)
    }

    /// Le message est complet et doit être pris en charge.
    ///
    /// # Errors
    ///
    /// [`DeliveryFailure`].
    fn finish(&mut self) -> Result<(), DeliveryFailure>;

    /// La transaction est abandonnée : rien ne doit en subsister.
    fn abort(&mut self);
}
