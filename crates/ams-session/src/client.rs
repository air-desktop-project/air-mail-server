//! La session SMTP **CLIENTE** (RFC 5321), sans entrée-sortie.
//!
//! # Émettre n'est pas recevoir à l'envers
//!
//! Le reste de cette crate tient la session d'un serveur : elle lit des
//! commandes et compose des réponses. Émettre du courrier est le geste
//! symétrique — écrire des commandes, lire des réponses — et il a ses propres
//! décisions, dont aucune ne se déduit du côté serveur :
//!
//! - **Que faire d'un `EHLO` refusé ?** Un serveur de la RFC 821 répond `500`,
//!   et il faut alors se rabattre sur `HELO` (§3.2). Ne pas le faire couperait
//!   du courrier vers des machines qui fonctionnent.
//! - **Que faire d'un destinataire refusé quand un autre est accepté ?** On
//!   continue : refuser tout le message parce qu'une adresse sur cinq est
//!   inconnue ferait perdre les quatre autres.
//! - **Quand un échec vaut-il la peine d'être réessayé ?** `4yz` oui, `5yz`
//!   non — et confondre les deux fait soit perdre du courrier, soit harceler un
//!   serveur qui a dit non.
//!
//! # ON N'ÉCRIT PAS DANS UNE COMMANDE CE QU'ON N'A PAS REGARDÉ
//!
//! L'adresse à laquelle on écrit ne vient pas toujours de nous. Celle d'un
//! rapport DMARC, par exemple, est publiée par le domaine qu'on rapporte —
//! c'est-à-dire, quand cela compte, par celui qui usurpe. Y glisser un `CRLF`
//! écrirait des commandes à notre place sur notre propre connexion.
//!
//! [`SmtpClient::new`] refuse donc toute adresse qui n'est pas de l'ASCII
//! imprimable sans espace ni chevrons. Ce n'est pas une validation d'adresse —
//! ce serait le travail d'ailleurs — c'est la garantie que rien de ce qu'on
//! écrit sur le fil ne vient d'être dicté par autrui.

use ams_proto_smtp::{
    Class, Code, ENVID_MAX, ORCPT_MAX, Reply, Status, XTEXT_GROWTH, encode_xtext,
};

use crate::Error;

/// La taille de tampon que cette session demande pour une commande.
///
/// La plus longue est `RCPT TO:<…> NOTIFY=… ORCPT=rfc822;…` : un chemin de 256
/// octets (RFC 5321 §4.5.3.1), onze octets d'enveloppe, et une adresse d'origine
/// de RFC 3461 §4.2 **RÉ-ENCODÉE EN XTEXT**, qui peut tripler.
///
/// # LE TRIPLEMENT N'EST PAS THÉORIQUE
///
/// Une adresse d'origine faite de `=` — qui s'écrivent `+3D` — occupe trois
/// fois sa longueur sur le fil. Dimensionner sur la valeur décodée laisserait
/// une commande refusée faute de place, c'est-à-dire un message perdu pour une
/// valeur que le déposant choisit. La borne est donc STRUCTURELLE : elle couvre
/// le pire, et aucune garde n'a à rattraper le reste.
pub const CLIENT_COMMAND_MAX: usize = 1536;

/// Ce qu'on retient au plus du texte d'un refus.
///
/// Une réponse tient dans 512 octets (RFC 5321 §4.5.3.1.5) et peut porter
/// plusieurs lignes ; on en garde de quoi rendre un motif et l'adresse d'une
/// page qui l'explique, sans faire du rapport un dépotoir.
pub const DIAGNOSTIC_MAX: usize = 512;

/// Ce qu'une valeur de RFC 3461 occupe au plus, une fois ré-encodée en xtext.
const XTEXT_PIRE: usize = ORCPT_MAX * XTEXT_GROWTH;

// Le tampon d'une commande couvre le pire `RCPT TO:` : l'enveloppe, un chemin,
// le `NOTIFY`, le mot-clé de l'`ORCPT`, et l'adresse d'origine triplée.
const _: () = assert!(CLIENT_COMMAND_MAX >= XTEXT_PIRE + 256 + 64);

/// Ce qu'une session cliente a besoin de savoir avant de parler.
#[derive(Debug, Clone, Copy)]
pub struct ClientConfig<'a> {
    /// Le nom qu'on annonce à l'`EHLO`. C'est le nôtre.
    pub name: &'a [u8],
    /// L'expéditeur d'enveloppe. **Vide vaut `<>`**, l'expéditeur nul.
    ///
    /// Un rapport DMARC comme un avis de non-remise s'émettent avec un
    /// expéditeur nul (RFC 7489 §7.2.1.1) : c'est ce qui empêche qu'une boucle
    /// s'installe entre deux serveurs qui se répondent l'un à l'autre.
    pub sender: &'a [u8],
    /// Les destinataires. Au moins un.
    pub recipients: &'a [&'a [u8]],
    /// Exige-t-on le chiffrement ?
    ///
    /// **Vrai, une remise en clair n'a pas lieu** : le pair qui n'annonce pas
    /// `STARTTLS` est laissé là, et l'issue est [`ClientOutcome::NoEncryption`].
    pub require_tls: bool,
    /// Ce que le déposant a demandé du sort de son message (RFC 3461).
    ///
    /// # ON NE LE PASSE QUE SI LE PAIR L'ANNONCE
    ///
    /// §5.2.1 : un serveur qui relaie vers un saut annonçant `DSN` lui passe ces
    /// paramètres, et c'est LUI qui rendra compte. Vers un saut qui ne les
    /// annonce pas, les écrire ferait refuser la transaction — un paramètre
    /// qu'on n'annonce pas se refuse, comme ce serveur le fait lui-même.
    pub dsn: Option<ClientDsn<'a>>,
}

/// Ce qu'un déposant a demandé, tel qu'on le passe au saut suivant.
///
/// Les valeurs sont ÉCRITES TELLES QUELLES, en xtext : elles ont été décodées à
/// l'arrivée, et les réencoder ici demanderait un second encodeur. C'est
/// l'appelant qui les fournit sous la forme qui part sur le fil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDsn<'a> {
    /// L'identifiant d'enveloppe du déposant (§4.4), ou vide.
    pub envelope_id: &'a [u8],
    /// Ce que chaque destinataire a demandé, dans l'ordre de `recipients`.
    pub reports: &'a [ClientReport<'a>],
}

/// Ce qu'un destinataire a demandé (RFC 3461 §4.1, §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientReport<'a> {
    /// Le déposant demande qu'on se taise, quoi qu'il arrive.
    pub never: bool,
    /// Un rapport est demandé en cas de succès.
    pub on_success: bool,
    /// L'adresse d'origine (§4.2), ou vide.
    pub original: &'a [u8],
}

/// Ce qu'une remise a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientOutcome {
    /// Le pair a pris le message en charge. Il n'est plus à nous.
    Delivered,
    /// Refus **définitif** (`5yz`) : réessayer à l'identique n'a aucun sens.
    Rejected(Code),
    /// Refus **temporaire** (`4yz`) : réessayer plus tard en a un.
    Deferred(Code),
    /// Le pair n'offre pas `STARTTLS`, et on l'exigeait.
    NoEncryption,
    /// Le pair a répondu quelque chose qui n'a pas de sens à cet endroit.
    ///
    /// **Ce n'est pas un refus** : c'est un désaccord sur le protocole, et
    /// l'appelant fera bien de réessayer plus tard plutôt que de jeter le
    /// message. Une implémentation en face peut être corrigée ; un message
    /// perdu ne revient pas.
    Unexpected(Code),
}

/// Le geste suivant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientStep {
    /// Écrire les `n` premiers octets du tampon, puis lire une réponse.
    Send(usize),
    /// Monter en chiffrement, puis appeler [`SmtpClient::on_secured`].
    Secure,
    /// Écrire le message **point-farci**, puis lire une réponse.
    SendBody,
    /// C'est fini.
    Done {
        /// Les octets à écrire avant de fermer — le `QUIT`, quand il a un sens.
        ///
        /// **On n'attend pas la réponse au `QUIT`.** Elle n'apprend rien, et
        /// l'attendre offrirait à un pair muet de nous retenir une connexion de
        /// plus, aussi longtemps qu'il lui plaît.
        sent: usize,
        /// Ce que la remise a donné.
        outcome: ClientOutcome,
    },
}

/// Où en est la conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Etat {
    /// On attend la bannière.
    Banniere,
    /// On attend la réponse à `EHLO`.
    Ehlo,
    /// On attend la réponse à `HELO`, après un `EHLO` refusé.
    Helo,
    /// On attend le `220` qui précède la poignée de main.
    Tls,
    /// On attend la réponse à `MAIL FROM:`.
    Enveloppe,
    /// On attend la réponse au `RCPT TO:` de rang `usize`.
    Destinataire(usize),
    /// On attend le `354`.
    Data,
    /// On attend la réponse au message.
    Contenu,
    /// Il n'y a plus rien à attendre.
    Fini,
}

/// Une session SMTP cliente.
#[derive(Debug, Clone)]
pub struct SmtpClient<'a> {
    config: ClientConfig<'a>,
    etat: Etat,
    /// Le chiffrement est-il monté ?
    chiffre: bool,
    /// A-t-on déjà essayé `EHLO` ?
    esmtp_tente: bool,
    /// Destinataires acceptés.
    acceptes: usize,
    /// Destinataires refusés.
    refuses: usize,
    /// Ce qu'on passera au saut suivant, s'il annonce `DSN`.
    ///
    /// **`None` tant que l'`EHLO` n'a rien dit** : c'est ce qui garantit qu'on
    /// n'écrit jamais un paramètre que le pair n'a pas annoncé.
    dsn: Option<ClientDsn<'a>>,
    /// Ce que le pair a dit en refusant, tel qu'il l'a dit.
    ///
    /// # POURQUOI LE RETENIR PLUTÔT QUE D'ÉCRIRE UNE PHRASE À SA PLACE
    ///
    /// Un code de trois chiffres ne dit presque rien. C'est le TEXTE qui porte
    /// le motif, et parfois l'adresse d'une page qui l'explique — la seule chose
    /// exploitable qu'un déposant recevra. L'inventer reviendrait à faire passer
    /// notre supposition pour la parole du pair, ce que le composeur de rapport
    /// refuse en toutes lettres.
    diagnostic: [u8; DIAGNOSTIC_MAX],
    diagnostic_len: usize,
    /// L'état étendu que le pair a écrit (RFC 3463 §2), s'il en a écrit un.
    statut: Option<Status>,
}

impl<'a> SmtpClient<'a> {
    /// Ouvre une session.
    ///
    /// # Errors
    ///
    /// [`Error::UnsafeAddress`] si le nom, l'expéditeur ou un destinataire
    /// porte autre chose que de l'ASCII imprimable sans espace ni chevrons —
    /// voir la documentation du module ; [`Error::NoRecipient`] s'il n'y a
    /// personne à qui écrire.
    pub fn new(config: ClientConfig<'a>) -> Result<Self, Error> {
        if config.recipients.is_empty() {
            return Err(Error::NoRecipient);
        }
        if config.name.is_empty() || !sur(config.name) {
            return Err(Error::UnsafeAddress);
        }
        // L'expéditeur peut être VIDE — c'est `<>` — mais pas douteux.
        if !sur(config.sender) {
            return Err(Error::UnsafeAddress);
        }
        for destinataire in config.recipients {
            if destinataire.is_empty() || !sur(destinataire) {
                return Err(Error::UnsafeAddress);
            }
        }
        if let Some(dsn) = config.dsn
            && !dsn_recevable(&dsn, config.recipients.len())
        {
            return Err(Error::UnsafeAddress);
        }
        Ok(Self {
            config,
            etat: Etat::Banniere,
            chiffre: false,
            esmtp_tente: false,
            acceptes: 0,
            refuses: 0,
            dsn: None,
            diagnostic: [0; DIAGNOSTIC_MAX],
            diagnostic_len: 0,
            statut: None,
        })
    }

    /// Le pair a-t-il pris en charge les demandes de RFC 3461 ?
    ///
    /// # C'EST CE QUI DÉCIDE SI L'ON REND COMPTE SOI-MÊME
    ///
    /// §5.2.1 : quand le saut suivant annonce `DSN`, les paramètres lui sont
    /// passés, et c'est LUI qui rendra compte. Émettre en plus un rapport de
    /// relais ferait deux rapports pour un même envoi, et le déposant ne
    /// saurait pas lequel croire.
    #[must_use]
    pub fn dsn_forwarded(&self) -> bool {
        self.dsn.is_some()
    }

    /// Le nombre de destinataires que le pair a acceptés.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.acceptes
    }

    /// Le nombre de destinataires que le pair a refusés.
    ///
    /// **Un refus partiel n'arrête pas la remise** : renoncer parce qu'une
    /// adresse sur cinq est inconnue ferait perdre les quatre autres.
    #[must_use]
    pub fn refused(&self) -> usize {
        self.refuses
    }

    /// La conversation est-elle chiffrée ?
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.chiffre
    }

    /// Reprend après la poignée de main : on se represente par un `EHLO`.
    ///
    /// RFC 3207 §4 : tout ce que le serveur avait annoncé est **oublié**, et
    /// tout ce que le client avait dit aussi. Réutiliser l'`EHLO` d'avant
    /// reviendrait à faire confiance à ce qu'on a entendu en clair.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` ne suffit pas.
    pub fn on_secured(&mut self, out: &mut [u8]) -> Result<ClientStep, Error> {
        self.chiffre = true;
        self.etat = Etat::Ehlo;
        Ok(ClientStep::Send(ecrire(
            out,
            &[b"EHLO ", self.config.name, b"\r\n"],
        )?))
    }

    /// Nourrit une réponse, et rend le geste suivant.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` ne suffit pas ; [`Error::SessionClosed`] si une
    /// réponse arrive alors qu'il n'y a plus rien à attendre.
    pub fn on_reply(&mut self, reply: &Reply<'_>, out: &mut [u8]) -> Result<ClientStep, Error> {
        match self.etat {
            Etat::Banniere => self.sur_banniere(reply, out),
            Etat::Ehlo => self.sur_ehlo(reply, out),
            Etat::Helo => self.sur_helo(reply, out),
            Etat::Tls => self.sur_tls(reply, out),
            Etat::Enveloppe => self.sur_enveloppe(reply, out),
            Etat::Destinataire(rang) => self.sur_destinataire(reply, rang, out),
            Etat::Data => self.sur_data(reply, out),
            Etat::Contenu => self.sur_contenu(reply, out),
            Etat::Fini => Err(Error::SessionClosed),
        }
    }

    /// La bannière : `220`, ou rien à faire ici.
    fn sur_banniere(&mut self, reply: &Reply<'_>, out: &mut [u8]) -> Result<ClientStep, Error> {
        if reply.code().value() != 220 {
            // Un `554` de bannière veut dire « je ne vous parlerai pas ». On
            // n'insiste pas, et l'on ne dit pas `QUIT` à qui vient de refuser
            // la conversation.
            return self.abandonner(reply, 0);
        }
        self.esmtp_tente = true;
        self.etat = Etat::Ehlo;
        Ok(ClientStep::Send(ecrire(
            out,
            &[b"EHLO ", self.config.name, b"\r\n"],
        )?))
    }

    /// La réponse à `EHLO`.
    fn sur_ehlo(&mut self, reply: &Reply<'_>, out: &mut [u8]) -> Result<ClientStep, Error> {
        if reply.code().class() != Class::Positive {
            // UN SERVEUR DE LA RFC 821 NE CONNAÎT PAS `EHLO` (§3.2). Se rabattre
            // sur `HELO` n'est pas de la complaisance : sans cela, on couperait
            // du courrier vers des machines qui fonctionnent.
            self.etat = Etat::Helo;
            return Ok(ClientStep::Send(ecrire(
                out,
                &[b"HELO ", self.config.name, b"\r\n"],
            )?));
        }
        // **CE QUE LE PAIR ANNONCE DÉCIDE DE CE QU'ON LUI ÉCRIT** (§5.2.1). Un
        // paramètre qu'il n'annonce pas ferait refuser la transaction entière,
        // et le message serait perdu pour une demande facultative.
        //
        // La lecture a lieu à CHAQUE `EHLO`, y compris le second après
        // `STARTTLS` : ce que le pair annonce en clair n'engage à rien, et §4.2
        // de RFC 3207 veut qu'on oublie tout ce qui précède la poignée de main.
        self.dsn = reply.offers(b"DSN").then_some(self.config.dsn).flatten();
        if !self.chiffre && reply.offers(b"STARTTLS") {
            self.etat = Etat::Tls;
            return Ok(ClientStep::Send(ecrire(out, &[b"STARTTLS\r\n"])?));
        }
        if !self.chiffre && self.config.require_tls {
            // Le pair n'offre rien, et on exigeait. On s'en va poliment : il n'a
            // rien fait de mal, c'est nous qui refusons de parler en clair.
            self.etat = Etat::Fini;
            return Ok(ClientStep::Done {
                sent: ecrire(out, &[b"QUIT\r\n"])?,
                outcome: ClientOutcome::NoEncryption,
            });
        }
        self.enveloppe(out)
    }

    /// La réponse à `HELO`.
    fn sur_helo(&mut self, reply: &Reply<'_>, out: &mut [u8]) -> Result<ClientStep, Error> {
        if reply.code().class() != Class::Positive {
            return self.abandonner(reply, ecrire(out, &[b"QUIT\r\n"])?);
        }
        if self.config.require_tls {
            // Pas d'`EHLO`, donc pas d'extension, donc pas de `STARTTLS` : ce
            // serveur ne sait pas chiffrer, et nous ne savons pas parler en
            // clair.
            self.etat = Etat::Fini;
            return Ok(ClientStep::Done {
                sent: ecrire(out, &[b"QUIT\r\n"])?,
                outcome: ClientOutcome::NoEncryption,
            });
        }
        self.enveloppe(out)
    }

    /// Le `220` qui précède la poignée de main.
    fn sur_tls(&mut self, reply: &Reply<'_>, out: &mut [u8]) -> Result<ClientStep, Error> {
        if reply.code().value() != 220 {
            // Le serveur a annoncé `STARTTLS` puis l'a refusé. **On ne se rabat
            // pas sur le clair** : un refus qu'un tiers peut provoquer est
            // exactement le levier d'une attaque par déclassement.
            self.etat = Etat::Fini;
            return Ok(ClientStep::Done {
                sent: ecrire(out, &[b"QUIT\r\n"])?,
                outcome: ClientOutcome::NoEncryption,
            });
        }
        self.etat = Etat::Fini;
        Ok(ClientStep::Secure)
    }

    /// Écrit `MAIL FROM:`.
    fn enveloppe(&mut self, out: &mut [u8]) -> Result<ClientStep, Error> {
        self.etat = Etat::Enveloppe;
        // **`ENVID` NE PART QUE SI LE PAIR ANNONCE `DSN`** (§5.2.1). L'écrire à
        // un serveur qui ne l'annonce pas ferait refuser la transaction entière,
        // et le message serait perdu pour un paramètre facultatif.
        let envid = self
            .dsn
            .and_then(|dsn| (!dsn.envelope_id.is_empty()).then_some(dsn.envelope_id));
        let Some(identifiant) = envid else {
            return Ok(ClientStep::Send(ecrire(
                out,
                &[b"MAIL FROM:<", self.config.sender, b">\r\n"],
            )?));
        };
        // **L'IDENTIFIANT REPART EN XTEXT.** La file le garde décodé, parce que
        // c'est sous cette forme qu'il s'écrit dans un rapport ; le fil, lui,
        // veut du xtext, et l'y mettre en clair changerait sa valeur pour qui le
        // relit (§4).
        let ecrits = ecrire(out, &[b"MAIL FROM:<", self.config.sender, b"> ENVID="])?;
        let ecrits = ajouter_xtext(out, ecrits, identifiant)?;
        Ok(ClientStep::Send(ajouter(out, ecrits, &[b"\r\n"])?))
    }

    /// La réponse à `MAIL FROM:`.
    fn sur_enveloppe(&mut self, reply: &Reply<'_>, out: &mut [u8]) -> Result<ClientStep, Error> {
        if reply.code().class() != Class::Positive {
            return self.abandonner(reply, ecrire(out, &[b"QUIT\r\n"])?);
        }
        self.destinataire(0, out)
    }

    /// Écrit le `RCPT TO:` de rang `rang`.
    ///
    /// `recipients` n'est jamais vide — [`SmtpClient::new`] le refuse — et ce
    /// rang vient toujours de son parcours. `unwrap_or_default` porte cette
    /// impossibilité-là dans la bibliothèque standard, plutôt que d'ajouter ici
    /// une garde qu'aucune entrée ne peut faire céder.
    fn destinataire(&mut self, rang: usize, out: &mut [u8]) -> Result<ClientStep, Error> {
        let adresse = self
            .config
            .recipients
            .get(rang)
            .copied()
            .unwrap_or_default();
        self.etat = Etat::Destinataire(rang);
        // **`NOTIFY` ET `ORCPT` SONT PAR DESTINATAIRE** (§4.1, §4.2), et ne
        // partent que si le pair annonce `DSN`.
        //
        // `get` ne peut pas manquer : [`SmtpClient::new`] a refusé la remise si
        // les deux listes n'avaient pas la même longueur. Porter cette
        // impossibilité dans `and_then` évite une garde que rien n'atteindrait.
        if let Some(rapport) = self.dsn.and_then(|dsn| dsn.reports.get(rang).copied()) {
            let notify: &[u8] = if rapport.never {
                b" NOTIFY=NEVER"
            } else if rapport.on_success {
                // **`FAILURE` RESTE DEMANDÉ AVEC `SUCCESS`.** L'écrire seul
                // ferait taire l'échec, que le déposant n'a pas renoncé à
                // connaître : sans paramètre, §4.1 le lui promet.
                b" NOTIFY=SUCCESS,FAILURE"
            } else {
                b""
            };
            let orcpt: &[u8] = if rapport.original.is_empty() {
                b""
            } else {
                b" ORCPT=rfc822;"
            };
            if !notify.is_empty() || !orcpt.is_empty() {
                let ecrits = ecrire(out, &[b"RCPT TO:<", adresse, b">", notify, orcpt])?;
                // **L'ADRESSE D'ORIGINE REPART EN XTEXT**, et cela n'a rien
                // d'anodin : `marie+liste@x.test` écrite en clair serait relue
                // par le saut suivant comme l'échappée `+li`, qui n'est pas de
                // l'hexadécimal. Il refuserait le `RCPT`, et le message serait
                // perdu pour un `+` — c'est-à-dire pour l'adressage par
                // étiquette, qui est partout.
                let ecrits = ajouter_xtext(out, ecrits, rapport.original)?;
                return Ok(ClientStep::Send(ajouter(out, ecrits, &[b"\r\n"])?));
            }
        }
        Ok(ClientStep::Send(ecrire(
            out,
            &[b"RCPT TO:<", adresse, b">\r\n"],
        )?))
    }

    /// La réponse à un `RCPT TO:`.
    fn sur_destinataire(
        &mut self,
        reply: &Reply<'_>,
        rang: usize,
        out: &mut [u8],
    ) -> Result<ClientStep, Error> {
        if reply.code().class() == Class::Positive {
            self.acceptes = self.acceptes.saturating_add(1);
        } else {
            // UN REFUS PARTIEL N'ARRÊTE PAS LA REMISE : renoncer parce qu'une
            // adresse sur cinq est inconnue ferait perdre les quatre autres.
            self.refuses = self.refuses.saturating_add(1);
        }
        let suivant = rang.saturating_add(1);
        if suivant < self.config.recipients.len() {
            return self.destinataire(suivant, out);
        }
        if self.acceptes == 0 {
            // PERSONNE NE VEUT DE CE MESSAGE, et `reply` est justement le refus
            // du dernier : sans acceptation, la réponse qu'on tient est un
            // refus, et son code dit s'il vaut la peine de réessayer.
            return self.abandonner(reply, ecrire(out, &[b"QUIT\r\n"])?);
        }
        self.etat = Etat::Data;
        Ok(ClientStep::Send(ecrire(out, &[b"DATA\r\n"])?))
    }

    /// La réponse à `DATA` : `354`, et rien d'autre.
    fn sur_data(&mut self, reply: &Reply<'_>, out: &mut [u8]) -> Result<ClientStep, Error> {
        if reply.code().value() != 354 {
            return self.abandonner(reply, ecrire(out, &[b"QUIT\r\n"])?);
        }
        self.etat = Etat::Contenu;
        Ok(ClientStep::SendBody)
    }

    /// La réponse au message lui-même. **C'est celle qui compte.**
    fn sur_contenu(&mut self, reply: &Reply<'_>, out: &mut [u8]) -> Result<ClientStep, Error> {
        self.etat = Etat::Fini;
        let sent = ecrire(out, &[b"QUIT\r\n"])?;
        if reply.code().class() == Class::Positive {
            return Ok(ClientStep::Done {
                sent,
                outcome: ClientOutcome::Delivered,
            });
        }
        Ok(ClientStep::Done {
            sent,
            outcome: issue_du_code(reply.code()),
        })
    }

    /// Renonce, en disant ce que le code veut dire.
    fn abandonner(&mut self, reply: &Reply<'_>, sent: usize) -> Result<ClientStep, Error> {
        self.etat = Etat::Fini;
        self.retenir_le_refus(reply);
        Ok(ClientStep::Done {
            sent,
            outcome: issue_du_code(reply.code()),
        })
    }

    /// Retient ce que le pair a dit en refusant : son état étendu et son texte.
    ///
    /// # UNE LIGNE QU'ON NE PEUT PAS RENDRE TOMBE ENTIÈRE
    ///
    /// Ce texte ressortira dans un `Diagnostic-Code` que NOUS composons et que
    /// le client de notre utilisateur lira. Un octet qu'on ne sait pas écrire —
    /// de l'UTF-8, un caractère de contrôle — ne se remplace pas : le corriger
    /// serait inventer, et une ligne rafistolée se lirait comme celle du pair.
    /// Elle est donc écartée, et si tout l'est, le champ sera OMIS.
    fn retenir_le_refus(&mut self, reply: &Reply<'_>) {
        self.diagnostic_len = 0;
        self.statut = None;
        let mut ecrits = 0_usize;
        for (rang, ligne) in reply.lines().enumerate() {
            // **L'ÉTAT NE SE LIT QU'EN TÊTE DE LA PREMIÈRE LIGNE** (§2 de
            // RFC 3463), et il en est retiré : le recopier dans le texte le
            // ferait paraître deux fois dans le rapport.
            let texte = match (rang, Status::parse(ligne)) {
                (0, Some((statut, suite))) => {
                    // §3.2 : un `550 4.x.x` ferait réessayer un refus définitif.
                    // Un état qui contredit son code n'est pas une information,
                    // c'est un piège.
                    self.statut = statut.agrees_with(reply.code()).then_some(statut);
                    suite
                }
                _ => ligne,
            };
            if !rendu_possible(texte) {
                continue;
            }
            // Les lignes se joignent par un espace : un rapport n'a qu'un champ
            // `Diagnostic-Code`, et le couper en deux le rendrait illisible.
            let separateur: &[u8] = if ecrits == 0 { b"" } else { b" " };
            for morceau in [separateur, texte] {
                let fin = ecrits.saturating_add(morceau.len());
                let Some(place) = self.diagnostic.get_mut(ecrits..fin) else {
                    // **CE QUI NE TIENT PAS S'ARRÊTE ICI**, entier : une phrase
                    // coupée au milieu changerait de sens.
                    self.diagnostic_len = ecrits;
                    return;
                };
                place.copy_from_slice(morceau);
                ecrits = fin;
            }
        }
        self.diagnostic_len = ecrits;
    }

    /// Ce que le pair a dit en refusant, ou rien.
    #[must_use]
    pub fn diagnostic(&self) -> &[u8] {
        self.diagnostic
            .get(..self.diagnostic_len)
            .unwrap_or_default()
    }

    /// L'état étendu que le pair a écrit, s'il en a écrit un qui s'accorde avec
    /// son code (RFC 3463 §3.2).
    #[must_use]
    pub const fn peer_status(&self) -> Option<Status> {
        self.statut
    }
}

/// Ce qu'un code veut dire pour celui qui émet.
///
/// **`4yz` et `5yz` ne se confondent pas** : les traiter pareil fait soit perdre
/// du courrier — en jetant ce qui aurait abouti plus tard — soit harceler un
/// serveur qui a déjà dit non.
fn issue_du_code(code: Code) -> ClientOutcome {
    match code.class() {
        Class::TransientFailure => ClientOutcome::Deferred(code),
        Class::PermanentFailure => ClientOutcome::Rejected(code),
        // Un `2yz` ou un `3yz` là où on ne l'attendait pas n'est pas un refus :
        // c'est un désaccord sur le protocole, et un message qu'on jetterait
        // pour cela ne reviendrait pas.
        Class::Positive | Class::Intermediate => ClientOutcome::Unexpected(code),
    }
}

/// Ce que le déposant a demandé est-il recevable, et bordé ?
///
/// # POURQUOI LES DEUX LISTES DOIVENT AVOIR LA MÊME LONGUEUR
///
/// Un tableau de rapports plus court que la liste des destinataires ferait
/// écrire les derniers `RCPT` SANS leur demande — donc sans le `NOTIFY=NEVER`
/// que le déposant avait écrit, et le saut suivant émettrait le rapport qu'il
/// avait explicitement refusé. Le manque serait silencieux ; le refus ne l'est
/// pas.
///
/// # POURQUOI LES LONGUEURS SONT BORNÉES ICI
///
/// C'est ce qui rend [`CLIENT_COMMAND_MAX`] structurel : sans borne, une
/// adresse d'origine assez longue ferait refuser la commande faute de place,
/// c'est-à-dire perdre un message pour une valeur que le déposant choisit.
fn dsn_recevable(dsn: &ClientDsn<'_>, destinataires: usize) -> bool {
    if dsn.reports.len() != destinataires || dsn.envelope_id.len() > ENVID_MAX {
        return false;
    }
    // **DE L'ASCII VISIBLE, ET NON `sur`** : ces valeurs sortent d'un décodage
    // xtext, qui laisse passer `<` et `>` — les refuser ici rejetterait une
    // adresse d'origine que la réception avait acceptée. Ce qui compte est
    // qu'aucune espace ni fin de ligne ne coupe le paramètre en deux.
    if !dsn.envelope_id.iter().all(u8::is_ascii_graphic) {
        return false;
    }
    dsn.reports
        .iter()
        .all(|un| un.original.len() <= ORCPT_MAX && un.original.iter().all(u8::is_ascii_graphic))
}

/// Cette ligne peut-elle être rendue telle quelle dans un rapport ?
///
/// De l'ASCII imprimable, et rien d'autre — la même règle que le composeur du
/// rapport applique. Une ligne vide n'apporte rien et n'est pas retenue.
fn rendu_possible(ligne: &[u8]) -> bool {
    !ligne.is_empty()
        && ligne
            .iter()
            .all(|octet| octet.is_ascii_graphic() || *octet == b' ')
}

/// Cette valeur peut-elle être écrite dans une commande sans rien y ajouter ?
fn sur(valeur: &[u8]) -> bool {
    valeur
        .iter()
        .all(|octet| octet.is_ascii_graphic() && !matches!(*octet, b'<' | b'>'))
}

/// Écrit des morceaux à la SUITE de ce qui est déjà là, et rend le total.
///
/// **AUCUNE GARDE SUR `deja`** : il vient d'une écriture qui a réussi dans ce
/// même tampon, donc il n'en dépasse pas la fin, et `unwrap_or_default` porte
/// cette impossibilité dans la bibliothèque standard. Un tampon vide n'ouvre
/// rien : `ecrire` refuse d'y mettre le moindre octet.
fn ajouter(out: &mut [u8], deja: usize, morceaux: &[&[u8]]) -> Result<usize, Error> {
    let place = out.get_mut(deja..).unwrap_or_default();
    Ok(deja.saturating_add(ecrire(place, morceaux)?))
}

/// Ré-encode `valeur` en xtext (RFC 3461 §4) à la suite de ce qui est déjà là.
fn ajouter_xtext(out: &mut [u8], deja: usize, valeur: &[u8]) -> Result<usize, Error> {
    let place = out.get_mut(deja..).unwrap_or_default();
    // **`encode_xtext` REFUSE CE QUI N'EST PAS DE L'ASCII VISIBLE**, et l'on ne
    // s'en remet pas à cela seul : `SmtpClient::new` a déjà refusé la remise si
    // une valeur en portait. Deux vérifications pour une, parce que celle-ci
    // est faite dans une autre caisse, et qu'une vérification qu'on ne voit pas
    // en lisant l'endroit qui en dépend n'en est pas une.
    let ecrits = encode_xtext(valeur, place).map_err(Error::Reply)?.len();
    Ok(deja.saturating_add(ecrits))
}

/// Écrit des morceaux à la suite, et rend le nombre d'octets écrits.
fn ecrire(out: &mut [u8], morceaux: &[&[u8]]) -> Result<usize, Error> {
    let mut ecrits = 0_usize;
    for morceau in morceaux {
        let fin = ecrits.saturating_add(morceau.len());
        let place = out.get_mut(ecrits..fin).ok_or(Error::Reply(
            ams_proto_smtp::Error::BufferTooSmall {
                needed: CLIENT_COMMAND_MAX,
            },
        ))?;
        place.copy_from_slice(morceau);
        ecrits = fin;
    }
    Ok(ecrits)
}

#[cfg(test)]
mod tests;
