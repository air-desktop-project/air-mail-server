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

use ams_proto_smtp::{Class, Code, Reply};

use crate::Error;

/// La taille de tampon que cette session demande pour une commande.
///
/// La plus longue est `RCPT TO:<…>` : un chemin de 256 octets (RFC 5321 §4.5.3.1)
/// et onze octets d'enveloppe. On arrondit largement au-dessus.
pub const CLIENT_COMMAND_MAX: usize = 512;

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
        Ok(Self {
            config,
            etat: Etat::Banniere,
            chiffre: false,
            esmtp_tente: false,
            acceptes: 0,
            refuses: 0,
        })
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
        Ok(ClientStep::Send(ecrire(
            out,
            &[b"MAIL FROM:<", self.config.sender, b">\r\n"],
        )?))
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
        Ok(ClientStep::Done {
            sent,
            outcome: issue_du_code(reply.code()),
        })
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

/// Cette valeur peut-elle être écrite dans une commande sans rien y ajouter ?
fn sur(valeur: &[u8]) -> bool {
    valeur
        .iter()
        .all(|octet| octet.is_ascii_graphic() && !matches!(*octet, b'<' | b'>'))
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
