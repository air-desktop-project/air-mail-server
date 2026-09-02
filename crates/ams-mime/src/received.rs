//! L'en-tête `Received:` (RFC 5321 §4.4), et les mots de RFC 3848.
//!
//! # C'EST LE SEUL EN-TÊTE QUE LA NORME EXIGE D'AJOUTER
//!
//! §4.4 ne le suggère pas : « an SMTP server **MUST** insert trace information
//! at the beginning of the message content ». Ce serveur écrivait déjà
//! `Received-SPF` et `Authentication-Results` — deux en-têtes que personne
//! n'oblige — et pas celui-là.
//!
//! Ce n'est pas une formalité. Sans lui :
//!
//! - **le chemin d'un message est intraçable.** C'est la première chose qu'on
//!   regarde quand un courrier n'arrive pas, ou arrive de travers.
//! - **une boucle ne se détecte plus.** §6.3 la détecte en COMPTANT les
//!   `Received:` ; un message qui tourne entre deux serveurs mal réglés se
//!   multiplie à chaque tour, et rien ne l'arrête.
//! - **les filtres en aval s'en méfient.** Un message sans trace ressemble à un
//!   message fabriqué.
//!
//! # PAS DE CLAUSE `for`, JAMAIS
//!
//! §4.4 la permet, et ce serveur ne l'écrit pas. Elle mettrait une adresse de
//! destinataire dans un en-tête qui voyage avec le message : sur une transaction
//! à plusieurs destinataires, chaque copie révélerait à son lecteur qu'il y en
//! avait d'autres. La norme s'en méfie elle-même — « a single FOR clause » au
//! plus, précisément pour cela — et ne jamais l'écrire évite d'avoir à s'en
//! souvenir.
//!
//! # CE QUE L'EN-TÊTE PORTE VIENT DU PAIR, ET N'EST DONC PAS CRU
//!
//! Le nom du `HELO` est ce que le pair a bien voulu dire. Un `CRLF` glissé
//! dedans écrirait un en-tête à notre place, **en tête du message**, là où un
//! lecteur croira que c'est nous qui parlons. Il est donc vérifié ici, et pas
//! seulement à la grammaire : cette crate ne suppose pas ce que son appelant a
//! fait.

use crate::Error;
use crate::date::{DATE_MAX, write_date};
use core::fmt::Write as _;
use core::net::IpAddr;

/// La place qu'un `Received:` peut demander.
///
/// `from ` + un nom (255) + ` (` + une adresse (45) + `)` puis le pli, `by ` +
/// notre nom (255), ` with ESMTPSA;` puis le pli et la date. Arrondi au-dessus :
/// une borne qu'on recalcule à chaque changement de texte est une borne qu'on
/// finit par se tromper.
pub const RECEIVED_MAX: usize = 700;

/// Ce qu'un nom peut peser (RFC 1035 §2.3.4), littéral d'adresse compris.
const NOM_MAX: usize = 255;

/// Comment le message est arrivé (RFC 3848).
///
/// # IL N'Y A PAS D'`ESMTPA`, ET C'EST STRUCTUREL
///
/// RFC 3848 le prévoit — authentifié, mais en clair. Ce serveur ne peut pas le
/// produire : la session refuse `AUTH` hors chiffrement, sans réglage pour le
/// rétablir (C6). Une variante que rien ne peut construire serait une branche
/// que rien ne pourrait éprouver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// `HELO`, en clair.
    Smtp,
    /// `EHLO`, en clair.
    Esmtp,
    /// `EHLO`, sous TLS.
    Esmtps,
    /// `EHLO`, sous TLS, et authentifié.
    EsmtpsA,
}

impl Transport {
    /// Le mot de RFC 3848.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Smtp => "SMTP",
            Self::Esmtp => "ESMTP",
            Self::Esmtps => "ESMTPS",
            Self::EsmtpsA => "ESMTPSA",
        }
    }
}

/// Ce que le champ dit du saut qui vient d'avoir lieu.
#[derive(Debug, Clone, Copy)]
pub struct Received<'a> {
    /// Le nom que le pair a annoncé au `HELO` ou `EHLO`.
    pub helo: &'a [u8],
    /// L'adresse d'où il parlait. **Elle, on ne la tient pas de lui.**
    pub client: IpAddr,
    /// Le nom que ce serveur annonce.
    pub receiver: &'a [u8],
    /// Comment le message est arrivé.
    pub with: Transport,
    /// L'instant de l'arrivée, en secondes depuis l'époque.
    pub date: u64,
}

/// Compose l'en-tête, `CRLF` final compris.
///
/// # LE CHAMP TIENT SUR TROIS LIGNES REPLIÉES
///
/// §2.1.1 de RFC 5322 borne une ligne à 998 octets, et deux noms de 255 plus
/// une adresse ne tiendraient pas sur une seule. Le pli est un blanc de
/// continuation : le champ reste UN champ.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `sortie` ne suffit pas ; [`Error::NotPrintable`]
/// si le nom du pair ou le nôtre porte autre chose que de l'ASCII visible.
pub fn write_received<'b>(sortie: &'b mut [u8], champ: &Received<'_>) -> Result<&'b [u8], Error> {
    // **CE QUI VIENT DU PAIR EST VÉRIFIÉ ICI.** La grammaire SMTP l'a déjà fait,
    // et cette crate ne le suppose pas : elle écrit en tête du message, là où un
    // octet de trop parle sous notre nom.
    if !nom_recevable(champ.helo) || !nom_recevable(champ.receiver) {
        return Err(Error::NotPrintable);
    }

    let mut plume = Plume {
        sortie,
        ecrits: 0,
        faute: None,
    };
    plume.pousser(b"Received: from ")?;
    plume.pousser(champ.helo)?;
    // L'adresse entre parenthèses et crochets : c'est la forme que tout le monde
    // écrit, et la seule que les outils de lecture savent défaire.
    plume.pousser(b" ([")?;
    plume.adresse(champ.client)?;
    plume.pousser(b"])\r\n\tby ")?;
    plume.pousser(champ.receiver)?;
    plume.pousser(b" with ")?;
    plume.pousser(champ.with.name().as_bytes())?;
    plume.pousser(b";\r\n\t")?;

    let mut date = [0_u8; DATE_MAX];
    // **CETTE ÉCRITURE NE PEUT PAS ÉCHOUER**, et un `?` y serait une garde que
    // rien n'atteindrait. `write_date` ne refuse que par manque de place, et
    // `DATE_MAX` est SA borne : la plus longue date qu'un `u64` puisse désigner
    // — l'an 584 942 419 325 — tient dans trente-neuf octets, et ce tampon en a
    // quarante. On le dit ici plutôt que de laisser une branche que personne ne
    // pourrait éprouver.
    let ecrite =
        write_date(champ.date, &mut date).expect("DATE_MAX majore toute date qu'un u64 désigne");
    plume.pousser(ecrite)?;
    plume.pousser(b"\r\n")?;

    let ecrits = plume.ecrits;
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

/// Ce nom peut-il s'écrire dans un en-tête ?
///
/// De l'ASCII visible, sans espace, ni vide, et pas plus long qu'un nom de
/// domaine. Un espace couperait le champ en deux mots, et un `CRLF` écrirait un
/// en-tête à notre place.
fn nom_recevable(nom: &[u8]) -> bool {
    !nom.is_empty() && nom.len() <= NOM_MAX && nom.iter().all(u8::is_ascii_graphic)
}

/// De quoi écrire dans une tranche, en retenant la première faute.
struct Plume<'b> {
    sortie: &'b mut [u8],
    ecrits: usize,
    faute: Option<Error>,
}

impl Plume<'_> {
    fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(morceau.len());
        let place = self
            .sortie
            .get_mut(self.ecrits..fin)
            .ok_or(Error::BufferTooSmall)?;
        place.copy_from_slice(morceau);
        self.ecrits = fin;
        Ok(())
    }

    /// L'adresse, telle que `core::net` l'écrit.
    ///
    /// Une adresse ne porte aucun octet à échapper : des chiffres, des points et
    /// des deux-points. C'est `core::net` qui la formate, et non nous — deux
    /// écritures d'une même adresse finiraient par ne plus dire la même chose.
    fn adresse(&mut self, client: IpAddr) -> Result<(), Error> {
        match write!(self, "{client}") {
            Ok(()) => Ok(()),
            // `fmt::Error` ne dit rien ; la cause, elle, a été retenue.
            Err(_) => Err(self.faute.unwrap_or(Error::BufferTooSmall)),
        }
    }
}

impl core::fmt::Write for Plume<'_> {
    fn write_str(&mut self, texte: &str) -> core::fmt::Result {
        match self.pousser(texte.as_bytes()) {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.faute = Some(cause);
                Err(core::fmt::Error)
            }
        }
    }
}

#[cfg(test)]
mod tests;
