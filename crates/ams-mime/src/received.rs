//! Les deux en-têtes que §4.4 de RFC 5321 exige, et les mots de RFC 3848.
//!
//! # §4.4 EN EXIGE DEUX, ET NON UN
//!
//! Il les demande à deux moments différents, et ce serveur est aux deux :
//!
//! - **la trace `Received:`**, de qui ACCEPTE un message — « an SMTP server
//!   **MUST** insert trace information at the beginning of the message
//!   content » ;
//! - **le `Return-Path:`**, de qui le REMET pour de bon — « it inserts a
//!   return-path line at the beginning of the mail data. This use of
//!   return-path is required ».
//!
//! **Ce titre disait « le seul en-tête » et se trompait**, pendant que ce
//! serveur écrivait déjà `Received-SPF` et `Authentication-Results` — deux
//! en-têtes que personne n'oblige — et pas le second de ceux qu'on lui demande.
//! Une phrase absolue est une phrase qu'on ne relit plus.
//!
//! # CE QUE LA TRACE EMPÊCHE
//!
//! Ce n'est pas une formalité. Sans elle :
//!
//! - **le chemin d'un message est intraçable.** C'est la première chose qu'on
//!   regarde quand un courrier n'arrive pas, ou arrive de travers.
//! - **une boucle ne se détecte plus.** §6.3 la détecte en COMPTANT les
//!   `Received:` ; un message qui tourne entre deux serveurs mal réglés se
//!   multiplie à chaque tour, et rien ne l'arrête.
//! - **les filtres en aval s'en méfient.** Un message sans trace ressemble à un
//!   message fabriqué.
//!
//! # CE QUE LE `Return-Path:` EMPÊCHE
//!
//! Sans lui, l'expéditeur d'ENVELOPPE est perdu à la remise. `From:` ne le dit
//! pas — cet écart est toute la base de SPF, de DMARC et du traitement des
//! rebonds — et un filtre, un répondeur d'absence ou un logiciel de liste n'a
//! plus aucun moyen de le connaître.
//!
//! Le cas qui coûte le plus est `<>` : il dit « ceci est un rapport », et §2 de
//! RFC 3834 veut qu'un répondeur automatique s'en abstienne. Sans cette ligne,
//! un rebond reçu d'un tiers ne se distingue plus d'un message ordinaire.
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
//! Le nom du `HELO` et le chemin de retour sont ce que le pair a bien voulu
//! dire. Un `CRLF` glissé dans l'un ou l'autre écrirait un en-tête à notre
//! place, **en tête du message**, là où un lecteur croira que c'est nous qui
//! parlons. Ils sont donc vérifiés ici, et pas seulement à la grammaire : cette
//! crate ne suppose pas ce que son appelant a fait.

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

/// La place qu'un `Return-Path:` peut demander.
///
/// `Return-Path: <` puis un chemin de 256 octets (RFC 5321 §4.5.3.1.3), `>` et
/// la fin de ligne.
pub const RETURN_PATH_MAX: usize = 14 + 256 + 3;

/// Écrit le `Return-Path:` que le serveur de REMISE FINALE doit poser (§4.4).
///
/// `chemin` est l'expéditeur d'enveloppe sans ses chevrons. **Vide vaut `<>`**,
/// et ce n'est pas un détail : §2 de RFC 3834 veut qu'un répondeur automatique
/// se taise devant un chemin nul, et c'est cette ligne qui le lui apprend.
///
/// # POURQUOI CET EN-TÊTE, ET POURQUOI ICI
///
/// §4.4 en fait une exigence — « this use of return-path is required ». Sans
/// lui, l'expéditeur d'ENVELOPPE est perdu à la remise : `From:` ne le dit pas,
/// et cet écart est toute la base de SPF, de DMARC et du traitement des
/// rebonds. Un filtre, un répondeur d'absence ou un logiciel de liste n'a plus
/// aucun moyen de le connaître.
///
/// # UN `Return-Path:` FORGÉ PLUS BAS N'EST PAS RETIRÉ
///
/// C'est le même choix que pour un `Received:` forgé, et la même raison : la
/// frontière de confiance est « ce qui est au-dessus de ce que j'ai ajouté ».
/// Celui-ci s'écrivant en TÊTE, une bibliothèque qui rend la première occurrence
/// rend la nôtre. Retirer un en-tête au fil de l'écoulement demanderait de
/// réécrire le bloc pendant que DKIM le condense, pour une menace que la
/// position règle déjà.
///
/// # Errors
///
/// [`Error::NotPrintable`] si le chemin porte autre chose que de l'ASCII
/// visible, ou des chevrons — il ressort ici en tête du message, là où un octet
/// de trop parle sous notre nom ; [`Error::BufferTooSmall`] si `sortie` ne
/// suffit pas.
pub fn write_return_path<'b>(sortie: &'b mut [u8], chemin: &[u8]) -> Result<&'b [u8], Error> {
    // **CETTE CAISSE NE CROIT PAS SON APPELANT.** La session a déjà lu ce chemin
    // avec la grammaire de RFC 5321 ; on ne le suppose pas, parce qu'une
    // vérification faite ailleurs est une vérification qu'on ne voit pas en
    // lisant l'endroit qui en dépend.
    if chemin.len() > NOM_MAX
        || !chemin
            .iter()
            .all(|octet| octet.is_ascii_graphic() && !matches!(*octet, b'<' | b'>'))
    {
        return Err(Error::NotPrintable);
    }
    let mut plume = Plume {
        sortie,
        ecrits: 0,
        faute: None,
    };
    plume.pousser(b"Return-Path: <")?;
    plume.pousser(chemin)?;
    plume.pousser(b">\r\n")?;
    let ecrits = plume.ecrits;
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

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
