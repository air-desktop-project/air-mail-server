//! Les commandes POP3 (RFC 1939 §5, RFC 2449, RFC 2595).

use crate::{Error, Limits};

/// Un numéro de message, tel que la RFC 1939 §5 les numérote.
///
/// **Jamais nul** : la numérotation commence à un, et accepter zéro obligerait
/// chaque appelant à s'en méfier une fois de plus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MessageNumber(core::num::NonZeroU32);

impl MessageNumber {
    /// Construit un numéro, s'il n'est pas nul.
    #[must_use]
    pub const fn new(valeur: u32) -> Option<Self> {
        match core::num::NonZeroU32::new(valeur) {
            Some(non_nul) => Some(Self(non_nul)),
            None => None,
        }
    }

    /// Sa valeur.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0.get()
    }
}

/// Une commande POP3.
///
/// Pas `#[non_exhaustive]`, pour la même raison que la commande SMTP : dans un
/// workspace qui avance d'un bloc, ce marqueur transforme une erreur de
/// compilation utile en un bras `_` silencieux et un trou de couverture
/// permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command<'a> {
    /// `USER <nom>` — la moitié d'une ouverture de session.
    User(&'a [u8]),
    /// `PASS <mot de passe>` — l'autre moitié.
    ///
    /// Le mot de passe traverse le fil **tel quel** : la session le refuse hors
    /// chiffrement, sans réglage possible (C6).
    Pass(&'a [u8]),
    /// `STLS` (RFC 2595 §4) — passer en TLS.
    Stls,
    /// `CAPA` (RFC 2449) — annoncer ce qui est servi.
    Capa,
    /// `STAT` — combien de messages, combien d'octets.
    Stat,
    /// `LIST [msg]` — la taille d'un message, ou de tous.
    List(Option<MessageNumber>),
    /// `UIDL [msg]` — l'identifiant durable d'un message, ou de tous.
    Uidl(Option<MessageNumber>),
    /// `RETR msg` — le message entier.
    Retr(MessageNumber),
    /// `TOP msg n` — l'en-tête, puis `n` lignes de corps.
    Top {
        /// Le message.
        message: MessageNumber,
        /// Combien de lignes de corps. **Zéro est licite** : c'est ainsi qu'un
        /// client demande l'en-tête seul, et c'est le cas le plus courant.
        lines: u32,
    },
    /// `DELE msg` — marquer pour effacement.
    Dele(MessageNumber),
    /// `NOOP` — ne rien faire.
    Noop,
    /// `RSET` — oublier les marques d'effacement.
    Rset,
    /// `QUIT` — fermer, et effacer ce qui est marqué.
    Quit,
}

impl<'a> Command<'a> {
    /// Lit une ligne de commande, **CRLF compris**.
    ///
    /// # Le `CRLF` est EXIGÉ, et un `LF` nu ne suffit pas
    ///
    /// C'est la même discipline qu'en SMTP, et pour la même raison : deux
    /// lecteurs qui ne s'accordent pas sur ce qui termine une ligne peuvent être
    /// amenés à découper le même flux en deux séries de commandes différentes.
    /// La RFC 1939 §3 dit `CRLF` ; c'est `CRLF`.
    ///
    /// # Errors
    ///
    /// [`Error`].
    pub fn parse(line: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        parse(line, limits)
    }
}

/// Le corps de [`Command::parse`].
fn parse<'a>(line: &'a [u8], limits: &Limits) -> Result<Command<'a>, Error> {
    if line.len() > limits.max_command_octets {
        return Err(Error::MalformedLine);
    }
    let corps = line.strip_suffix(b"\r\n").ok_or(Error::MalformedLine)?;
    // Un `CR` ou un `LF` AILLEURS que dans le terminateur : ce n'est pas une
    // ligne, c'est deux lignes qu'un lecteur plus tolérant lirait autrement.
    if corps.iter().any(|&octet| octet == b'\r' || octet == b'\n') {
        return Err(Error::MalformedLine);
    }

    let (verbe, reste) = match corps.iter().position(|&octet| octet == b' ') {
        Some(at) => (
            corps.get(..at).unwrap_or_default(),
            corps.get(at.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (corps, &[][..]),
    };

    // RFC 1939 §3 : les verbes sont insensibles à la casse. Quatre lettres au
    // plus, ce qui tient dans un tampon fixe — la crate n'alloue pas.
    let mut majuscules = [0_u8; 4];
    if verbe.is_empty() || verbe.len() > majuscules.len() {
        return Err(Error::UnknownCommand);
    }
    for (case, &octet) in majuscules.iter_mut().zip(verbe) {
        *case = octet.to_ascii_uppercase();
    }
    let verbe = majuscules.get(..verbe.len()).unwrap_or_default();

    match verbe {
        b"USER" => Ok(Command::User(argument(reste, limits)?)),
        b"PASS" => Ok(Command::Pass(mot_de_passe(reste, limits)?)),
        b"STLS" => sans_argument(reste, Command::Stls),
        b"CAPA" => sans_argument(reste, Command::Capa),
        b"STAT" => sans_argument(reste, Command::Stat),
        b"NOOP" => sans_argument(reste, Command::Noop),
        b"RSET" => sans_argument(reste, Command::Rset),
        b"QUIT" => sans_argument(reste, Command::Quit),
        b"LIST" => Ok(Command::List(numero_optionnel(reste)?)),
        b"UIDL" => Ok(Command::Uidl(numero_optionnel(reste)?)),
        b"RETR" => Ok(Command::Retr(numero(reste)?)),
        b"DELE" => Ok(Command::Dele(numero(reste)?)),
        b"TOP" => top(reste),
        // `APOP` est CONNU et REFUSÉ, et le distinguer d'un verbe inconnu n'a
        // aucun intérêt : la session répondra `-ERR` dans les deux cas, et un
        // pair qui apprendrait qu'`APOP` est « reconnu mais désactivé »
        // réessaierait. C6 l'exclut ; il n'existe pas ici.
        _ => Err(Error::UnknownCommand),
    }
}

/// Une commande qui n'admet aucun argument.
fn sans_argument<'a>(reste: &[u8], commande: Command<'a>) -> Result<Command<'a>, Error> {
    if reste.is_empty() {
        Ok(commande)
    } else {
        Err(Error::MalformedArguments)
    }
}

/// Un argument simple, non vide et sans espace.
fn argument<'a>(reste: &'a [u8], limits: &Limits) -> Result<&'a [u8], Error> {
    if reste.is_empty() {
        return Err(Error::MalformedArguments);
    }
    if reste.len() > limits.max_argument_octets {
        return Err(Error::ArgumentTooLong);
    }
    if reste.contains(&b' ') {
        return Err(Error::MalformedArguments);
    }
    Ok(reste)
}

/// Le mot de passe : tout ce qui suit l'espace, **espaces compris**.
///
/// RFC 1939 §7 : `PASS` prend le reste de la ligne. Un mot de passe qui
/// contient une espace est parfaitement légitime, et le refuser fermerait la
/// porte à des mots de passe plus solides que les autres.
fn mot_de_passe<'a>(reste: &'a [u8], limits: &Limits) -> Result<&'a [u8], Error> {
    if reste.is_empty() {
        return Err(Error::MalformedArguments);
    }
    if reste.len() > limits.max_argument_octets {
        return Err(Error::ArgumentTooLong);
    }
    Ok(reste)
}

/// Un numéro de message obligatoire.
fn numero(reste: &[u8]) -> Result<MessageNumber, Error> {
    let valeur = entier(reste)?;
    MessageNumber::new(valeur).ok_or(Error::MalformedMessageNumber)
}

/// Un numéro de message facultatif.
fn numero_optionnel(reste: &[u8]) -> Result<Option<MessageNumber>, Error> {
    if reste.is_empty() {
        return Ok(None);
    }
    numero(reste).map(Some)
}

/// `TOP msg n`.
fn top<'a>(reste: &[u8]) -> Result<Command<'a>, Error> {
    let at = reste
        .iter()
        .position(|&octet| octet == b' ')
        .ok_or(Error::MalformedArguments)?;
    let message = numero(reste.get(..at).unwrap_or_default())?;
    // `n` PEUT ÊTRE NUL : c'est ainsi qu'un client demande l'en-tête seul, et
    // c'est le cas le plus courant. Il ne passe donc pas par `numero`.
    let lines = entier(reste.get(at.saturating_add(1)..).unwrap_or_default())?;
    Ok(Command::Top { message, lines })
}

/// Un entier décimal, **sans zéro en tête**.
///
/// # Une écriture par valeur
///
/// `01` et `1` désignent le même message, et les accepter tous deux donnerait
/// deux écritures pour une valeur — de quoi passer à côté d'un journal ou d'un
/// comptage qui compare les formes. Aucun client n'émet de zéro en tête ; la
/// stricte n'interdit donc rien de réel. `0` seul reste licite là où zéro a un
/// sens, c'est-à-dire pour le compte de lignes de `TOP`.
fn entier(brut: &[u8]) -> Result<u32, Error> {
    if brut.is_empty() {
        return Err(Error::MalformedMessageNumber);
    }
    if brut.len() > 1 && brut.first() == Some(&b'0') {
        return Err(Error::MalformedMessageNumber);
    }
    let mut valeur = 0_u32;
    for &octet in brut {
        let chiffre = octet
            .checked_sub(b'0')
            .filter(|&chiffre| chiffre <= 9)
            .ok_or(Error::MalformedMessageNumber)?;
        valeur = valeur
            .checked_mul(10)
            .and_then(|dizaines| dizaines.checked_add(u32::from(chiffre)))
            .ok_or(Error::MalformedMessageNumber)?;
    }
    Ok(valeur)
}

#[cfg(test)]
mod tests {
    use super::{Command, MessageNumber};
    use crate::{Error, Limits};

    fn lire(ligne: &[u8]) -> Result<Command<'_>, Error> {
        Command::parse(ligne, &Limits::DEFAULT)
    }

    fn numero(valeur: u32) -> MessageNumber {
        MessageNumber::new(valeur).expect("non nul")
    }

    /// Compose `<verbe> <a×n>\r\n` dans un tampon FIXE : la crate est `no_std`
    /// SANS `alloc`, et ses tests le sont aussi.
    fn ligne_longue<const N: usize>(verbe: &[u8], remplissage: usize) -> [u8; N] {
        let mut ligne = [b'a'; N];
        ligne[..verbe.len()].copy_from_slice(verbe);
        ligne[verbe.len()] = b' ';
        let fin = verbe.len().saturating_add(1).saturating_add(remplissage);
        ligne[fin..].copy_from_slice(b"\r\n");
        ligne
    }

    #[test]
    fn les_verbes_sans_argument_se_lisent() {
        for (ligne, attendue) in [
            (&b"STLS\r\n"[..], Command::Stls),
            (b"CAPA\r\n", Command::Capa),
            (b"STAT\r\n", Command::Stat),
            (b"NOOP\r\n", Command::Noop),
            (b"RSET\r\n", Command::Rset),
            (b"QUIT\r\n", Command::Quit),
        ] {
            assert_eq!(lire(ligne), Ok(attendue), "{ligne:?}");
        }
    }

    #[test]
    fn les_verbes_sont_insensibles_a_la_casse() {
        // RFC 1939 §3. Le verbe est replié dans un tampon de quatre octets —
        // aucun verbe POP3 n'est plus long.
        for ligne in [&b"quit\r\n"[..], b"QuIt\r\n", b"QUIT\r\n"] {
            assert_eq!(lire(ligne), Ok(Command::Quit), "{ligne:?}");
        }
    }

    #[test]
    fn un_verbe_sans_argument_en_refuse_un() {
        assert_eq!(lire(b"QUIT maintenant\r\n"), Err(Error::MalformedArguments));
        assert_eq!(lire(b"CAPA x\r\n"), Err(Error::MalformedArguments));
    }

    #[test]
    fn user_et_pass_portent_leurs_arguments() {
        assert_eq!(lire(b"USER jean\r\n"), Ok(Command::User(b"jean")));
        assert_eq!(lire(b"PASS ouvre-toi\r\n"), Ok(Command::Pass(b"ouvre-toi")));
    }

    #[test]
    fn un_mot_de_passe_peut_contenir_des_espaces() {
        // RFC 1939 §7 : `PASS` prend le RESTE de la ligne. Refuser les espaces
        // fermerait la porte à des mots de passe plus solides que les autres.
        assert_eq!(
            lire(b"PASS mon mot de passe\r\n"),
            Ok(Command::Pass(b"mon mot de passe"))
        );
        // `USER`, lui, n'en admet pas : un nom de compte n'en contient pas, et
        // en accepter ferait diverger la lecture de celle du magasin.
        assert_eq!(lire(b"USER jean paul\r\n"), Err(Error::MalformedArguments));
    }

    #[test]
    fn un_argument_vide_ou_trop_long_est_refuse() {
        assert_eq!(lire(b"USER\r\n"), Err(Error::MalformedArguments));
        assert_eq!(lire(b"USER \r\n"), Err(Error::MalformedArguments));
        assert_eq!(lire(b"PASS\r\n"), Err(Error::MalformedArguments));
        // `USER ` + 65 octets + CRLF = 72.
        let ligne: [u8; 72] = ligne_longue(b"USER", 65);
        assert_eq!(lire(&ligne), Err(Error::ArgumentTooLong));
        let ligne: [u8; 72] = ligne_longue(b"PASS", 65);
        assert_eq!(lire(&ligne), Err(Error::ArgumentTooLong));
    }

    #[test]
    fn les_commandes_a_numero_se_lisent() {
        assert_eq!(lire(b"RETR 1\r\n"), Ok(Command::Retr(numero(1))));
        assert_eq!(lire(b"DELE 42\r\n"), Ok(Command::Dele(numero(42))));
        assert_eq!(lire(b"LIST\r\n"), Ok(Command::List(None)));
        assert_eq!(lire(b"LIST 7\r\n"), Ok(Command::List(Some(numero(7)))));
        assert_eq!(lire(b"UIDL\r\n"), Ok(Command::Uidl(None)));
        assert_eq!(lire(b"UIDL 7\r\n"), Ok(Command::Uidl(Some(numero(7)))));
    }

    #[test]
    fn zero_n_est_pas_un_numero_de_message() {
        // La RFC 1939 §5 numérote à partir de un. Accepter zéro obligerait
        // chaque appelant à s'en méfier une fois de plus.
        for ligne in [
            &b"RETR 0\r\n"[..],
            b"DELE 0\r\n",
            b"LIST 0\r\n",
            b"UIDL 0\r\n",
        ] {
            assert_eq!(lire(ligne), Err(Error::MalformedMessageNumber), "{ligne:?}");
        }
    }

    #[test]
    fn un_numero_a_une_ecriture_et_une_seule() {
        // `01` et `1` désignent le même message. Deux écritures pour une valeur,
        // c'est une de trop — et aucun client n'émet de zéro en tête.
        assert_eq!(lire(b"RETR 01\r\n"), Err(Error::MalformedMessageNumber));
        assert_eq!(lire(b"RETR +1\r\n"), Err(Error::MalformedMessageNumber));
        assert_eq!(lire(b"RETR 1x\r\n"), Err(Error::MalformedMessageNumber));
        assert_eq!(lire(b"RETR \r\n"), Err(Error::MalformedMessageNumber));
        assert_eq!(lire(b"RETR\r\n"), Err(Error::MalformedMessageNumber));
        // Et un nombre qui déborde `u32` n'est pas un numéro non plus.
        assert_eq!(
            lire(b"RETR 4294967296\r\n"),
            Err(Error::MalformedMessageNumber)
        );
        assert_eq!(
            lire(b"RETR 99999999999999999999\r\n"),
            Err(Error::MalformedMessageNumber)
        );
        assert_eq!(
            lire(b"RETR 4294967295\r\n"),
            Ok(Command::Retr(numero(u32::MAX)))
        );
    }

    #[test]
    fn top_prend_un_message_et_un_compte_de_lignes_qui_peut_etre_nul() {
        assert_eq!(
            lire(b"TOP 3 0\r\n"),
            Ok(Command::Top {
                message: numero(3),
                lines: 0
            })
        );
        assert_eq!(
            lire(b"TOP 3 20\r\n"),
            Ok(Command::Top {
                message: numero(3),
                lines: 20
            })
        );
        // Il en faut DEUX.
        assert_eq!(lire(b"TOP 3\r\n"), Err(Error::MalformedArguments));
        assert_eq!(lire(b"TOP\r\n"), Err(Error::MalformedArguments));
        assert_eq!(lire(b"TOP 0 5\r\n"), Err(Error::MalformedMessageNumber));
        assert_eq!(lire(b"TOP 3 x\r\n"), Err(Error::MalformedMessageNumber));
    }

    #[test]
    fn apop_n_existe_pas_ici() {
        // C6 l'exclut : MD5, et surtout l'obligation de garder le mot de passe
        // EN CLAIR côté serveur. Le distinguer d'un verbe inconnu ferait
        // réessayer un pair à qui l'on aurait appris qu'il est « désactivé ».
        assert_eq!(lire(b"APOP jean abcdef\r\n"), Err(Error::UnknownCommand));
    }

    #[test]
    fn un_verbe_inconnu_ou_absent_est_refuse() {
        for ligne in [&b"XYZZY\r\n"[..], b"\r\n", b" \r\n", b"TOOLONGVERB\r\n"] {
            assert_eq!(lire(ligne), Err(Error::UnknownCommand), "{ligne:?}");
        }
    }

    #[test]
    fn le_crlf_est_exige_et_rien_d_autre_ne_le_remplace() {
        // Deux lecteurs qui ne s'accordent pas sur ce qui termine une ligne
        // peuvent découper le même flux en deux séries de commandes
        // différentes. C'est le contrebandage, et il se joue là.
        for ligne in [
            &b"QUIT"[..],
            b"QUIT\n",
            b"QUIT\r",
            b"QU\nIT\r\n",
            b"QU\rIT\r\n",
        ] {
            assert_eq!(lire(ligne), Err(Error::MalformedLine), "{ligne:?}");
        }
    }

    #[test]
    fn une_ligne_trop_longue_est_refusee_sans_dire_la_borne() {
        // `USER ` + 600 octets + CRLF = 607, au-delà des 512 de la RFC.
        let ligne: [u8; 607] = ligne_longue(b"USER", 600);
        assert_eq!(lire(&ligne), Err(Error::MalformedLine));
    }

    #[test]
    fn un_numero_se_construit_et_se_compare() {
        assert_eq!(MessageNumber::new(0), None);
        assert_eq!(numero(3).value(), 3);
        assert!(numero(2) < numero(3));
        let copie = numero(2);
        assert_eq!(copie, numero(2));
    }
}
