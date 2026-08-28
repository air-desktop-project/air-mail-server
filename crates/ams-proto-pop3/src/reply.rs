//! Les réponses POP3 : `+OK`, `-ERR`, et le doublement du point.

use crate::{Error, Limits};

/// Les deux seules réponses que POP3 connaisse.
///
/// # Il n'y a pas de code numérique, et c'est une chance
///
/// Un client ne peut pas distinguer « ce compte n'existe pas » de « ce mot de
/// passe est faux » autrement que par le texte. Nos refus n'en diront donc rien,
/// et il n'y a même pas de code à choisir pour trahir la différence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// `+OK`
    Ok,
    /// `-ERR`
    Err,
}

impl Status {
    /// Le marqueur, tel qu'il part sur le fil.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Status::Ok => b"+OK",
            Status::Err => b"-ERR",
        }
    }
}

/// Combien d'octets la réponse d'une ligne occupera.
///
/// # Errors
///
/// [`Error::ReplyTooLong`] si le texte ne tient pas sous la borne.
pub fn encoded_len(status: Status, text: &[u8], limits: &Limits) -> Result<usize, Error> {
    // L'enveloppe : le marqueur, puis `CRLF`. L'espace n'existe QUE s'il y a un
    // texte — `+OK\r\n` est une réponse licite, et y laisser une espace en
    // ferait une autre.
    let marqueur = status.as_bytes().len();
    let espace = usize::from(!text.is_empty());
    let enveloppe = marqueur.saturating_add(espace).saturating_add(2);
    let Some(texte_max) = limits.max_reply_octets.checked_sub(enveloppe) else {
        // UNE BORNE INFÉRIEURE À L'ENVELOPPE NE PEUT ÊTRE TENUE PAR AUCUNE
        // RÉPONSE, et il faut le dire plutôt que de la rabattre à zéro : une
        // saturation ferait passer les réponses vides sous une borne qui ne les
        // admet pas. C'est le défaut que le fuzz a trouvé côté SMTP.
        return Err(Error::ReplyTooLong {
            limit: limits.max_reply_octets,
        });
    };
    if text.len() > texte_max {
        return Err(Error::ReplyTooLong {
            limit: limits.max_reply_octets,
        });
    }
    // Un `CR` ou un `LF` DANS le texte ferait deux lignes d'une réponse, et la
    // seconde serait lue comme une réponse à autre chose.
    if text.iter().any(|&octet| octet == b'\r' || octet == b'\n') {
        return Err(Error::ReplyTooLong {
            limit: limits.max_reply_octets,
        });
    }
    Ok(enveloppe.saturating_add(text.len()))
}

/// Écrit une réponse d'une ligne.
///
/// # Errors
///
/// [`Error::ReplyTooLong`] ou [`Error::BufferTooSmall`].
pub fn encode<'b>(
    buffer: &'b mut [u8],
    status: Status,
    text: &[u8],
    limits: &Limits,
) -> Result<&'b [u8], Error> {
    let needed = encoded_len(status, text, limits)?;
    if buffer.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }
    let (cible, _) = buffer.split_at_mut(needed);

    // À partir d'ici l'écriture NE PEUT PLUS ÉCHOUER : `encoded_len` a validé le
    // texte et calculé la place exacte, et le tampon l'a. Chaque morceau est
    // découpé par `split_at_mut`, qui rend deux tranches dont la somme des
    // longueurs est connue — il n'y a donc aucun bras d'erreur à écrire, donc
    // aucun qu'un test ne pourrait emprunter.
    let marqueur = status.as_bytes();
    let (tete, reste) = cible.split_at_mut(marqueur.len());
    tete.copy_from_slice(marqueur);
    let (espace, reste) = reste.split_at_mut(usize::from(!text.is_empty()));
    if let Some(case) = espace.first_mut() {
        *case = b' ';
    }
    let (corps, fin) = reste.split_at_mut(text.len());
    corps.copy_from_slice(text);
    fin.copy_from_slice(b"\r\n");
    Ok(cible)
}

/// Combien d'octets une ligne de corps occupera une fois **doublée**.
///
/// RFC 1939 §3 : une ligne qui commence par `.` en reçoit un second, sans quoi
/// elle serait prise pour le terminateur `<CRLF>.<CRLF>`.
#[must_use]
pub fn stuffed_len(line: &[u8]) -> usize {
    let point = usize::from(line.first() == Some(&b'.'));
    line.len().saturating_add(point).saturating_add(2)
}

/// Écrit une ligne de corps, point doublé et `CRLF` compris.
///
/// # Le doublement est ici, et à un seul endroit
///
/// C'est la même règle qu'en SMTP, dans l'autre sens. L'écrire deux fois, c'est
/// se donner deux occasions de l'écrire différemment — et un point non doublé
/// termine le message au milieu, ce qu'un lecteur voit comme un message tronqué
/// suivi de commandes qui n'en sont pas.
///
/// # Errors
///
/// [`Error::BufferTooSmall`].
pub fn stuff_line<'b>(buffer: &'b mut [u8], line: &[u8]) -> Result<&'b [u8], Error> {
    let needed = stuffed_len(line);
    if buffer.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }
    let (cible, _) = buffer.split_at_mut(needed);

    // `split_at_mut` plutôt qu'un second emprunt : la tranche est consommée
    // morceau par morceau, et il n'y a aucun bras d'erreur à écrire — donc
    // aucun qu'un test ne pourrait emprunter.
    let (double, reste) = cible.split_at_mut(usize::from(line.first() == Some(&b'.')));
    if let Some(case) = double.first_mut() {
        *case = b'.';
    }
    let (corps, fin) = reste.split_at_mut(line.len());
    corps.copy_from_slice(line);
    fin.copy_from_slice(b"\r\n");
    Ok(cible)
}

#[cfg(test)]
mod tests {
    use super::{Status, encode, encoded_len, stuff_line, stuffed_len};
    use crate::{Error, Limits};

    fn ecrire<'b>(tampon: &'b mut [u8], status: Status, texte: &[u8]) -> Result<&'b [u8], Error> {
        encode(tampon, status, texte, &Limits::DEFAULT)
    }

    #[test]
    fn les_deux_reponses_s_ecrivent() {
        let mut tampon = [0_u8; 64];
        assert_eq!(
            ecrire(&mut tampon, Status::Ok, b"POP3 server ready"),
            Ok(&b"+OK POP3 server ready\r\n"[..])
        );
        let mut tampon = [0_u8; 64];
        assert_eq!(
            ecrire(&mut tampon, Status::Err, b"no such message"),
            Ok(&b"-ERR no such message\r\n"[..])
        );
    }

    #[test]
    fn une_reponse_sans_texte_n_a_pas_d_espace_en_trop() {
        // `+OK\r\n` est licite ; `+OK \r\n` est une autre réponse, et personne
        // n'a demandé celle-là.
        let mut tampon = [0_u8; 8];
        assert_eq!(ecrire(&mut tampon, Status::Ok, b""), Ok(&b"+OK\r\n"[..]));
        assert_eq!(encoded_len(Status::Ok, b"", &Limits::DEFAULT), Ok(5));
    }

    #[test]
    fn un_texte_trop_long_est_refuse() {
        let long = [b'a'; 512];
        assert_eq!(
            encoded_len(Status::Ok, &long, &Limits::DEFAULT),
            Err(Error::ReplyTooLong { limit: 512 })
        );
        // Et juste en dessous, il passe : `+OK ` (4) + texte + CRLF (2) = 512.
        let juste = [b'a'; 506];
        assert_eq!(encoded_len(Status::Ok, &juste, &Limits::DEFAULT), Ok(512));
    }

    #[test]
    fn une_borne_plus_petite_que_l_enveloppe_est_dite_et_non_rabattue() {
        // La saturation ferait passer les réponses vides sous une borne qui ne
        // les admet pas — le défaut que le fuzz a trouvé côté SMTP.
        let etroite = Limits {
            max_reply_octets: 3,
            ..Limits::DEFAULT
        };
        assert_eq!(
            encoded_len(Status::Ok, b"", &etroite),
            Err(Error::ReplyTooLong { limit: 3 })
        );
        // `-ERR` fait quatre octets : sous une borne de cinq, même vide, il ne
        // tient pas non plus (4 + 2 = 6).
        let cinq = Limits {
            max_reply_octets: 5,
            ..Limits::DEFAULT
        };
        assert_eq!(
            encoded_len(Status::Err, b"", &cinq),
            Err(Error::ReplyTooLong { limit: 5 })
        );
        assert_eq!(encoded_len(Status::Ok, b"", &cinq), Ok(5));
    }

    #[test]
    fn un_saut_de_ligne_dans_le_texte_est_refuse() {
        // Il ferait DEUX lignes d'une réponse, et la seconde serait lue comme
        // une réponse à autre chose.
        for texte in [&b"a\rb"[..], b"a\nb", b"a\r\nb"] {
            assert!(
                encoded_len(Status::Ok, texte, &Limits::DEFAULT).is_err(),
                "{texte:?}"
            );
        }
    }

    #[test]
    fn encode_refuse_ce_qu_encoded_len_refuse() {
        // Les deux ne doivent pas pouvoir diverger : `encode` commence par
        // demander la place à `encoded_len`, et lui rend son refus tel quel.
        let long = [b'a'; 512];
        let mut tampon = [0_u8; 1024];
        assert_eq!(
            ecrire(&mut tampon, Status::Ok, &long),
            Err(Error::ReplyTooLong { limit: 512 })
        );
    }

    #[test]
    fn un_tampon_trop_petit_est_dit_et_non_deborde() {
        let mut tampon = [0_u8; 4];
        assert_eq!(
            ecrire(&mut tampon, Status::Ok, b"ready"),
            Err(Error::BufferTooSmall { needed: 11 })
        );
    }

    #[test]
    fn un_point_en_tete_est_double() {
        // RFC 1939 §3. Sans cela, la ligne serait prise pour le terminateur, et
        // le message finirait au milieu.
        let mut tampon = [0_u8; 32];
        assert_eq!(
            stuff_line(&mut tampon, b".hidden"),
            Ok(&b"..hidden\r\n"[..])
        );
        assert_eq!(stuffed_len(b".hidden"), 10);
        // Le terminateur lui-même, s'il venait du message.
        let mut tampon = [0_u8; 8];
        assert_eq!(stuff_line(&mut tampon, b"."), Ok(&b"..\r\n"[..]));
    }

    #[test]
    fn une_ligne_ordinaire_n_est_pas_touchee() {
        let mut tampon = [0_u8; 32];
        assert_eq!(stuff_line(&mut tampon, b"bonjour"), Ok(&b"bonjour\r\n"[..]));
        assert_eq!(stuffed_len(b"bonjour"), 9);
        // Un point AILLEURS qu'en tête ne se double pas.
        assert_eq!(stuffed_len(b"a.b"), 5);
        // Et une ligne vide reste une ligne vide.
        let mut tampon = [0_u8; 8];
        assert_eq!(stuff_line(&mut tampon, b""), Ok(&b"\r\n"[..]));
        assert_eq!(stuffed_len(b""), 2);
    }

    #[test]
    fn un_tampon_trop_petit_pour_le_doublement_est_dit() {
        let mut tampon = [0_u8; 3];
        assert_eq!(
            stuff_line(&mut tampon, b".x"),
            Err(Error::BufferTooSmall { needed: 5 })
        );
    }

    #[test]
    fn le_marqueur_se_lit_et_se_compare() {
        assert_eq!(Status::Ok.as_bytes(), b"+OK");
        assert_eq!(Status::Err.as_bytes(), b"-ERR");
        assert_ne!(Status::Ok, Status::Err);
        let copie = Status::Ok;
        assert_eq!(copie, Status::Ok);
    }
}
