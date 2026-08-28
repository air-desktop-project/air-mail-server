//! Encodage des réponses (RFC 5321 §4.2).

use crate::{Error, Limits};

/// Le code à trois chiffres d'une réponse.
///
/// C'est un type, et non un `u16`, pour une raison précise : [`encode`] ne peut
/// pas recevoir un code invalide, donc n'a pas à s'en défendre. La validation a
/// lieu une fois, à la construction, comme partout ailleurs dans cette crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Code(u16);

/// La famille d'un code, qui dit au pair ce qu'il doit faire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// `2yz` — la commande a abouti.
    Positive,
    /// `3yz` — la commande est acceptée, la suite est attendue.
    Intermediate,
    /// `4yz` — échec **temporaire** : réessayer plus tard a un sens.
    TransientFailure,
    /// `5yz` — échec **permanent** : réessayer à l'identique n'en a aucun.
    PermanentFailure,
}

impl Code {
    /// Construit un code.
    ///
    /// Rend `None` hors de `200..=599`. Les codes `1yz` sont exclus : la
    /// RFC 5321 §4.2.1 les définit comme « réponse préliminaire positive » et
    /// ajoute que **SMTP n'en émet aucun**. En émettre un laisserait le pair
    /// attendre une seconde réponse qui ne viendrait jamais.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        if 200 <= value && value <= 599 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// La valeur numérique.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// La famille du code.
    #[must_use]
    pub const fn class(self) -> Class {
        match self.0 {
            200..=299 => Class::Positive,
            300..=399 => Class::Intermediate,
            400..=499 => Class::TransientFailure,
            // Par construction, il ne reste que `500..=599`.
            _ => Class::PermanentFailure,
        }
    }

    /// `220` — le service est prêt.
    pub const SERVICE_READY: Self = Self(220);
    /// `221` — le service ferme le canal de transmission.
    pub const CLOSING: Self = Self(221);
    /// `235` — authentification réussie (RFC 4954 §6).
    pub const AUTH_SUCCEEDED: Self = Self(235);
    /// `250` — la commande a abouti.
    pub const OK: Self = Self(250);
    /// `334` — défi d'authentification (RFC 4954 §4).
    pub const AUTH_CHALLENGE: Self = Self(334);
    /// `354` — le corps du message est attendu, terminé par `<CRLF>.<CRLF>`.
    pub const START_MAIL_INPUT: Self = Self(354);
    /// `421` — le service ferme le canal, indisponible.
    pub const SERVICE_CLOSING: Self = Self(421);
    /// `450` — boîte indisponible pour l'instant.
    pub const MAILBOX_BUSY: Self = Self(450);
    /// `451` — l'action locale a échoué.
    pub const LOCAL_ERROR: Self = Self(451);
    /// `452` — place insuffisante.
    pub const INSUFFICIENT_STORAGE: Self = Self(452);
    /// `454` — `STARTTLS` indisponible pour l'instant (RFC 3207 §4).
    pub const TLS_UNAVAILABLE: Self = Self(454);
    /// `500` — erreur de syntaxe : la commande n'a pas été comprise.
    pub const SYNTAX_ERROR: Self = Self(500);
    /// `501` — erreur de syntaxe dans les arguments.
    pub const ARGUMENT_ERROR: Self = Self(501);
    /// `502` — commande comprise, mais **non servie**.
    pub const NOT_IMPLEMENTED: Self = Self(502);
    /// `503` — mauvaise séquence de commandes.
    pub const BAD_SEQUENCE: Self = Self(503);
    /// `530` — authentification requise (RFC 4954 §6).
    pub const AUTH_REQUIRED: Self = Self(530);
    /// `538` — chiffrement requis pour ce mécanisme (RFC 4954 §6).
    pub const ENCRYPTION_REQUIRED: Self = Self(538);
    /// `550` — boîte indisponible : action non effectuée.
    pub const MAILBOX_UNAVAILABLE: Self = Self(550);
    /// `554` — la transaction a échoué.
    pub const TRANSACTION_FAILED: Self = Self(554);
}

/// Le nombre d'octets qu'occuperait la réponse encodée.
///
/// Valide `code` et `lines` **entièrement** : si cette fonction rend `Ok`,
/// [`encode`] n'échouera que sur un tampon trop petit.
///
/// # Errors
///
/// [`Error::EmptyReply`], [`Error::ReplyTextNotPrintable`],
/// [`Error::ReplyLineTooLong`].
pub fn encoded_len(lines: &[&[u8]], limits: &Limits) -> Result<usize, Error> {
    if lines.is_empty() {
        return Err(Error::EmptyReply);
    }
    // `3` pour le code, `1` pour le séparateur, `2` pour le CRLF. Cette
    // enveloppe est INCONDITIONNELLE : aucune ligne, pas même vide, ne coûte
    // moins.
    let enveloppe = 6_usize;
    let Some(texte_max) = limits.max_reply_octets.checked_sub(enveloppe) else {
        // UNE BORNE INFÉRIEURE À L'ENVELOPPE NE PEUT ÊTRE TENUE PAR AUCUNE
        // LIGNE, et il faut le dire plutôt que de la rabattre à zéro.
        //
        // La première rédaction employait `saturating_sub`, par la même habitude
        // qui, ailleurs dans cette crate, évite une branche que rien ne pourrait
        // exercer. Ici la branche EST exerçable — `max_reply_octets` vient de la
        // configuration (C8), donc d'un administrateur qui peut y écrire `3` —
        // et la saturation transformait « aucune ligne ne tient » en « les
        // lignes vides tiennent ». L'encodeur émettait alors six octets sous une
        // borne de trois. Trouvé par `fuzz_ams_smtp_reply` en soixante secondes.
        return Err(Error::ReplyLineTooLong {
            limit: limits.max_reply_octets,
        });
    };
    let mut total = 0_usize;
    for texte in lines {
        if texte.len() > texte_max {
            return Err(Error::ReplyLineTooLong {
                limit: limits.max_reply_octets,
            });
        }
        check_text(texte)?;
        total = total.saturating_add(enveloppe).saturating_add(texte.len());
    }
    Ok(total)
}

/// Encode une réponse dans `buffer`, et rend la tranche écrite.
///
/// Chaque élément de `lines` devient une ligne. Toutes portent le même code ;
/// **seule la dernière porte une espace** après le code, les autres un tiret —
/// c'est ce tiret qui dit au pair que la réponse continue. Un `lines` vide est
/// refusé : sans dernière ligne, le pair attendrait indéfiniment.
///
/// ```
/// use ams_proto_smtp::{Code, Limits, encode};
///
/// let mut tampon = [0_u8; 128];
/// let ecrit = encode(
///     &mut tampon,
///     Code::OK,
///     &[b"example.com", b"SIZE 10485760", b"STARTTLS"],
///     &Limits::DEFAULT,
/// )
/// .expect("réponse encodable");
///
/// assert_eq!(
///     ecrit,
///     b"250-example.com\r\n250-SIZE 10485760\r\n250 STARTTLS\r\n"
/// );
/// ```
///
/// # Errors
///
/// Celles d'[`encoded_len`], plus [`Error::BufferTooSmall`].
pub fn encode<'b>(
    buffer: &'b mut [u8],
    code: Code,
    lines: &[&[u8]],
    limits: &Limits,
) -> Result<&'b [u8], Error> {
    let needed = encoded_len(lines, limits)?;
    if buffer.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    // À partir d'ici l'écriture NE PEUT PLUS ÉCHOUER : `encoded_len` a validé
    // chaque ligne et calculé la place exacte, et le tampon l'a. On indexe donc
    // sans se défendre — un `if let` ouvrirait ici une branche que rien ne
    // saurait exercer, et le 100 % de C2 la compterait à jamais découverte.
    let chiffres = digits(code.value());
    let mut ecrit = 0_usize;
    let dernier = lines.len().saturating_sub(1);
    for (rang, texte) in lines.iter().enumerate() {
        let separateur = if rang == dernier { b' ' } else { b'-' };
        ecrit = push(buffer, ecrit, &chiffres);
        ecrit = push(buffer, ecrit, &[separateur]);
        ecrit = push(buffer, ecrit, texte);
        ecrit = push(buffer, ecrit, b"\r\n");
    }
    Ok(buffer.get(..ecrit).unwrap_or_default())
}

/// Copie `octets` à `depuis`, et rend la nouvelle position.
fn push(buffer: &mut [u8], depuis: usize, octets: &[u8]) -> usize {
    let fin = depuis.saturating_add(octets.len());
    buffer[depuis..fin].copy_from_slice(octets);
    fin
}

/// Les trois chiffres décimaux d'un code.
fn digits(code: u16) -> [u8; 3] {
    let borne = code.min(999);
    [
        borne.wrapping_div(100),
        borne.wrapping_div(10).wrapping_rem(10),
        borne.wrapping_rem(10),
    ]
    // Chaque chiffre vaut `0..=9`, donc tient dans un `u8`.
    .map(|chiffre| u8::try_from(chiffre).unwrap_or(0).wrapping_add(b'0'))
}

/// `textstring = 1*(%d09 / %d32-126)` (RFC 5321 §4.1.2), ou vide.
///
/// # Pourquoi cette vérification porte tout le reste
///
/// Une réponse contient souvent ce que le client vient d'envoyer. Un CR ou un LF
/// qui y passerait lui laisserait écrire une ligne de réponse entière de son
/// choix — et donc mentir à ce qui lit la connexion derrière lui.
///
/// L'alphabet est **US-ASCII**. Servir `SMTPUTF8` (RFC 6531) demanderait de
/// l'élargir, et ce serait une décision à prendre, pas un assouplissement à
/// laisser glisser.
fn check_text(texte: &[u8]) -> Result<(), Error> {
    if texte
        .iter()
        .all(|&octet| octet == 9 || (32..=126).contains(&octet))
    {
        Ok(())
    } else {
        Err(Error::ReplyTextNotPrintable)
    }
}

#[cfg(test)]
mod tests {
    use super::{Class, Code, encode, encoded_len};
    use crate::{Error, Limits};

    fn encoder<'b>(tampon: &'b mut [u8], code: Code, lignes: &[&[u8]]) -> Result<&'b [u8], Error> {
        encode(tampon, code, lignes, &Limits::DEFAULT)
    }

    // ── Le code ─────────────────────────────────────────────────────────────

    #[test]
    fn seuls_les_codes_de_200_a_599_existent() {
        // Les `1yz` sont exclus : la RFC 5321 §4.2.1 les définit, et ajoute que
        // SMTP n'en émet aucun. En émettre un ferait attendre le pair.
        assert_eq!(Code::new(199), None);
        assert_eq!(Code::new(600), None);
        assert_eq!(Code::new(0), None);
        assert_eq!(Code::new(200).map(Code::value), Some(200));
        assert_eq!(Code::new(599).map(Code::value), Some(599));
    }

    #[test]
    fn la_famille_du_code_couvre_les_quatre_cas() {
        assert_eq!(Code::OK.class(), Class::Positive);
        assert_eq!(Code::START_MAIL_INPUT.class(), Class::Intermediate);
        assert_eq!(Code::MAILBOX_BUSY.class(), Class::TransientFailure);
        assert_eq!(Code::MAILBOX_UNAVAILABLE.class(), Class::PermanentFailure);
    }

    #[test]
    fn la_distinction_4yz_5yz_est_celle_qui_compte_pour_le_pair() {
        // `4yz` : réessayer plus tard a un sens. `5yz` : réessayer à l'identique
        // n'en a aucun. Les confondre fait soit perdre un message, soit boucler.
        assert_ne!(
            Code::MAILBOX_BUSY.class(),
            Code::MAILBOX_UNAVAILABLE.class()
        );
        assert_eq!(Code::MAILBOX_BUSY.value(), 450);
        assert_eq!(Code::MAILBOX_UNAVAILABLE.value(), 550);
    }

    #[test]
    fn les_codes_se_copient_se_comparent_et_s_ordonnent() {
        let code = Code::OK;
        let copie = code;
        assert_eq!(copie, code);
        assert!(Code::SERVICE_READY < Code::OK);
        assert!(!std::format!("{code:?}").is_empty());
        assert!(!std::format!("{:?}", Class::Positive).is_empty());
    }

    // ── L'encodage ──────────────────────────────────────────────────────────

    #[test]
    fn une_reponse_d_une_ligne_porte_une_espace() {
        let mut tampon = [0_u8; 64];
        assert_eq!(
            encoder(&mut tampon, Code::OK, &[b"OK"]).expect("encodable"),
            b"250 OK\r\n"
        );
    }

    #[test]
    fn une_reponse_multiligne_porte_des_tirets_sauf_a_la_fin() {
        // C'est le tiret qui dit au pair que la réponse continue. La dernière
        // ligne, et elle seule, porte une espace.
        let mut tampon = [0_u8; 128];
        assert_eq!(
            encoder(
                &mut tampon,
                Code::OK,
                &[b"example.com", b"SIZE 10485760", b"STARTTLS"]
            )
            .expect("encodable"),
            b"250-example.com\r\n250-SIZE 10485760\r\n250 STARTTLS\r\n"
        );
    }

    #[test]
    fn un_texte_vide_reste_une_ligne_licite() {
        // L'ABNF rend le texte FACULTATIF : `250 \r\n` est une réponse valide.
        let mut tampon = [0_u8; 16];
        assert_eq!(
            encoder(&mut tampon, Code::OK, &[b""]).expect("encodable"),
            b"250 \r\n"
        );
    }

    #[test]
    fn les_trois_chiffres_sont_ceux_du_code() {
        let mut tampon = [0_u8; 16];
        for code in [
            Code::SERVICE_READY,
            Code::AUTH_CHALLENGE,
            Code::TRANSACTION_FAILED,
        ] {
            let ecrit = encoder(&mut tampon, code, &[b""]).expect("encodable");
            let attendu = std::format!("{} \r\n", code.value());
            assert_eq!(ecrit, attendu.as_bytes());
        }
    }

    // ── Ce que l'encodeur refuse ────────────────────────────────────────────

    #[test]
    fn un_cr_ou_un_lf_dans_le_texte_est_refuse() {
        // LE REFUS QUI PORTE TOUT LE RESTE. Une réponse contient souvent ce que
        // le client vient d'envoyer ; un CR qui y passerait lui laisserait écrire
        // une ligne de réponse entière de son choix.
        let mut tampon = [0_u8; 128];
        for injection in [
            b"<x@y.z>\r\n250 injecte".as_slice(),
            b"avant\rapres",
            b"avant\napres",
        ] {
            assert_eq!(
                encoder(&mut tampon, Code::MAILBOX_UNAVAILABLE, &[injection]),
                Err(Error::ReplyTextNotPrintable),
                "{injection:?} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn les_octets_hors_de_textstring_sont_refuses() {
        let mut tampon = [0_u8; 64];
        for mauvais in [
            b"\x00".as_slice(), // NUL
            b"\x1b[31m",        // séquence d'échappement de terminal
            b"\x7f",            // DEL
            "é".as_bytes(),     // hors US-ASCII : servir SMTPUTF8 est une décision
        ] {
            assert_eq!(
                encoder(&mut tampon, Code::OK, &[mauvais]),
                Err(Error::ReplyTextNotPrintable),
                "{mauvais:?} aurait dû être refusé"
            );
        }
        // HTAB et les bornes de l'imprimable, elles, passent.
        assert!(encoder(&mut tampon, Code::OK, &[b"\ta ~"]).is_ok());
    }

    #[test]
    fn une_reponse_sans_ligne_est_refusee() {
        // Sans dernière ligne, le pair attendrait indéfiniment.
        let mut tampon = [0_u8; 16];
        assert_eq!(encoder(&mut tampon, Code::OK, &[]), Err(Error::EmptyReply));
        assert_eq!(encoded_len(&[], &Limits::DEFAULT), Err(Error::EmptyReply));
    }

    #[test]
    fn une_ligne_trop_longue_est_refusee() {
        // RFC 5321 §4.5.3.1.5 : 512 octets, CRLF compris — soit 506 de texte.
        let mut tampon = [0_u8; 1024];
        let juste = std::vec![b'a'; 506];
        assert!(encoder(&mut tampon, Code::OK, &[&juste]).is_ok());

        let trop = std::vec![b'a'; 507];
        assert_eq!(
            encoder(&mut tampon, Code::OK, &[&trop]),
            Err(Error::ReplyLineTooLong { limit: 512 })
        );
    }

    #[test]
    fn une_borne_inferieure_a_l_enveloppe_ne_laisse_passer_aucune_ligne() {
        // L'enveloppe — code, séparateur, CRLF — coûte six octets, toujours. Une
        // borne plus petite ne peut être tenue par aucune ligne, PAS MÊME VIDE.
        // Rabattre la borne à zéro y ferait passer les lignes vides, et
        // l'encodeur émettrait six octets sous une borne de trois.
        let etroites = Limits {
            max_reply_octets: 3,
            ..Limits::DEFAULT
        };
        assert_eq!(
            encoded_len(&[b""], &etroites),
            Err(Error::ReplyLineTooLong { limit: 3 })
        );
        let mut tampon = [0_u8; 64];
        assert_eq!(
            encode(&mut tampon, Code::OK, &[b""], &etroites),
            Err(Error::ReplyLineTooLong { limit: 3 })
        );

        // Six octets exactement suffisent pour une ligne vide.
        let justes = Limits {
            max_reply_octets: 6,
            ..Limits::DEFAULT
        };
        assert_eq!(encoded_len(&[b""], &justes), Ok(6));
    }

    #[test]
    fn un_tampon_trop_petit_dit_ce_qu_il_aurait_fallu() {
        let mut tampon = [0_u8; 5];
        assert_eq!(
            encoder(&mut tampon, Code::OK, &[b"OK"]),
            Err(Error::BufferTooSmall { needed: 8 })
        );
        // Huit octets exactement suffisent : `250 OK\r\n`.
        let mut juste = [0_u8; 8];
        assert!(encoder(&mut juste, Code::OK, &[b"OK"]).is_ok());
    }

    #[test]
    fn la_taille_annoncee_est_celle_qui_est_ecrite() {
        // `encoded_len` n'est pas une estimation : c'est le contrat sur lequel
        // l'écriture se dispense ensuite de toute vérification.
        let lignes: &[&[u8]] = &[b"example.com", b"SIZE 100", b"STARTTLS"];
        let annonce = encoded_len(lignes, &Limits::DEFAULT).expect("mesurable");
        let mut tampon = [0_u8; 256];
        let ecrit = encoder(&mut tampon, Code::OK, lignes).expect("encodable");
        assert_eq!(ecrit.len(), annonce);
    }
}
