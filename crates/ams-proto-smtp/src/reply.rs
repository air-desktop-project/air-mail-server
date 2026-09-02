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

/// Le code d'état étendu d'une réponse (RFC 3463), tel que RFC 2034 le préfixe.
///
/// # POURQUOI IL NE SE DÉDUIT PAS DU CODE À TROIS CHIFFRES
///
/// Un `550` peut être une boîte inconnue (`5.1.1`) ou un refus de politique
/// (`5.7.1`) : ce sont deux choses différentes, et c'est précisément pour les
/// distinguer que RFC 3463 existe. Le déduire reviendrait à inventer une des
/// deux réponses.
///
/// # CE QUE LA CLASSE DOIT AU CODE
///
/// §3.2 de RFC 3463 : la classe — le premier chiffre — dit la même chose que le
/// premier chiffre du code à trois chiffres. Un `550 4.x.x` ferait réessayer un
/// pair qu'on refuse définitivement, et un `250 5.x.x` n'a aucun sens. C'est une
/// propriété qu'on peut vérifier, et [`Status::agrees_with`] la vérifie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    class: u8,
    subject: u16,
    detail: u16,
}

impl Status {
    /// Construit un état.
    ///
    /// Rend `None` si la classe n'est pas `2`, `4` ou `5`, ou si le sujet ou le
    /// détail dépasse trois chiffres (§3 de RFC 3463).
    #[must_use]
    pub const fn new(class: u8, subject: u16, detail: u16) -> Option<Self> {
        if (class == 2 || class == 4 || class == 5) && subject <= 999 && detail <= 999 {
            Some(Self {
                class,
                subject,
                detail,
            })
        } else {
            None
        }
    }

    /// La classe : `2`, `4` ou `5`.
    #[must_use]
    pub const fn class(self) -> u8 {
        self.class
    }

    /// **Cet état dit-il la même chose que ce code ?** (§3.2)
    ///
    /// Un `550 4.x.x` ferait réessayer un pair qu'on refuse définitivement.
    #[must_use]
    pub const fn agrees_with(self, code: Code) -> bool {
        // Le premier chiffre d'un code de trois : `550 / 100 == 5`.
        self.class as u16 == code.value() / 100
    }

    /// Écrit `class.subject.detail`, sans espace ni fin de ligne.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si `out` ne suffit pas.
    pub fn write(self, out: &mut [u8]) -> Result<&[u8], Error> {
        let mut ecrits = pousser_chiffres(out, 0, u16::from(self.class))?;
        ecrits = pousser_octet(out, ecrits, b'.')?;
        ecrits = pousser_chiffres(out, ecrits, self.subject)?;
        ecrits = pousser_octet(out, ecrits, b'.')?;
        ecrits = pousser_chiffres(out, ecrits, self.detail)?;
        out.get(..ecrits)
            .ok_or(Error::BufferTooSmall { needed: ecrits })
    }

    // ── Les états que ce serveur emploie ────────────────────────────────────
    //
    // Ils sont NOMMÉS plutôt qu'écrits sur place : un même refus doit rendre le
    // même état partout, et deux écritures d'un même sens finiraient par ne plus
    // dire la même chose.

    /// `2.0.0` — succès sans précision.
    pub const OK: Self = Self {
        class: 2,
        subject: 0,
        detail: 0,
    };
    /// `2.1.0` — l'adresse de l'expéditeur est valable.
    pub const SENDER_OK: Self = Self {
        class: 2,
        subject: 1,
        detail: 0,
    };
    /// `2.1.5` — l'adresse du destinataire est valable.
    pub const RECIPIENT_OK: Self = Self {
        class: 2,
        subject: 1,
        detail: 5,
    };
    /// `2.7.0` — succès lié à la sécurité (authentification, chiffrement).
    pub const SECURITY_OK: Self = Self {
        class: 2,
        subject: 7,
        detail: 0,
    };
    /// `4.3.0` — panne du serveur, sans précision.
    pub const LOCAL_ERROR: Self = Self {
        class: 4,
        subject: 3,
        detail: 0,
    };
    /// `4.3.2` — le service n'accepte pas de message pour l'instant.
    pub const NOT_ACCEPTING: Self = Self {
        class: 4,
        subject: 3,
        detail: 2,
    };
    /// `4.2.1` — la boîte est momentanément indisponible.
    pub const MAILBOX_BUSY: Self = Self {
        class: 4,
        subject: 2,
        detail: 1,
    };
    /// `4.5.3` — trop de destinataires pour cette transaction.
    pub const TOO_MANY_RECIPIENTS: Self = Self {
        class: 4,
        subject: 5,
        detail: 3,
    };
    /// `4.7.0` — refus temporaire lié à la sécurité.
    pub const SECURITY_TEMP: Self = Self {
        class: 4,
        subject: 7,
        detail: 0,
    };
    /// `5.5.1` — commande inconnue.
    pub const UNKNOWN_COMMAND: Self = Self {
        class: 5,
        subject: 5,
        detail: 1,
    };
    /// `5.5.2` — erreur de syntaxe.
    pub const SYNTAX_ERROR: Self = Self {
        class: 5,
        subject: 5,
        detail: 2,
    };
    /// `5.5.4` — paramètre invalide.
    pub const BAD_PARAMETER: Self = Self {
        class: 5,
        subject: 5,
        detail: 4,
    };
    /// `5.5.0` — commande mal placée dans la séquence.
    pub const BAD_SEQUENCE: Self = Self {
        class: 5,
        subject: 5,
        detail: 0,
    };
    /// `5.1.1` — la boîte n'existe pas.
    pub const MAILBOX_UNAVAILABLE: Self = Self {
        class: 5,
        subject: 1,
        detail: 1,
    };
    /// `5.7.1` — refusé par la politique.
    pub const POLICY: Self = Self {
        class: 5,
        subject: 7,
        detail: 1,
    };
    /// `5.7.0` — refus permanent lié à la sécurité.
    pub const SECURITY: Self = Self {
        class: 5,
        subject: 7,
        detail: 0,
    };
    /// `5.3.4` — le message est plus grand que ce qu'on accepte.
    pub const MESSAGE_TOO_LARGE: Self = Self {
        class: 5,
        subject: 3,
        detail: 4,
    };
    /// `5.6.0` — le contenu du message est irrecevable.
    pub const BAD_CONTENT: Self = Self {
        class: 5,
        subject: 6,
        detail: 0,
    };
    /// `5.4.6` — trop de sauts : le message tourne en boucle.
    pub const TOO_MANY_HOPS: Self = Self {
        class: 5,
        subject: 4,
        detail: 6,
    };
    /// `5.0.0` — refus permanent, sujet indéfini (§3.3).
    pub const POLICY_OTHER: Self = Self {
        class: 5,
        subject: 0,
        detail: 0,
    };
    /// `5.7.23` — l'expéditeur n'est pas autorisé par SPF (RFC 7372 §3.2).
    pub const SPF_REFUSED: Self = Self {
        class: 5,
        subject: 7,
        detail: 23,
    };
    /// `4.4.3` — la résolution DNS n'a pas abouti.
    pub const DNS_TEMP: Self = Self {
        class: 4,
        subject: 4,
        detail: 3,
    };
}

/// Écrit un nombre décimal, sans zéro de tête.
fn pousser_chiffres(out: &mut [u8], depuis: usize, valeur: u16) -> Result<usize, Error> {
    // Trois chiffres au plus : `Status::new` l'a vérifié.
    let mut chiffres = [0_u8; 3];
    let mut combien = 0_usize;
    let mut reste = valeur;
    loop {
        chiffres[combien] = b'0'.saturating_add((reste % 10) as u8);
        combien = combien.saturating_add(1);
        reste /= 10;
        if reste == 0 {
            break;
        }
    }
    let mut ecrits = depuis;
    while combien > 0 {
        combien = combien.saturating_sub(1);
        ecrits = pousser_octet(out, ecrits, chiffres[combien])?;
    }
    Ok(ecrits)
}

/// Écrit un octet, ou dit que la place manque.
fn pousser_octet(out: &mut [u8], depuis: usize, octet: u8) -> Result<usize, Error> {
    let place = out.get_mut(depuis).ok_or(Error::BufferTooSmall {
        needed: depuis.saturating_add(1),
    })?;
    *place = octet;
    Ok(depuis.saturating_add(1))
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

    /// `214` — message d'aide.
    pub const HELP_MESSAGE: Self = Self(214);
    /// `220` — le service est prêt.
    pub const SERVICE_READY: Self = Self(220);
    /// `221` — le service ferme le canal de transmission.
    pub const CLOSING: Self = Self(221);
    /// `235` — authentification réussie (RFC 4954 §6).
    pub const AUTH_SUCCEEDED: Self = Self(235);
    /// `250` — la commande a abouti.
    pub const OK: Self = Self(250);
    /// `252` — impossible de vérifier la boîte, mais le message sera tenté.
    ///
    /// La réponse que la RFC 5321 §3.5.3 prévoit pour `VRFY` quand on refuse de
    /// dire si une boîte existe : elle ne révèle rien, et reste conforme.
    pub const CANNOT_VRFY: Self = Self(252);
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
    /// `452` — trop de destinataires (RFC 5321 §4.5.3.1.10).
    ///
    /// Même valeur qu'[`Code::INSUFFICIENT_STORAGE`], et c'est la RFC qui le veut
    /// ainsi. Deux noms parce que ce sont deux situations, et qu'un appelant qui
    /// lit `INSUFFICIENT_STORAGE` là où il refuse un centième destinataire se
    /// demanderait où est le disque plein.
    pub const TOO_MANY_RECIPIENTS: Self = Self(452);
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
    /// `504` — paramètre de commande non servi (RFC 4954 §4).
    ///
    /// Distinct d'[`Code::NOT_IMPLEMENTED`] : la commande est servie, c'est
    /// l'argument qui ne l'est pas. `AUTH CRAM-MD5` obtient celui-ci, et non un
    /// `502` qui laisserait croire qu'`AUTH` n'existe pas ici.
    pub const PARAMETER_NOT_IMPLEMENTED: Self = Self(504);
    /// `530` — authentification requise (RFC 4954 §6).
    pub const AUTH_REQUIRED: Self = Self(530);
    /// `535` — authentification refusée (RFC 4954 §6).
    pub const AUTH_FAILED: Self = Self(535);
    /// `538` — chiffrement requis pour ce mécanisme (RFC 4954 §6).
    pub const ENCRYPTION_REQUIRED: Self = Self(538);
    /// `550` — boîte indisponible : action non effectuée.
    pub const MAILBOX_UNAVAILABLE: Self = Self(550);
    /// `552` — le message dépasse la taille maximale (RFC 1870 §6).
    pub const MESSAGE_TOO_LARGE: Self = Self(552);
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
    use super::Status;

    /// **UN ÉTAT SE VALIDE À LA CONSTRUCTION**, comme un code : `Status::write`
    /// n'a alors rien à vérifier.
    #[test]
    fn un_etat_se_valide_a_la_construction() {
        let etat = Status::new(5, 7, 23).expect("valide");
        assert_eq!(etat.class(), 5);
        assert!(etat.agrees_with(Code::MAILBOX_UNAVAILABLE));
        assert!(!etat.agrees_with(Code::OK));
        assert_eq!(etat, Status::SPF_REFUSED);

        // RFC 3463 §3 : la classe vaut 2, 4 ou 5, et rien d'autre. Une classe
        // `3` n'existe pas — c'est ce qui rend impossible d'en écrire une sur
        // une réponse `3xx`.
        for classe in [0_u8, 1, 3, 6, 9] {
            assert_eq!(Status::new(classe, 0, 0), None, "classe {classe}");
        }
        // Trois chiffres au plus, de chaque côté.
        assert!(Status::new(5, 999, 999).is_some());
        assert_eq!(Status::new(5, 1000, 0), None);
        assert_eq!(Status::new(5, 0, 1000), None);
        assert!(!std::format!("{:?}", Status::OK).is_empty());
    }

    /// **CE QUI EST ÉCRIT SE RELIT**, et un tampon trop court le dit.
    #[test]
    fn un_etat_s_ecrit_en_chiffres_et_en_points() {
        let mut sortie = [0_u8; 16];
        assert_eq!(
            Status::SPF_REFUSED.write(&mut sortie).expect("écrit"),
            b"5.7.23"
        );
        assert_eq!(Status::OK.write(&mut sortie).expect("écrit"), b"2.0.0");
        assert_eq!(
            Status::new(4, 999, 999)
                .expect("valide")
                .write(&mut sortie)
                .expect("écrit"),
            b"4.999.999"
        );
        // Toutes les tailles trop courtes, une par une. `2.0.0` en fait cinq.
        for taille in 0..5 {
            let mut court = std::vec![0_u8; taille];
            assert!(
                Status::OK.write(&mut court).is_err(),
                "une taille de {taille} a suffi"
            );
        }
    }

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
