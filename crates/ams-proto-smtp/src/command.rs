//! Le verbe, ses arguments, et ce qu'on refuse de comprendre.

use crate::domain::{ClientId, parse_client_id, strip_prefix_ci};
use crate::path::{Path, PathKind, check_bare_domain, parse_path};
use crate::{Error, Limits, Parameters};

/// Une commande SMTP décodée.
///
/// # Ce que cette crate décide, et ce qu'elle laisse à la session
///
/// Le refus **grammatical** vit ici : un verbe retiré par la RFC 5321, une route
/// source, un chemin sans chevrons. Ce sont des propriétés du texte reçu.
///
/// Le refus de **politique** vit dans la session : exiger TLS avant `AUTH`,
/// refuser `HELO` pour n'offrir que l'ESMTP, limiter le nombre de destinataires.
/// Ce sont des propriétés de l'état de la connexion, que ce décodeur ne connaît
/// pas — et ne doit pas connaître, sous peine de ne plus être décodable seul.
///
/// C'est pourquoi `HELO` se décode ici alors que C6 le range parmi ce qu'on ne
/// sert pas : **on ne peut pas refuser proprement ce qu'on ne sait pas lire.**
///
/// # Pourquoi cette énumération n'est PAS `#[non_exhaustive]`
///
/// `#[non_exhaustive]` protège les consommateurs qui suivent une version
/// publiée : il les oblige à écrire un bras `_`, pour qu'une variante ajoutée en
/// amont ne casse pas leur compilation. Ici, les consommateurs sont dans le même
/// dépôt et partagent la même version (verrou de version du workspace).
///
/// Le marqueur y aurait donc l'effet exactement inverse de celui qu'on veut :
/// ajouter `BDAT` un jour DOIT casser la compilation d'`ams-session`, pour que
/// quelqu'un décide comment y répondre. Un bras `_` transformerait cette
/// question en réponse silencieuse — et, accessoirement, en branche que rien ne
/// pourrait exercer, donc en trou de couverture permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command<'a> {
    /// `EHLO domaine-ou-littéral`
    Ehlo(ClientId<'a>),

    /// `HELO domaine` — sans littéral d'adresse : l'ABNF de la RFC 5321
    /// §4.1.1.1 n'en prévoit que pour `EHLO`.
    Helo(&'a [u8]),

    /// `MAIL FROM:<chemin> [paramètres]`
    Mail {
        /// L'expéditeur de l'enveloppe. `<>` pour un avis de non-remise.
        reverse_path: Path<'a>,
        /// Les paramètres ESMTP.
        parameters: Parameters<'a>,
    },

    /// `RCPT TO:<chemin> [paramètres]`
    Rcpt {
        /// Le destinataire de l'enveloppe.
        forward_path: Path<'a>,
        /// Les paramètres ESMTP.
        parameters: Parameters<'a>,
    },

    /// `DATA`
    Data,

    /// `RSET`
    Rset,

    /// `NOOP [chaîne]` — l'argument facultatif est accepté et **ignoré**
    /// (RFC 5321 §4.1.1.9). Le décoder n'apprendrait rien à personne.
    Noop,

    /// `QUIT`
    Quit,

    /// `STARTTLS` (RFC 3207 §2) — sans argument.
    StartTls,

    /// `AUTH mécanisme [réponse-initiale]` (RFC 4954 §4).
    Auth {
        /// Le nom du mécanisme SASL.
        mechanism: &'a [u8],
        /// La réponse initiale, en base64. `=` désigne une réponse **vide**, et
        /// non l'absence de réponse : la distinction compte pour les mécanismes
        /// qui commencent par un message vide.
        initial_response: Option<&'a [u8]>,
    },

    /// `VRFY` — l'argument n'est **délibérément pas décodé**.
    ///
    /// La seule réponse acceptable ne révèle rien de l'existence d'une boîte
    /// (RFC 5321 §7.3 : `VRFY` est un instrument d'énumération d'utilisateurs).
    /// Décoder un argument dont on n'a rien à faire ne serait que de la surface
    /// d'attaque offerte.
    Vrfy,

    /// `EXPN` — même traitement que [`Command::Vrfy`], et pour la même raison :
    /// développer une liste, c'est en publier les membres.
    Expn,

    /// `HELP` — l'argument n'est pas décodé.
    Help,
}

impl<'a> Command<'a> {
    /// Décode une ligne de commande, **CRLF compris**.
    ///
    /// # Errors
    ///
    /// Les variantes d'[`Error`].
    pub fn parse(line: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        let contenu = strip_line_ending(line, limits)?;
        let (verbe, reste) = split_verb(contenu);
        dispatch(verbe, reste, limits)
    }
}

/// Retire le CRLF final, en refusant tout CR ou LF isolé.
fn strip_line_ending<'a>(line: &'a [u8], limits: &Limits) -> Result<&'a [u8], Error> {
    if line.len() > limits.max_command_octets {
        return Err(Error::LineTooLong {
            limit: limits.max_command_octets,
        });
    }
    let [contenu @ .., b'\r', b'\n'] = line else {
        return Err(Error::MalformedLineEnding);
    };
    // Un CR ou un LF au milieu, c'est deux commandes pour qui découpe autrement.
    // C'est la faille de la contrebande SMTP, et elle se ferme ici.
    if contenu.iter().any(|&b| b == b'\r' || b == b'\n') {
        return Err(Error::MalformedLineEnding);
    }
    Ok(contenu)
}

/// Sépare le verbe du reste. Le reste **conserve son espace de tête**, parce que
/// `MAIL FROM:` et `RCPT TO:` en font partie intégrante.
fn split_verb(contenu: &[u8]) -> (&[u8], &[u8]) {
    match contenu.iter().position(|&b| b == b' ') {
        Some(at) => contenu.split_at(at),
        None => (contenu, &contenu[..0]),
    }
}

/// Aiguille sur le verbe, sans tenir compte de la casse (RFC 5321 §2.4).
fn dispatch<'a>(verbe: &'a [u8], reste: &'a [u8], limits: &Limits) -> Result<Command<'a>, Error> {
    if verbe.eq_ignore_ascii_case(b"EHLO") {
        return Ok(Command::Ehlo(parse_client_id(argument(reste)?, limits)?));
    }
    if verbe.eq_ignore_ascii_case(b"HELO") {
        let domaine = argument(reste)?;
        check_bare_domain(domaine)?;
        if domaine.len() > limits.max_domain_octets {
            return Err(Error::DomainTooLong {
                limit: limits.max_domain_octets,
            });
        }
        return Ok(Command::Helo(domaine));
    }
    if verbe.eq_ignore_ascii_case(b"MAIL") {
        let (reverse_path, parameters) =
            parse_path_command(reste, b" FROM:", PathKind::Reverse, limits)?;
        return Ok(Command::Mail {
            reverse_path,
            parameters,
        });
    }
    if verbe.eq_ignore_ascii_case(b"RCPT") {
        let (forward_path, parameters) =
            parse_path_command(reste, b" TO:", PathKind::Forward, limits)?;
        return Ok(Command::Rcpt {
            forward_path,
            parameters,
        });
    }
    if verbe.eq_ignore_ascii_case(b"DATA") {
        no_argument(reste)?;
        return Ok(Command::Data);
    }
    if verbe.eq_ignore_ascii_case(b"RSET") {
        no_argument(reste)?;
        return Ok(Command::Rset);
    }
    if verbe.eq_ignore_ascii_case(b"QUIT") {
        no_argument(reste)?;
        return Ok(Command::Quit);
    }
    if verbe.eq_ignore_ascii_case(b"STARTTLS") {
        no_argument(reste)?;
        return Ok(Command::StartTls);
    }
    if verbe.eq_ignore_ascii_case(b"NOOP") {
        // L'argument est licite et ignoré ; on ne le regarde même pas.
        return Ok(Command::Noop);
    }
    if verbe.eq_ignore_ascii_case(b"VRFY") {
        return Ok(Command::Vrfy);
    }
    if verbe.eq_ignore_ascii_case(b"EXPN") {
        return Ok(Command::Expn);
    }
    if verbe.eq_ignore_ascii_case(b"HELP") {
        return Ok(Command::Help);
    }
    if verbe.eq_ignore_ascii_case(b"AUTH") {
        return parse_auth(reste);
    }
    // Retirés par la RFC 5321 (§7.3, appendice C). `TURN` inverse les rôles
    // client et serveur sur une connexion déjà ouverte : c'est un vol de
    // courrier documenté, et c'est pour cela qu'il a disparu.
    for obsolete in [b"SEND".as_slice(), b"SOML", b"SAML", b"TURN"] {
        if verbe.eq_ignore_ascii_case(obsolete) {
            return Err(Error::ObsoleteVerb);
        }
    }
    Err(Error::UnknownVerb)
}

/// `MAIL FROM:<…>` / `RCPT TO:<…>`, avec leurs paramètres facultatifs.
fn parse_path_command<'a>(
    reste: &'a [u8],
    mot_cle: &[u8],
    kind: PathKind,
    limits: &Limits,
) -> Result<(Path<'a>, Parameters<'a>), Error> {
    let apres = strip_prefix_ci(reste, mot_cle).ok_or(Error::MissingPathKeyword)?;
    // Le chemin s'arrête au premier espace : au-delà commencent les paramètres.
    // L'ABNF de la RFC 5321 §4.1.1.2 ne prévoit AUCUN espace entre `FROM:` et
    // `<`, et n'en tolérer aucun ferme une divergence d'interprétation de plus.
    let (chemin, parametres) = match apres.iter().position(|&b| b == b' ') {
        Some(at) => {
            let (chemin, suite) = apres.split_at(at);
            (chemin, suite.get(1..).unwrap_or(&[]))
        }
        None => (apres, &apres[..0]),
    };
    let path = parse_path(chemin, kind, limits)?;
    let parameters = if parametres.is_empty() {
        Parameters::empty()
    } else {
        Parameters::parse(parametres, limits)?
    };
    Ok((path, parameters))
}

/// `AUTH mécanisme [réponse-initiale]` (RFC 4954 §4).
fn parse_auth(reste: &[u8]) -> Result<Command<'_>, Error> {
    let argument = argument(reste)?;
    let (mechanism, initial_response) = match argument.iter().position(|&b| b == b' ') {
        Some(at) => {
            let (mechanism, suite) = argument.split_at(at);
            (mechanism, Some(suite.get(1..).unwrap_or(&[])))
        }
        None => (argument, None),
    };

    // RFC 4422 §3.1 : de 1 à 20 caractères, majuscules, chiffres, tiret,
    // souligné. Une casse minuscule est refusée — la norme ne l'admet pas, et un
    // mécanisme reconnu à la casse près serait un mécanisme de plus.
    if mechanism.is_empty()
        || mechanism.len() > 20
        || !mechanism
            .iter()
            .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(Error::MalformedMechanism);
    }

    if let Some(reponse) = initial_response {
        check_initial_response(reponse)?;
    }
    Ok(Command::Auth {
        mechanism,
        initial_response,
    })
}

/// La réponse initiale d'`AUTH` : du base64, ou `=` pour une réponse vide.
fn check_initial_response(reponse: &[u8]) -> Result<(), Error> {
    // RFC 4954 §4 : un `=` seul désigne une réponse initiale VIDE. Ce n'est pas
    // la même chose qu'une absence de réponse initiale, et le confondre ferait
    // dévier les mécanismes qui commencent par un message vide.
    if reponse == b"=" {
        return Ok(());
    }
    if reponse.is_empty()
        || !reponse
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return Err(Error::MalformedInitialResponse);
    }
    Ok(())
}

/// Un argument obligatoire, précédé d'exactement un espace.
fn argument(reste: &[u8]) -> Result<&[u8], Error> {
    let [b' ', argument @ ..] = reste else {
        return Err(Error::MissingArgument);
    };
    if argument.is_empty() {
        return Err(Error::MissingArgument);
    }
    Ok(argument)
}

/// Aucun argument attendu.
fn no_argument(reste: &[u8]) -> Result<(), Error> {
    if reste.is_empty() {
        Ok(())
    } else {
        Err(Error::UnexpectedArgument)
    }
}

#[cfg(test)]
mod tests {
    use super::Command;
    use crate::{ClientId, Error, Limits, Mailbox, Parameters, Path};

    /// Extrait l'enveloppe d'un `MAIL`. TOTAL — cf. `path::tests::boite`.
    fn mail<'a>(commande: Command<'a>) -> Option<(Path<'a>, Parameters<'a>)> {
        match commande {
            Command::Mail {
                reverse_path,
                parameters,
            } => Some((reverse_path, parameters)),
            _ => None,
        }
    }

    /// Extrait la boîte d'un chemin. TOTAL.
    fn boite<'a>(chemin: Path<'a>) -> Option<Mailbox<'a>> {
        match chemin {
            Path::Mailbox(boite) => Some(boite),
            Path::Null | Path::Postmaster => None,
        }
    }

    fn analyser(ligne: &[u8]) -> Result<Command<'_>, Error> {
        Command::parse(ligne, &Limits::DEFAULT)
    }

    // ── La ligne ────────────────────────────────────────────────────────────

    #[test]
    fn une_ligne_sans_crlf_est_refusee() {
        for mauvais in [b"QUIT".as_slice(), b"QUIT\n", b"QUIT\r", b"", b"\n"] {
            assert_eq!(
                analyser(mauvais),
                Err(Error::MalformedLineEnding),
                "{mauvais:?} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn un_cr_ou_un_lf_isole_dans_la_ligne_est_refuse() {
        // C'est la faille de la contrebande SMTP : deux serveurs qui découpent
        // différemment voient deux commandes différentes.
        assert_eq!(
            analyser(b"NOOP\nRCPT TO:<x@y.z>\r\n"),
            Err(Error::MalformedLineEnding)
        );
        assert_eq!(
            analyser(b"NOOP\rRCPT TO:<x@y.z>\r\n"),
            Err(Error::MalformedLineEnding)
        );
    }

    #[test]
    fn une_ligne_trop_longue_est_refusee() {
        // RFC 5321 §4.5.3.1.4 : 512 octets, CRLF compris.
        let bornes = Limits {
            max_command_octets: 6,
            ..Limits::DEFAULT
        };
        assert_eq!(
            Command::parse(b"QUIT\r\n", &bornes),
            Ok(Command::Quit),
            "six octets exactement doivent passer"
        );
        assert_eq!(
            Command::parse(b"NOOP \r\n", &bornes),
            Err(Error::LineTooLong { limit: 6 })
        );
    }

    // ── Les verbes sans argument ────────────────────────────────────────────

    #[test]
    fn les_verbes_sans_argument_se_decodent_a_la_casse_pres() {
        assert_eq!(analyser(b"DATA\r\n"), Ok(Command::Data));
        assert_eq!(analyser(b"RSET\r\n"), Ok(Command::Rset));
        assert_eq!(analyser(b"quit\r\n"), Ok(Command::Quit));
        assert_eq!(analyser(b"StArTtLs\r\n"), Ok(Command::StartTls));
    }

    #[test]
    fn un_argument_inattendu_est_refuse() {
        for mauvais in [
            b"DATA maintenant\r\n".as_slice(),
            b"RSET x\r\n",
            b"QUIT x\r\n",
            b"STARTTLS x\r\n",
        ] {
            assert_eq!(
                analyser(mauvais),
                Err(Error::UnexpectedArgument),
                "{mauvais:?} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn noop_accepte_un_argument_et_ne_le_decode_pas() {
        // RFC 5321 §4.1.1.9. Le décoder n'apprendrait rien à personne.
        assert_eq!(analyser(b"NOOP\r\n"), Ok(Command::Noop));
        assert_eq!(analyser(b"NOOP garde-moi eveille\r\n"), Ok(Command::Noop));
    }

    #[test]
    fn vrfy_expn_et_help_se_reconnaissent_sans_decoder_leur_argument() {
        // Décoder un argument dont la seule réponse acceptable ne révèle rien ne
        // serait que de la surface d'attaque offerte (RFC 5321 §7.3).
        assert_eq!(analyser(b"VRFY jean\r\n"), Ok(Command::Vrfy));
        assert_eq!(analyser(b"EXPN liste\r\n"), Ok(Command::Expn));
        assert_eq!(analyser(b"HELP MAIL\r\n"), Ok(Command::Help));
        assert_eq!(analyser(b"VRFY\r\n"), Ok(Command::Vrfy));
    }

    // ── Les verbes refusés ──────────────────────────────────────────────────

    #[test]
    fn les_verbes_retires_par_la_rfc_5321_sont_distingues_des_inconnus() {
        // La session leur doit 502, pas 500 : ils sont compris, pas servis.
        for obsolete in [
            b"SEND FROM:<x@y.z>\r\n".as_slice(),
            b"SOML FROM:<x@y.z>\r\n",
            b"SAML FROM:<x@y.z>\r\n",
            b"TURN\r\n",
        ] {
            assert_eq!(
                analyser(obsolete),
                Err(Error::ObsoleteVerb),
                "{obsolete:?} aurait dû être reconnu comme obsolète"
            );
        }
        assert_eq!(analyser(b"XYZZY\r\n"), Err(Error::UnknownVerb));
        assert_eq!(analyser(b"\r\n"), Err(Error::UnknownVerb));
    }

    // ── EHLO et HELO ────────────────────────────────────────────────────────

    #[test]
    fn ehlo_accepte_un_domaine_ou_un_litteral() {
        assert_eq!(
            analyser(b"EHLO mail.example.com\r\n"),
            Ok(Command::Ehlo(ClientId::Domain(b"mail.example.com")))
        );
        assert_eq!(
            analyser(b"EHLO [192.0.2.1]\r\n"),
            Ok(Command::Ehlo(ClientId::AddressLiteral(b"[192.0.2.1]")))
        );
    }

    #[test]
    fn helo_n_accepte_qu_un_domaine() {
        // L'ABNF de la RFC 5321 §4.1.1.1 ne prévoit de littéral que pour `EHLO`.
        assert_eq!(
            analyser(b"HELO mail.example.com\r\n"),
            Ok(Command::Helo(b"mail.example.com"))
        );
        assert_eq!(
            analyser(b"HELO [192.0.2.1]\r\n"),
            Err(Error::MalformedDomain)
        );
    }

    #[test]
    fn helo_borne_aussi_son_domaine() {
        let bornes = Limits {
            max_domain_octets: 4,
            ..Limits::DEFAULT
        };
        assert_eq!(
            Command::parse(b"HELO example.com\r\n", &bornes),
            Err(Error::DomainTooLong { limit: 4 })
        );
    }

    #[test]
    fn un_argument_obligatoire_manquant_est_refuse() {
        assert_eq!(analyser(b"EHLO\r\n"), Err(Error::MissingArgument));
        // Un espace suivi de rien n'est pas un argument.
        assert_eq!(analyser(b"EHLO \r\n"), Err(Error::MissingArgument));
        assert_eq!(analyser(b"HELO\r\n"), Err(Error::MissingArgument));
    }

    // ── MAIL et RCPT ────────────────────────────────────────────────────────

    #[test]
    fn mail_from_se_decode_avec_ses_parametres() {
        let commande = analyser(b"MAIL FROM:<moi@example.com> SIZE=1000 BODY=8BITMIME\r\n")
            .expect("recevable");
        let (reverse_path, parameters) = mail(commande).expect("attendu MAIL");
        let boite = boite(reverse_path).expect("attendu une boîte");
        assert_eq!(boite.local_part().as_bytes(), b"moi");
        assert_eq!(
            parameters.find(b"BODY").expect("BODY").value(),
            Some(b"8BITMIME".as_slice())
        );
    }

    #[test]
    fn mail_from_sans_parametre() {
        assert_eq!(
            analyser(b"MAIL FROM:<>\r\n"),
            Ok(Command::Mail {
                reverse_path: Path::Null,
                parameters: crate::Parameters::empty(),
            })
        );
    }

    #[test]
    fn rcpt_to_se_decode_et_refuse_le_chemin_nul() {
        assert_eq!(
            analyser(b"RCPT TO:<Postmaster>\r\n"),
            Ok(Command::Rcpt {
                forward_path: Path::Postmaster,
                parameters: crate::Parameters::empty(),
            })
        );
        assert_eq!(analyser(b"RCPT TO:<>\r\n"), Err(Error::NullPathRefused));
    }

    #[test]
    fn le_mot_cle_du_chemin_est_obligatoire_et_insensible_a_la_casse() {
        assert!(analyser(b"MAIL from:<moi@example.com>\r\n").is_ok());
        assert!(analyser(b"RCPT To:<moi@example.com>\r\n").is_ok());
        assert_eq!(
            analyser(b"MAIL TO:<moi@example.com>\r\n"),
            Err(Error::MissingPathKeyword)
        );
        assert_eq!(analyser(b"MAIL\r\n"), Err(Error::MissingPathKeyword));
    }

    #[test]
    fn l_espace_entre_from_et_le_chevron_est_refuse() {
        // CHOIX STRICT ASSUMÉ. L'ABNF de la RFC 5321 §4.1.1.2 n'en prévoit pas ;
        // beaucoup de clients en envoient un. Le tolérer serait une divergence
        // d'interprétation de plus entre implémentations.
        assert_eq!(
            analyser(b"MAIL FROM: <moi@example.com>\r\n"),
            Err(Error::MalformedPath)
        );
    }

    #[test]
    fn un_parametre_mal_forme_fait_echouer_la_commande() {
        assert_eq!(
            analyser(b"MAIL FROM:<moi@example.com> SIZE=\r\n"),
            Err(Error::MalformedParameter)
        );
    }

    // ── AUTH ────────────────────────────────────────────────────────────────

    #[test]
    fn auth_se_decode_avec_ou_sans_reponse_initiale() {
        assert_eq!(
            analyser(b"AUTH PLAIN\r\n"),
            Ok(Command::Auth {
                mechanism: b"PLAIN",
                initial_response: None,
            })
        );
        assert_eq!(
            analyser(b"AUTH PLAIN AGplaWpvdQBtb3RkZXBhc3Nl\r\n"),
            Ok(Command::Auth {
                mechanism: b"PLAIN",
                initial_response: Some(b"AGplaWpvdQBtb3RkZXBhc3Nl"),
            })
        );
    }

    #[test]
    fn une_reponse_initiale_vide_n_est_pas_une_absence_de_reponse() {
        // RFC 4954 §4 : `=` désigne une réponse initiale VIDE. La distinction
        // compte pour les mécanismes qui commencent par un message vide.
        assert_eq!(
            analyser(b"AUTH EXTERNAL =\r\n"),
            Ok(Command::Auth {
                mechanism: b"EXTERNAL",
                initial_response: Some(b"="),
            })
        );
    }

    #[test]
    fn les_mecanismes_mal_formes_sont_refuses() {
        for mauvais in [
            b"AUTH  PLAIN\r\n".as_slice(),                // mécanisme vide
            b"AUTH plain\r\n",                            // minuscules
            b"AUTH MECANISME-BEAUCOUP-TROP-LONG-ICI\r\n", // plus de 20
            b"AUTH PL.AIN\r\n",                           // point hors alphabet
        ] {
            assert_eq!(
                analyser(mauvais),
                Err(Error::MalformedMechanism),
                "{mauvais:?} aurait dû être refusé"
            );
        }
        assert_eq!(analyser(b"AUTH\r\n"), Err(Error::MissingArgument));
    }

    #[test]
    fn une_reponse_initiale_hors_base64_est_refusee() {
        for mauvais in [
            b"AUTH PLAIN \r\n".as_slice(), // vide, et ce n'est pas `=`
            b"AUTH PLAIN a b\r\n",         // l'espace n'est pas du base64
            b"AUTH PLAIN a!b\r\n",
        ] {
            assert_eq!(
                analyser(mauvais),
                Err(Error::MalformedInitialResponse),
                "{mauvais:?} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn les_extracteurs_ne_rendent_rien_hors_de_leur_forme() {
        assert_eq!(mail(Command::Data), None);
        assert_eq!(boite(Path::Null), None);
        assert_eq!(boite(Path::Postmaster), None);
    }

    // ── Les erreurs qui remontent des sous-analyseurs ────────────────────────

    #[test]
    fn une_erreur_de_domaine_remonte_jusqu_a_la_commande() {
        // Chaque `?` de l'aiguillage est un chemin à part : il ne suffit pas que
        // le sous-analyseur soit testé, il faut que sa remontée le soit aussi.
        assert_eq!(analyser(b"EHLO -mauvais-\r\n"), Err(Error::MalformedDomain));
        assert_eq!(
            analyser(b"EHLO [192.0.2.999]\r\n"),
            Err(Error::MalformedAddressLiteral)
        );
        assert_eq!(
            analyser(b"MAIL FROM:<moi@-mauvais->\r\n"),
            Err(Error::MalformedDomain)
        );
    }

    #[test]
    fn une_commande_se_copie_et_se_debogue() {
        let commande = analyser(b"DATA\r\n").expect("recevable");
        let copie = commande;
        assert_eq!(copie, commande);
        assert!(!std::format!("{commande:?}").is_empty());
    }
}
