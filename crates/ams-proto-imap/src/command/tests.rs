//! Ce qu'une commande dit d'elle-même.

use super::{Command, Line};
use crate::{Error, Limits};

const BORNES: Limits = Limits::DEFAULT;

#[test]
fn une_commande_ordinaire_se_decoupe() {
    let lue = Line::parse(b"a001 SELECT INBOX\r\n", &BORNES).expect("lisible");
    assert_eq!(lue.tag.as_bytes(), b"a001");
    assert_eq!(lue.command, Command::Select);
    assert_eq!(lue.arguments, b"INBOX");
}

#[test]
fn une_commande_sans_argument_en_a_zero() {
    let lue = Line::parse(b"a001 NOOP\r\n", &BORNES).expect("lisible");
    assert_eq!(lue.command, Command::Noop);
    assert_eq!(lue.arguments, b"");
}

/// Les verbes sont insensibles à la casse (RFC 9051 §9).
#[test]
fn la_casse_du_verbe_ne_compte_pas() {
    for texte in [
        &b"a001 select INBOX\r\n"[..],
        b"a001 SeLeCt INBOX\r\n",
        b"a001 SELECT INBOX\r\n",
    ] {
        assert_eq!(
            Line::parse(texte, &BORNES).expect("lisible").command,
            Command::Select,
            "{texte:?}"
        );
    }
}

#[test]
fn tout_le_vocabulaire_se_lit() {
    for (mot, attendu) in [
        ("CAPABILITY", Command::Capability),
        ("NOOP", Command::Noop),
        ("LOGOUT", Command::Logout),
        ("STARTTLS", Command::StartTls),
        ("AUTHENTICATE", Command::Authenticate),
        ("LOGIN", Command::Login),
        ("ENABLE", Command::Enable),
        ("SELECT", Command::Select),
        ("EXAMINE", Command::Examine),
        ("CREATE", Command::Create),
        ("DELETE", Command::Delete),
        ("RENAME", Command::Rename),
        ("SUBSCRIBE", Command::Subscribe),
        ("UNSUBSCRIBE", Command::Unsubscribe),
        ("LIST", Command::List),
        ("NAMESPACE", Command::Namespace),
        ("STATUS", Command::Status),
        ("APPEND", Command::Append),
        ("IDLE", Command::Idle),
        ("CLOSE", Command::Close),
        ("UNSELECT", Command::Unselect),
        ("EXPUNGE", Command::Expunge),
        ("SEARCH", Command::Search),
        ("FETCH", Command::Fetch),
        ("STORE", Command::Store),
        ("COPY", Command::Copy),
        ("MOVE", Command::Move),
        ("UID", Command::Uid),
        ("LSUB", Command::Lsub),
        ("CHECK", Command::Check),
    ] {
        assert_eq!(Command::parse(mot.as_bytes()), Ok(attendu), "{mot}");
        assert!(!std::format!("{attendu:?}").is_empty());
    }
}

/// **La différence entre un client qui se rabat et un client qui abandonne** :
/// « je sais ce que c'est, et je ne le fais pas » n'est pas « je ne comprends
/// pas ».
#[test]
fn les_verbes_retires_par_rev2_sont_reconnus_sans_etre_servis() {
    for mot in [&b"LSUB"[..], b"CHECK"] {
        let verbe = Command::parse(mot).expect("reconnu");
        assert!(verbe.is_obsolete(), "{mot:?}");
    }
    assert!(!Command::Select.is_obsolete());
}

#[test]
fn ce_qui_n_est_pas_du_vocabulaire_est_ecarte() {
    for mot in [&b"XYZZY"[..], b"", b"SELEC", b"SELECTX"] {
        assert_eq!(Command::parse(mot), Err(Error::UnknownCommand), "{mot:?}");
    }
    assert_eq!(
        Line::parse(b"a001 XYZZY\r\n", &BORNES),
        Err(Error::UnknownCommand)
    );
}

#[test]
fn une_commande_sans_verbe_est_ecartee() {
    assert_eq!(
        Line::parse(b"a001\r\n", &BORNES),
        Err(Error::MissingCommand)
    );
    assert_eq!(
        Line::parse(b"a001 \r\n", &BORNES),
        Err(Error::MissingCommand)
    );
}

#[test]
fn un_tag_irrecevable_ecarte_la_commande() {
    assert_eq!(Line::parse(b" NOOP\r\n", &BORNES), Err(Error::MissingTag));
    assert_eq!(Line::parse(b"+ NOOP\r\n", &BORNES), Err(Error::ReservedTag));
    assert_eq!(
        Line::parse(b"a*1 NOOP\r\n", &BORNES),
        Err(Error::MalformedTag)
    );
}

/// Les littéraux font partie des arguments : le découpage les a déjà comptés,
/// et ce module les rend tels quels.
#[test]
fn les_litteraux_restent_dans_les_arguments() {
    let lue = Line::parse(b"a001 LOGIN {4+}\r\ntoto secret\r\n", &BORNES).expect("lisible");
    assert_eq!(lue.command, Command::Login);
    assert_eq!(lue.arguments, b"{4+}\r\ntoto secret");
}

#[test]
fn ce_qui_se_lit_se_montre_et_se_compare() {
    let lue = Line::parse(b"a001 NOOP\r\n", &BORNES).expect("lisible");
    let copie = lue;
    assert_eq!(lue, copie);
    assert!(!std::format!("{lue:?}").is_empty());
    assert_ne!(Command::Noop, Command::Capability);
}
