use super::{
    Missing, SUBMISSION_FIELDS_MAX, UNIQUE_MAX, missing_submission_fields, write_submission_fields,
};
use crate::limits::Limits;
use crate::message::Message;

/// Ce qui manque à ce message.
fn manque(brut: &[u8]) -> Missing {
    let message = Message::parse(brut, &Limits::DEFAULT).expect("lisible");
    missing_submission_fields(&message)
}

/// Compose les champs manquants, et les rend en texte.
fn champs(manquants: Missing) -> std::string::String {
    let mut place = [0_u8; SUBMISSION_FIELDS_MAX];
    let ecrit = write_submission_fields(
        &mut place,
        manquants,
        1_788_000_000,
        b"a1b2c3-d4e5f6",
        b"example.com",
    )
    .expect("composable");
    std::string::String::from_utf8_lossy(ecrit).into_owned()
}

/// **ON NE REGARDE QUE LA PRÉSENCE, JAMAIS LA VALEUR.**
///
/// Une date que le déposant a écrite de travers reste la sienne : §8.1 de
/// RFC 6409 ne demande que de combler une absence, et la corriger serait décider
/// à sa place.
#[test]
fn ce_qui_est_present_ne_manque_pas() {
    let complet = manque(b"From: marie@example.com\r\nDate: hier\r\nMessage-ID: <x@y>\r\n\r\n");
    assert!(complet.rien(), "{complet:?}");

    // La casse ne change rien (§1.2.2 de RFC 5322).
    let complet = manque(b"DATE: hier\r\nmessage-id: <x@y>\r\n\r\n");
    assert!(complet.rien(), "{complet:?}");
}

/// **`Date:` EST L'UN DES DEUX SEULS CHAMPS OBLIGATOIRES** (§3.6 de RFC 5322).
///
/// Un message qui sort sans est malformé, et les filtres en aval le pénalisent
/// lourdement — certains le refusent d'emblée.
#[test]
fn ce_qui_manque_est_nomme() {
    let vide = manque(b"From: marie@example.com\r\n\r\n");
    assert_eq!(
        vide,
        Missing {
            date: true,
            message_id: true
        }
    );
    assert!(!vide.rien());

    let sans_date = manque(b"Message-ID: <x@y>\r\n\r\n");
    assert_eq!(
        sans_date,
        Missing {
            date: true,
            message_id: false
        }
    );
    let sans_id = manque(b"Date: hier\r\n\r\n");
    assert_eq!(
        sans_id,
        Missing {
            date: false,
            message_id: true
        }
    );
}

/// **CE QU'ON ÉCRIT EST EXACTEMENT CE QUI MANQUAIT**, et rien d'autre.
#[test]
fn seuls_les_champs_manquants_s_ecrivent() {
    assert_eq!(
        champs(Missing {
            date: true,
            message_id: true
        }),
        "Date: Sat, 29 Aug 2026 10:40:00 +0000\r\n\
         Message-ID: <a1b2c3-d4e5f6@example.com>\r\n"
    );
    assert_eq!(
        champs(Missing {
            date: true,
            message_id: false
        }),
        "Date: Sat, 29 Aug 2026 10:40:00 +0000\r\n"
    );
    assert_eq!(
        champs(Missing {
            date: false,
            message_id: true
        }),
        "Message-ID: <a1b2c3-d4e5f6@example.com>\r\n"
    );
    // Rien à ajouter : rien n'est écrit, et ce n'est pas une erreur.
    assert_eq!(champs(Missing::default()), "");
}

/// **CETTE CAISSE NE CROIT PAS SON APPELANT.**
///
/// Ces valeurs ressortent dans un en-tête que NOUS composons. Un `@` de trop
/// ferait deux identifiants d'un seul champ, et un chevron le fermerait avant la
/// fin — un lecteur n'aurait aucun moyen de savoir lequel désigne le message.
#[test]
fn une_valeur_qui_couperait_le_champ_est_refusee() {
    let mut place = [0_u8; SUBMISSION_FIELDS_MAX];
    let manquants = Missing {
        date: false,
        message_id: true,
    };
    for (unique, domaine) in [
        (&b"a@b"[..], &b"example.com"[..]),
        (b"a", b"exa@mple.com"),
        (b"a>x", b"example.com"),
        (b"a", b"exa<mple.com"),
        (b"a b", b"example.com"),
        (b"a\r\nX-Forge: oui", b"example.com"),
        (b"", b"example.com"),
        (b"a", b""),
        (b"a", b"exempl\xc3\xa9.com"),
    ] {
        assert!(
            write_submission_fields(&mut place, manquants, 0, unique, domaine).is_err(),
            "{unique:?}@{domaine:?} est passé"
        );
    }
    // Et une valeur plus longue que sa borne ne passe pas non plus.
    let long = std::vec![b'x'; UNIQUE_MAX + 1];
    assert!(write_submission_fields(&mut place, manquants, 0, &long, b"example.com").is_err());
    let large = std::vec![b'x'; 256];
    assert!(write_submission_fields(&mut place, manquants, 0, b"a", &large).is_err());
}

/// **CE QUI NE TIENT PAS LE DIT**, et la borne annoncée suffit exactement.
#[test]
fn un_tampon_trop_court_le_dit() {
    let manquants = Missing {
        date: true,
        message_id: true,
    };
    let complet = champs(manquants).len();
    for taille in 0..complet {
        let mut court = std::vec![0_u8; taille];
        assert!(
            write_submission_fields(
                &mut court,
                manquants,
                1_788_000_000,
                b"a1b2c3-d4e5f6",
                b"example.com"
            )
            .is_err(),
            "une taille de {taille} a suffi"
        );
    }
    // La borne couvre le pire cas : les deux champs, avec les plus longues
    // valeurs qu'on accepte.
    let unique = std::vec![b'x'; UNIQUE_MAX];
    let domaine = std::vec![b'y'; 255];
    let mut place = [0_u8; SUBMISSION_FIELDS_MAX];
    assert!(
        write_submission_fields(&mut place, manquants, u64::MAX, &unique, &domaine).is_ok(),
        "la borne annoncée ne couvre pas le pire cas"
    );
}
