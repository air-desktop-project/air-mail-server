//! Ce qu'un découpage de commande doit tenir.

use super::{CommandReader, Need};
use crate::{Error, Limits};

const BORNES: Limits = Limits::DEFAULT;

/// Examine un tampon d'un seul tenant.
fn examiner(buffer: &[u8]) -> Result<Need, Error> {
    CommandReader::new().poll(buffer, &BORNES)
}

#[test]
fn une_commande_sans_litteral_se_decoupe_au_crlf() {
    let entree = b"a001 CAPABILITY\r\n";
    assert_eq!(examiner(entree), Ok(Need::Complete(entree.len())));
}

/// La longueur rendue est celle de LA commande, pas celle du tampon : ce qui
/// suit appartient à la commande d'après. IMAP les entrelace, et un client peut
/// parfaitement en envoyer trois d'affilée.
#[test]
fn ce_qui_suit_la_commande_n_en_fait_pas_partie() {
    let entree = b"a001 NOOP\r\na002 NOOP\r\n";
    assert_eq!(examiner(entree), Ok(Need::Complete(11)));
}

#[test]
fn tant_qu_il_en_manque_on_le_dit() {
    for partiel in [&b""[..], b"a", b"a001 NOOP", b"a001 NOOP\r"] {
        assert_eq!(examiner(partiel), Ok(Need::More), "{partiel:?}");
    }
}

// ── LES LITTÉRAUX ───────────────────────────────────────────────────────────

/// **Chercher le premier `CRLF` pour découper une commande IMAP, c'est offrir à
/// un client de faire lire n'importe quoi comme une commande.**
#[test]
fn c_est_ici_que_la_commande_ne_se_coupe_pas_au_milieu_d_un_litteral() {
    // Le littéral porte lui-même un `CRLF` : une lecture naïve s'arrêterait
    // dedans, et lirait « MOT DE PASSE » comme une commande.
    let entree = b"a001 LOGIN {6+}\r\nto\r\nto MOTDEPASSE\r\n";
    assert_eq!(examiner(entree), Ok(Need::Complete(entree.len())));
}

/// Un littéral synchronisant se signale AVANT que le client n'envoie rien.
#[test]
fn un_litteral_synchronisant_demande_une_continuation() {
    let mut lecteur = CommandReader::new();
    let debut = b"a001 LOGIN {4}\r\n";
    assert_eq!(lecteur.poll(debut, &BORNES), Ok(Need::Continuation));
    // On ne le demande qu'une fois : le suivant compte les octets.
    assert_eq!(lecteur.poll(debut, &BORNES), Ok(Need::More));
    let mut entier = std::vec::Vec::from(&debut[..]);
    entier.extend_from_slice(b"toto MOTDEPASSE\r\n");
    assert_eq!(
        lecteur.poll(&entier, &BORNES),
        Ok(Need::Complete(entier.len()))
    );
}

/// Un littéral non synchronisant n'attend rien : les octets suivent.
#[test]
fn un_litteral_non_synchronisant_n_attend_pas() {
    let entree = b"a001 LOGIN {4+}\r\ntoto MOTDEPASSE\r\n";
    assert_eq!(examiner(entree), Ok(Need::Complete(entree.len())));
}

#[test]
fn plusieurs_litteraux_se_suivent() {
    let entree = b"a001 LOGIN {4+}\r\ntoto {6+}\r\nsecret\r\n";
    assert_eq!(examiner(entree), Ok(Need::Complete(entree.len())));
}

/// **Le découpage ne dépend pas de la façon dont les octets arrivent.**
#[test]
fn le_decoupage_ne_change_rien() {
    let entree = b"a001 LOGIN {6+}\r\nto\r\nto MOTDEPASSE\r\n";
    for coupure in 0..=entree.len() {
        let mut lecteur = CommandReader::new();
        let (avant, _) = entree.split_at(coupure);
        // Ce qui manque se dit, et rien d'autre.
        let premier = lecteur.poll(avant, &BORNES).expect("lisible");
        if coupure == entree.len() {
            assert_eq!(premier, Need::Complete(entree.len()));
            continue;
        }
        assert!(
            matches!(premier, Need::More | Need::Continuation),
            "coupure {coupure} : {premier:?}"
        );
        assert_eq!(
            lecteur.poll(entree, &BORNES),
            Ok(Need::Complete(entree.len())),
            "coupure {coupure}"
        );
    }
}

/// **`a001 LOGIN "toto{5}" x` ne porte aucun littéral** : l'accolade y est dans
/// une chaîne. La chercher sans suivre les guillemets laisserait le client
/// choisir où l'on découpe.
#[test]
fn une_accolade_entre_guillemets_n_annonce_rien() {
    let entree = b"a001 LOGIN \"toto{5}\"\r\n";
    assert_eq!(examiner(entree), Ok(Need::Complete(entree.len())));
    // Et un guillemet échappé ne referme pas la chaîne.
    let entree = b"a001 LOGIN \"to\\\"to{5}\"\r\n";
    assert_eq!(examiner(entree), Ok(Need::Complete(entree.len())));
    // Hors guillemets, en revanche, c'est bien un littéral.
    let entree = b"a001 LOGIN \"toto\" {5+}\r\nabcde\r\n";
    assert_eq!(examiner(entree), Ok(Need::Complete(entree.len())));
}

/// **Un guillemet échappé ne referme pas la chaîne**, et la ligne se termine
/// pourtant par une accolade : c'est le cas où une lecture naïve de la dernière
/// accolade se tromperait sans qu'aucun test simple ne le voie.
#[test]
fn un_guillemet_echappe_ne_referme_pas_la_chaine() {
    // `"x\"y{3}"` est une chaîne qui contient `{3}` ; le `}` final est du
    // texte, et il n'y a aucun littéral.
    let entree = b"a001 SEARCH \"x\\\"y{3}\"}\r\n";
    assert_eq!(examiner(entree), Ok(Need::Complete(entree.len())));

    // Le même échappement, suivi cette fois d'un vrai littéral.
    let entree = b"a001 LOGIN \"a\\\"b\" {3+}\r\nxyz\r\n";
    assert_eq!(examiner(entree), Ok(Need::Complete(entree.len())));
}

// ── LES BORNES ──────────────────────────────────────────────────────────────

/// **`{4294967295}` est une ligne de treize octets qui demande quatre
/// gibioctets.** On la refuse avant de lire quoi que ce soit.
#[test]
fn c_est_ici_qu_un_litteral_demesure_est_refuse() {
    assert_eq!(
        examiner(b"a001 APPEND boite {4294967295}\r\n"),
        Err(Error::LiteralTooLong {
            limit: BORNES.max_literal_octets
        })
    );
    // Et une longueur qui déborde n'est pas une petite longueur.
    assert_eq!(
        examiner(b"a001 APPEND boite {99999999999999999999999}\r\n"),
        Err(Error::MalformedLiteral)
    );
}

/// **Celui-là part sans que le serveur ait rien dit** : la RFC 9051 §6.3.11 le
/// borne à quatre kibioctets, et cette borne n'est pas la nôtre à choisir.
#[test]
fn un_litteral_non_synchronisant_trop_gros_est_refuse() {
    assert_eq!(
        examiner(b"a001 LOGIN {4097+}\r\n"),
        Err(Error::NonSynchronizingTooLong { limit: 4096 })
    );
    // Le même, synchronisant, passe : le serveur pourra dire non.
    assert_eq!(examiner(b"a001 LOGIN {4097}\r\n"), Ok(Need::Continuation));
}

/// Mille littéraux d'un octet passeraient chacun sous la borne précédente, et
/// la commande n'aurait pas de fin.
#[test]
fn trop_de_litteraux_font_refuser_la_commande() {
    let mut entree = std::vec::Vec::from(&b"a001 LOGIN"[..]);
    for _ in 0..=BORNES.max_literals {
        entree.extend_from_slice(b" {1+}\r\nx");
    }
    entree.extend_from_slice(b"\r\n");
    assert_eq!(
        examiner(&entree),
        Err(Error::TooManyLiterals {
            limit: BORNES.max_literals
        })
    );
}

#[test]
fn une_ligne_qui_ne_finit_pas_est_bornee() {
    let mut trop = std::vec::Vec::from(&b"a001 "[..]);
    trop.resize(BORNES.max_line_octets + 2, b'x');
    assert_eq!(
        examiner(&trop),
        Err(Error::LineTooLong {
            limit: BORNES.max_line_octets
        })
    );
    trop.extend_from_slice(b"\r\n");
    assert_eq!(
        examiner(&trop),
        Err(Error::LineTooLong {
            limit: BORNES.max_line_octets
        })
    );
}

#[test]
fn un_cr_ou_un_lf_isole_fait_refuser_la_ligne() {
    for mechant in [&b"a001 NO\rOP\r\n"[..], b"a001 NO\nOP\r\n"] {
        assert_eq!(
            examiner(mechant),
            Err(Error::MalformedLineEnding),
            "{mechant:?}"
        );
    }
}

#[test]
fn une_accolade_qui_n_annonce_pas_un_nombre_est_une_faute() {
    for mechant in [
        &b"a001 LOGIN {abc}\r\n"[..],
        b"a001 LOGIN {}\r\n",
        b"a001 LOGIN {+}\r\n",
        b"a001 LOGIN {1x}\r\n",
    ] {
        assert_eq!(
            examiner(mechant),
            Err(Error::MalformedLiteral),
            "{mechant:?}"
        );
    }
    // Une accolade FERMANTE sans ouvrante n'annonce rien du tout.
    assert_eq!(examiner(b"a001 SEARCH x}\r\n"), Ok(Need::Complete(16)));
}

/// **Un lecteur neuf n'a rien examiné**, et c'est ce qui dit à l'appelant que le
/// tampon COMMENCE une commande — la seule situation où l'on peut en reconnaître
/// une avant de la découper.
#[test]
fn un_lecteur_dit_s_il_est_neuf() {
    let mut lecteur = CommandReader::new();
    assert!(lecteur.is_fresh());
    // Un littéral en cours : ce qui suit n'est plus le début d'une commande.
    assert_eq!(
        lecteur.poll(b"a001 LOGIN {4}\r\n", &BORNES),
        Ok(Need::Continuation)
    );
    assert!(!lecteur.is_fresh());
    lecteur.reset();
    assert!(lecteur.is_fresh());
    // Une ligne examinée sans conclure suffit aussi à ne plus être neuf.
    assert_eq!(
        lecteur.poll(b"a001 LOGIN {4+}\r\nto", &BORNES),
        Ok(Need::More)
    );
    assert!(!lecteur.is_fresh());
}

#[test]
fn un_lecteur_se_remet_a_zero() {
    let mut lecteur = CommandReader::new();
    let entree = b"a001 LOGIN {4+}\r\ntoto\r\na002 NOOP\r\n";
    assert_eq!(lecteur.poll(entree, &BORNES), Ok(Need::Complete(23)));
    lecteur.reset();
    assert_eq!(lecteur.poll(&entree[23..], &BORNES), Ok(Need::Complete(11)));
    assert!(!std::format!("{lecteur:?}").is_empty());
    assert_eq!(
        std::format!("{:?}", CommandReader::default()),
        std::format!("{:?}", CommandReader::new())
    );
    assert_ne!(Need::More, Need::Continuation);
}
