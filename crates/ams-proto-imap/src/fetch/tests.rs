//! Ce qu'un `FETCH` demande, et ce qu'on refuse de lui donner.

use super::{Fetch, FetchItem, Partial, Section};
use crate::{Error, Limits};

const BORNES: Limits = Limits::DEFAULT;

/// Lit un `FETCH` et rend ses éléments.
fn elements(arguments: &[u8]) -> std::vec::Vec<FetchItem> {
    Fetch::parse(arguments, &BORNES)
        .expect("lisible")
        .items()
        .to_vec()
}

#[test]
fn les_elements_ordinaires_se_lisent() {
    assert_eq!(
        elements(b"1:5 (UID FLAGS)"),
        std::vec![FetchItem::Uid, FetchItem::Flags]
    );
    assert_eq!(
        elements(b"1 (INTERNALDATE RFC822.SIZE)"),
        std::vec![FetchItem::InternalDate, FetchItem::Rfc822Size]
    );
    // Un élément seul se passe de parenthèses.
    assert_eq!(elements(b"1 UID"), std::vec![FetchItem::Uid]);
    // Et la casse ne compte pas.
    assert_eq!(
        elements(b"1 (uid flags)"),
        std::vec![FetchItem::Uid, FetchItem::Flags]
    );
}

#[test]
fn l_ensemble_de_numeros_est_celui_qu_on_a_ecrit() {
    let lu = Fetch::parse(b"2:4 UID", &BORNES).expect("lisible");
    assert_eq!(
        lu.set().ranges(10).collect::<std::vec::Vec<_>>(),
        std::vec![(2, 4)]
    );
}

/// **`PEEK` n'est pas une variante cosmétique** : `BODY[]` marque le message
/// comme lu, `BODY.PEEK[]` ne le marque pas (§6.4.5). Confondre les deux fait
/// qu'un client qui prévisualise marque tout comme lu.
#[test]
fn peek_se_distingue_de_ce_qui_marque_comme_lu() {
    assert_eq!(
        elements(b"1 BODY[]"),
        std::vec![FetchItem::Body {
            section: Section::Full,
            peek: false,
            partial: None
        }]
    );
    assert_eq!(
        elements(b"1 BODY.PEEK[]"),
        std::vec![FetchItem::Body {
            section: Section::Full,
            peek: true,
            partial: None
        }]
    );
}

#[test]
fn les_trois_sections_servies_se_lisent() {
    for (texte, attendue) in [
        (&b"1 BODY[]"[..], Section::Full),
        (b"1 BODY[HEADER]", Section::Header),
        (b"1 BODY[TEXT]", Section::Text),
        (b"1 BODY[header]", Section::Header),
    ] {
        assert_eq!(
            elements(texte),
            std::vec![FetchItem::Body {
                section: attendue,
                peek: false,
                partial: None
            }],
            "{texte:?}"
        );
    }
}

/// **La demande partielle est une surface** : un décalage et une longueur venus
/// du réseau, appliqués à un message dont on ne connaît la taille qu'après.
#[test]
fn une_demande_partielle_se_lit_sans_deborder() {
    assert_eq!(
        elements(b"1 BODY[]<1000.500>"),
        std::vec![FetchItem::Body {
            section: Section::Full,
            peek: false,
            partial: Some(Partial {
                offset: 1000,
                length: 500
            })
        }]
    );
    // Le décalage a le droit d'être nul ; la longueur, non.
    assert_eq!(
        elements(b"1 BODY.PEEK[TEXT]<0.1>"),
        std::vec![FetchItem::Body {
            section: Section::Text,
            peek: true,
            partial: Some(Partial {
                offset: 0,
                length: 1
            })
        }]
    );
    // Les bornes d'un `u32` passent ; un de plus, non.
    assert!(Fetch::parse(b"1 BODY[]<4294967295.4294967295>", &BORNES).is_ok());
    for mechant in [
        &b"1 BODY[]<4294967296.1>"[..],
        b"1 BODY[]<0.4294967296>",
        // Zéro octet n'est pas une demande.
        b"1 BODY[]<0.0>",
        b"1 BODY[]<1000>",
        b"1 BODY[]<.5>",
        b"1 BODY[]<1.>",
        b"1 BODY[]<1.5",
        b"1 BODY[]1.5>",
        b"1 BODY[]<a.b>",
    ] {
        assert_eq!(
            Fetch::parse(mechant, &BORNES),
            Err(Error::MalformedFetch),
            "{mechant:?}"
        );
    }
}

/// `FAST` est le seul raccourci servi : les deux autres demandent une enveloppe
/// analysée qu'on ne compose pas encore.
#[test]
fn le_seul_raccourci_servi_est_fast() {
    assert_eq!(
        elements(b"1 FAST"),
        std::vec![
            FetchItem::Flags,
            FetchItem::InternalDate,
            FetchItem::Rfc822Size
        ]
    );
    for autre in [&b"1 ALL"[..], b"1 FULL", b"1 all"] {
        assert_eq!(
            Fetch::parse(autre, &BORNES),
            Err(Error::UnsupportedFetchItem),
            "{autre:?}"
        );
    }
}

/// **Reconnus, et refusés.** Ce n'est pas une erreur de syntaxe : le client sait
/// alors qu'il doit demander autrement, au lieu de chercher la faute dans ce
/// qu'il a écrit.
/// `BODYSTRUCTURE` se lit désormais comme les autres.
#[test]
fn la_structure_se_lit() {
    assert_eq!(
        elements(b"1 BODYSTRUCTURE"),
        std::vec![FetchItem::BodyStructure]
    );
    assert_eq!(
        elements(b"1 (UID BODYSTRUCTURE ENVELOPE)"),
        std::vec![
            FetchItem::Uid,
            FetchItem::BodyStructure,
            FetchItem::Envelope
        ]
    );
}

/// `ENVELOPE` se lit désormais comme les autres.
#[test]
fn l_enveloppe_se_lit() {
    assert_eq!(elements(b"1 ENVELOPE"), std::vec![FetchItem::Envelope]);
    assert_eq!(
        elements(b"1 (UID ENVELOPE)"),
        std::vec![FetchItem::Uid, FetchItem::Envelope]
    );
}

#[test]
fn ce_qui_est_reconnu_sans_etre_servi_se_dit_comme_tel() {
    for mot in [
        &b"1 BODY"[..],
        b"1 RFC822",
        b"1 RFC822.HEADER",
        b"1 RFC822.TEXT",
        b"1 BINARY",
        // Des sections qu'on ne découpe pas.
        b"1 BODY[1]",
        b"1 BODY[1.MIME]",
        b"1 BODY[HEADER.FIELDS",
    ] {
        assert_eq!(
            Fetch::parse(mot, &BORNES),
            Err(Error::UnsupportedFetchItem),
            "{mot:?}"
        );
    }
}

#[test]
fn ce_qui_n_a_pas_la_forme_est_une_faute() {
    for mechant in [
        // Pas d'ensemble, ou pas de demande.
        &b"1"[..],
        b"",
        b"1 ",
        b"1 ()",
        // Une parenthèse d'un seul côté n'est pas une liste.
        b"1 (UID",
        b"1 UID)",
        // Un mot qui n'est pas un élément.
        b"1 XYZZY",
        b"1 BODYX[]",
        b"1 BODY.PEEK",
        b"1 BODYHEADER]",
        // Un ensemble de numéros fautif.
        b"0 UID",
    ] {
        assert!(
            matches!(
                Fetch::parse(mechant, &BORNES),
                Err(Error::MalformedFetch | Error::MalformedSequence)
            ),
            "{mechant:?} : {:?}",
            Fetch::parse(mechant, &BORNES)
        );
    }
}

/// Chaque élément demande un travail par message : mille de plus par commande
/// est déjà bien au-delà de ce qu'un client écrit.
#[test]
fn une_liste_demesuree_est_refusee() {
    let mut trop = std::vec::Vec::from(&b"1 (UID"[..]);
    for _ in 0..BORNES.max_fetch_items {
        trop.extend_from_slice(b" UID");
    }
    trop.extend_from_slice(b")");
    assert_eq!(
        Fetch::parse(&trop, &BORNES),
        Err(Error::TooManyFetchItems {
            limit: BORNES.max_fetch_items
        })
    );

    // La borne elle-même passe.
    let mut juste = std::vec::Vec::from(&b"1 (UID"[..]);
    for _ in 1..BORNES.max_fetch_items {
        juste.extend_from_slice(b" UID");
    }
    juste.extend_from_slice(b")");
    assert_eq!(
        Fetch::parse(&juste, &BORNES)
            .expect("lisible")
            .items()
            .len(),
        BORNES.max_fetch_items
    );
}

/// Les espaces en trop ne font pas d'éléments vides.
#[test]
fn les_espaces_en_trop_ne_comptent_pas() {
    assert_eq!(
        elements(b"1 (UID   FLAGS)"),
        std::vec![FetchItem::Uid, FetchItem::Flags]
    );
}

#[test]
fn ce_qui_se_lit_se_montre_et_se_compare() {
    let lu = Fetch::parse(b"1 UID", &BORNES).expect("lisible");
    let copie = lu;
    assert_eq!(copie.items(), lu.items());
    assert!(!std::format!("{lu:?}").is_empty());
    assert!(!std::format!("{:?}", Section::Full).is_empty());
    assert_eq!(Section::Full, Section::Full);
    assert_ne!(Section::Full, Section::Text);
    assert!(
        !std::format!(
            "{:?}",
            Partial {
                offset: 0,
                length: 1
            }
        )
        .is_empty()
    );
    assert_ne!(FetchItem::Uid, FetchItem::Flags);
}
