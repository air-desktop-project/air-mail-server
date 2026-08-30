//! Ce qu'un `FETCH` demande, et ce qu'on refuse de lui donner.

use super::{Fetch, FetchItem, PartPath, PartWhat, Partial, SECTION_DEPTH_MAX, Section};
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
/// Une partie désignée se lit : son chemin, et ce qu'on veut d'elle.
#[test]
fn une_partie_designee_se_lit() {
    let chemin = |texte: &[u8]| match elements(texte).first().copied() {
        Some(FetchItem::Body {
            section: Section::Part { path, what },
            ..
        }) => (std::vec::Vec::from(path.numbers()), what),
        autre => panic!("{autre:?}"),
    };
    assert_eq!(chemin(b"1 BODY[1]"), (std::vec![1], PartWhat::Content));
    assert_eq!(chemin(b"1 BODY[2.1]"), (std::vec![2, 1], PartWhat::Content));
    assert_eq!(chemin(b"1 BODY[1.MIME]"), (std::vec![1], PartWhat::Mime));
    assert_eq!(
        chemin(b"1 BODY[3.header]"),
        (std::vec![3], PartWhat::Header)
    );
    assert_eq!(
        chemin(b"1 BODY.PEEK[3.2.TEXT]"),
        (std::vec![3, 2], PartWhat::Text)
    );
    // Huit niveaux tiennent ; le neuvième, non.
    assert_eq!(
        chemin(b"1 BODY[1.1.1.1.1.1.1.1]").0,
        std::vec![1_u32; SECTION_DEPTH_MAX]
    );
    // Et la demande partielle s'applique aussi à une partie.
    assert_eq!(
        elements(b"1 BODY[1]<10.5>"),
        std::vec![FetchItem::Body {
            section: Section::Part {
                path: chemin_de(&[1]),
                what: PartWhat::Content,
            },
            peek: false,
            partial: Some(Partial {
                offset: 10,
                length: 5
            }),
        }]
    );
}

/// Fabrique un chemin, pour comparer.
fn chemin_de(numeros: &[u32]) -> PartPath {
    let texte = numeros
        .iter()
        .map(|numero| std::format!("{numero}"))
        .collect::<std::vec::Vec<_>>()
        .join(".");
    match elements(std::format!("1 BODY[{texte}]").as_bytes())
        .first()
        .copied()
    {
        Some(FetchItem::Body {
            section: Section::Part { path, .. },
            ..
        }) => path,
        autre => panic!("{autre:?}"),
    }
}

/// **UN CHOIX DE CHAMPS SE LIT, LISTE COMPRISE.** C'est le seul endroit d'un
/// élément où un blanc figure, et couper dessus rendait deux morceaux dont aucun
/// n'était lisible.
#[test]
fn un_choix_de_champs_se_lit() {
    let lu = Fetch::parse(b"1 BODY.PEEK[HEADER.FIELDS (From Subject)]", &BORNES).expect("lisible");
    assert_eq!(
        lu.items(),
        [FetchItem::Body {
            section: Section::HeaderFields { except: false },
            peek: true,
            partial: None,
        }]
    );
    assert_eq!(lu.header_names(0), b"From Subject");

    // `.NOT` renverse le choix.
    let sauf = Fetch::parse(b"1 BODY[HEADER.FIELDS.NOT (received)]", &BORNES).expect("lisible");
    assert_eq!(
        sauf.items(),
        [FetchItem::Body {
            section: Section::HeaderFields { except: true },
            peek: false,
            partial: None,
        }]
    );
    assert_eq!(sauf.header_names(0), b"received");
}

/// Un choix sur une PARTIE se lit aussi, chemin compris.
#[test]
fn un_choix_sur_une_partie_se_lit() {
    let lu = Fetch::parse(b"1 BODY.PEEK[2.1.HEADER.FIELDS (To)]", &BORNES).expect("lisible");
    match lu.items().first().copied() {
        Some(FetchItem::Body {
            section: Section::Part { path, what },
            ..
        }) => {
            assert_eq!(path.numbers(), [2, 1]);
            assert_eq!(what, PartWhat::HeaderFields { except: false });
        }
        autre => panic!("{autre:?}"),
    }
    assert_eq!(lu.header_names(0), b"To");
}

/// **UN ÉLÉMENT QUI PORTE UNE LISTE N'EMPÊCHE PAS DE LIRE LES SUIVANTS.** C'est
/// ce que le découpage respectueux des crochets rend possible.
#[test]
fn un_choix_n_empeche_pas_de_lire_la_suite() {
    let lu =
        Fetch::parse(b"1 (UID BODY.PEEK[HEADER.FIELDS (From)] FLAGS)", &BORNES).expect("lisible");
    assert_eq!(lu.items().len(), 3);
    assert_eq!(lu.items().first().copied(), Some(FetchItem::Uid));
    assert_eq!(lu.items().get(2).copied(), Some(FetchItem::Flags));
    // Les noms suivent l'élément qui les porte, et lui seul.
    assert_eq!(lu.header_names(0), b"");
    assert_eq!(lu.header_names(1), b"From");
    assert_eq!(lu.header_names(2), b"");
    // Et au-delà des éléments lus, il n'y a rien.
    assert_eq!(lu.header_names(60), b"");
}

/// Un choix mal formé est une faute, et non un refus de service.
#[test]
fn un_choix_mal_forme_est_une_faute() {
    for mechant in [
        // Une liste vide ne désigne rien.
        &b"1 BODY[HEADER.FIELDS ()]"[..],
        b"1 BODY[HEADER.FIELDS (  )]",
        // Un choix sans liste n'en est pas un.
        b"1 BODY[HEADER.FIELDS]",
        b"1 BODY[HEADER.FIELDS.NOT]",
        // Une liste sans parenthèses.
        b"1 BODY[HEADER.FIELDS From]",
        // Un nom qui n'est pas un atome : le deux-points sépare, il ne nomme pas.
        b"1 BODY[HEADER.FIELDS (From:)]",
        // Un chemin qui n'a pas la forme, devant un choix qui l'a.
        b"1 BODY[0.HEADER.FIELDS (From)]",
        b"1 BODY[1..2.HEADER.FIELDS (From)]",
        // Une liste derrière autre chose qu'un choix.
        b"1 BODY[TEXT (From)]",
        b"1 BODY[1.MIME (From)]",
        b"1 BODY[1 (From)]",
    ] {
        assert_eq!(
            Fetch::parse(mechant, &BORNES),
            Err(Error::MalformedFetch),
            "{mechant:?}"
        );
    }
}

/// **UN NOM CITÉ EST RECEVABLE, ET ON NE LE SERT PAS.** `header-fld-name` est un
/// `astring` : le refuser comme une FAUTE ferait chercher au client une erreur
/// là où il n'y en a pas.
#[test]
fn un_nom_cite_se_refuse_sans_accuser_le_client() {
    for cite in [
        &b"1 BODY[HEADER.FIELDS (\"From\")]"[..],
        b"1 BODY[HEADER.FIELDS (From {4})]",
        b"1 BODY[HEADER.FIELDS (Fro\\m)]",
    ] {
        assert_eq!(
            Fetch::parse(cite, &BORNES),
            Err(Error::UnsupportedFetchItem),
            "{cite:?}"
        );
    }
}

/// UN CHEMIN QUI N'A PAS LA FORME EST UNE FAUTE, et non un refus de service :
/// les confondre ferait chercher au client une erreur là où il n'y en a pas.
#[test]
fn un_chemin_mal_forme_est_une_faute() {
    for mechant in [
        &b"1 BODY[0]"[..],
        b"1 BODY[1.0]",
        b"1 BODY[1..2]",
        b"1 BODY[.1]",
        b"1 BODY[1.]",
        b"1 BODY[MIME]",
        b"1 BODY[1.MIME.2]",
        b"1 BODY[1.x]",
        b"1 BODY[-1]",
    ] {
        assert_eq!(
            Fetch::parse(mechant, &BORNES),
            Err(Error::MalformedFetch),
            "{mechant:?}"
        );
    }
}

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
        // Une section dont la forme est correcte mais qu'on ne sait pas
        // découper.
        b"1 BODY[HEADER.FIELDS",
        // Un chemin plus profond que ce qu'on retient.
        b"1 BODY[1.1.1.1.1.1.1.1.1]",
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

/// Deux lectures d'une même commande se comparent et s'affichent.
///
/// Ce n'est pas une coquetterie : les dérivés de `Fetch` portent la comparaison
/// de ses noms, et un dérivé qu'aucune épreuve n'exerce est du code livré que
/// rien ne regarde.
#[test]
fn deux_lectures_d_une_meme_commande_se_comparent() {
    let commande = &b"1 (UID BODY.PEEK[HEADER.FIELDS (From To)])"[..];
    let une = Fetch::parse(commande, &BORNES).expect("lisible");
    let autre = Fetch::parse(commande, &BORNES).expect("lisible");
    assert_eq!(une, autre);
    let differente =
        Fetch::parse(b"1 (UID BODY.PEEK[HEADER.FIELDS (From)])", &BORNES).expect("lisible");
    assert_ne!(une, differente);
    // Les noms sont des octets : le rendu les montre en nombres.
    assert!(std::format!("{une:?}").contains("70, 114, 111, 109"));
}
