//! Ce qu'une recherche désigne, et ce qu'elle refuse de prétendre.

use super::{Candidate, Search, SearchReturn, SearchScope};
use crate::{Error, Flags, Limits};

const BORNES: Limits = Limits::DEFAULT;

/// Une source d'épreuve : une fermeture pour le texte, un jour pour la date.
///
/// La grammaire pose deux questions ; les tests répondent aux deux du même
/// geste, sans que chacun ait à écrire une structure.
struct Source<F: FnMut(SearchScope, &[u8], &[u8]) -> bool> {
    /// Ce qu'on répond aux critères de contenu.
    texte: F,
    /// Ce qu'on répond aux critères `SENT…`.
    jour: Option<u64>,
}

impl<F: FnMut(SearchScope, &[u8], &[u8]) -> bool> super::SearchSource for Source<F> {
    fn contains(&mut self, portee: SearchScope, champ: &[u8], texte: &[u8]) -> bool {
        (self.texte)(portee, champ, texte)
    }

    fn sent_day(&mut self) -> Option<u64> {
        self.jour
    }
}

/// Une source qui ne sait rien : ni texte, ni date.
fn muette() -> Source<impl FnMut(SearchScope, &[u8], &[u8]) -> bool> {
    Source {
        texte: |_, _, _| false,
        jour: None,
    }
}

/// Un message d'épreuve.
fn message(sequence: u32, uid: u32, size: u64, flags: Flags, date: u64) -> Candidate {
    Candidate {
        sequence,
        uid,
        size,
        flags,
        internal_date: date,
    }
}

/// Le 29 août 2026, à midi UTC.
const AOUT: u64 = 1_788_004_800;
/// Le 1er janvier 2020, à midi UTC.
const JANVIER: u64 = 1_577_880_000;

/// Les rangs qui correspondent, parmi trois messages d'épreuve.
fn trouves(critere: &[u8]) -> std::vec::Vec<u32> {
    let recherche = Search::parse(critere, &BORNES).expect("lisible");
    let messages = [
        message(1, 10, 100, Flags::NONE, JANVIER),
        message(2, 20, 5000, Flags::SEEN, AOUT),
        message(3, 30, 300, Flags::SEEN.with(Flags::DELETED), AOUT),
    ];
    messages
        .iter()
        .filter(|message| {
            // Cette liste-ci ne cherche rien DANS les messages : les critères
            // de contenu ont leurs propres épreuves, où la source dit ce
            // qu'elle voit.
            recherche.matches(message, 3, 30, &mut muette())
        })
        .map(|message| message.sequence)
        .collect()
}

#[test]
fn all_prend_tout() {
    assert_eq!(trouves(b"ALL"), std::vec![1, 2, 3]);
    assert_eq!(trouves(b"all"), std::vec![1, 2, 3]);
}

#[test]
fn les_drapeaux_se_cherchent_dans_les_deux_sens() {
    assert_eq!(trouves(b"SEEN"), std::vec![2, 3]);
    assert_eq!(trouves(b"UNSEEN"), std::vec![1]);
    assert_eq!(trouves(b"DELETED"), std::vec![3]);
    assert_eq!(trouves(b"UNDELETED"), std::vec![1, 2]);
    assert_eq!(trouves(b"UNFLAGGED"), std::vec![1, 2, 3]);
    assert_eq!(trouves(b"ANSWERED"), std::vec::Vec::<u32>::new());
    assert_eq!(trouves(b"UNDRAFT"), std::vec![1, 2, 3]);
}

#[test]
fn les_tailles_se_comparent_strictement() {
    assert_eq!(trouves(b"LARGER 300"), std::vec![2]);
    assert_eq!(trouves(b"SMALLER 300"), std::vec![1]);
    // Strictement : la taille exacte n'est ni plus grande ni plus petite.
    assert_eq!(trouves(b"LARGER 100 SMALLER 5000"), std::vec![3]);
}

#[test]
fn les_dates_se_comparent_par_jour() {
    assert_eq!(trouves(b"SINCE 29-Aug-2026"), std::vec![2, 3]);
    assert_eq!(trouves(b"BEFORE 29-Aug-2026"), std::vec![1]);
    assert_eq!(trouves(b"ON 29-Aug-2026"), std::vec![2, 3]);
    assert_eq!(trouves(b"ON 1-Jan-2020"), std::vec![1]);
    // Les guillemets sont admis, et la casse du mois ne compte pas.
    assert_eq!(trouves(b"ON \"29-aug-2026\""), std::vec![2, 3]);
}

#[test]
fn les_ensembles_se_cherchent_par_rang_et_par_uid() {
    assert_eq!(trouves(b"1:2"), std::vec![1, 2]);
    assert_eq!(trouves(b"UID 20:*"), std::vec![2, 3]);
    assert_eq!(trouves(b"2,3"), std::vec![2, 3]);
}

/// **Juxtaposer, c'est conjoindre** (§6.4.4).
#[test]
fn deux_criteres_se_conjoignent() {
    assert_eq!(trouves(b"SEEN UNDELETED"), std::vec![2]);
    assert_eq!(trouves(b"SEEN LARGER 1000"), std::vec![2]);
}

#[test]
fn not_et_or_disent_ce_qu_ils_disent() {
    assert_eq!(trouves(b"NOT SEEN"), std::vec![1]);
    assert_eq!(trouves(b"OR SEEN DELETED"), std::vec![2, 3]);
    assert_eq!(trouves(b"OR UNSEEN DELETED"), std::vec![1, 3]);
    // `NOT` porte sur la clef qui suit, et une seule.
    assert_eq!(trouves(b"NOT SEEN UNDELETED"), std::vec![1]);
    // Doublement nié vaut affirmé.
    assert_eq!(trouves(b"NOT NOT SEEN"), std::vec![2, 3]);
}

#[test]
fn les_parentheses_groupent() {
    assert_eq!(trouves(b"OR (SEEN DELETED) UNSEEN"), std::vec![1, 3]);
    assert_eq!(trouves(b"(SEEN)"), std::vec![2, 3]);
    assert_eq!(trouves(b"NOT (SEEN UNDELETED)"), std::vec![1, 3]);
    // Collées, elles se lisent pareil.
    assert_eq!(trouves(b"(SEEN UNDELETED)"), std::vec![2]);
}

/// **Un critère qu'on ne sert pas est refusé, pas rendu faux.** Un
/// `SEARCH SUBJECT "facture"` répondant « aucun résultat » serait un mensonge
/// exact.
#[test]
fn un_critere_non_servi_est_refuse() {
    for critere in [
        &b"KEYWORD $Important"[..],
        b"UNKEYWORD $Important",
        b"OLDER 3600",
        // Le refus traverse les parenthèses et les opérateurs.
        b"(SEEN KEYWORD $x)",
        b"OR KEYWORD $x SEEN",
        b"OR SEEN KEYWORD $x",
        b"NOT KEYWORD $x",
        // Une chaîne à échappement est licite, et on ne sait pas la déciter.
        b"SUBJECT \"la \\\"facture\\\"\"",
    ] {
        assert_eq!(
            Search::parse(critere, &BORNES).err(),
            Some(Error::UnsupportedSearchKey),
            "{:?}",
            core::str::from_utf8(critere)
        );
    }
}

#[test]
fn les_formes_fautives_sont_des_fautes() {
    for critere in [
        &b""[..],
        b"   ",
        b"NOT",
        b"OR SEEN",
        b"(",
        b"(SEEN",
        b")",
        b"SEEN )",
        b"LARGER",
        b"LARGER x",
        b"SINCE",
        b"SINCE 32-Aug-2026",
        b"SINCE 1-Zzz-2026",
        b"SINCE 1-Jan-1969",
        b"SINCE 1-Jan",
        b"SINCE 1",
        b"SINCE 1-Jan-2026-3",
        // Un nombre qui déborde n'est pas un petit nombre.
        b"LARGER 99999999999999999999999",
        b"SMALLER 18446744073709551616",
        b"UID",
        b"UID x",
        b"1:x",
    ] {
        assert!(
            Search::parse(critere, &BORNES).is_err(),
            "{:?} aurait dû être refusé",
            core::str::from_utf8(critere)
        );
    }
}

/// **La pile n'est pas extensible**, et le client choisit la profondeur.
#[test]
fn une_imbrication_demesuree_est_refusee() {
    let mut profond = std::vec::Vec::new();
    for _ in 0..64 {
        profond.extend_from_slice(b"NOT ");
    }
    profond.extend_from_slice(b"SEEN");
    assert_eq!(
        Search::parse(&profond, &BORNES).err(),
        Some(Error::SearchTooDeep {
            limit: super::SEARCH_DEPTH_MAX
        })
    );
}

/// La borne vaut aussi DANS des parenthèses : elle porte sur l'expression, pas
/// sur sa forme.
#[test]
fn une_expression_demesuree_entre_parentheses_est_refusee_aussi() {
    let mut longue = std::vec::Vec::from(&b"("[..]);
    for _ in 0..super::SEARCH_KEYS_MAX {
        longue.extend_from_slice(b"SEEN ");
    }
    longue.extend_from_slice(b")");
    assert_eq!(
        Search::parse(&longue, &BORNES).err(),
        Some(Error::SearchTooComplex {
            limit: super::SEARCH_KEYS_MAX
        })
    );
}

/// **Le tableau de nœuds est fini**, et une conjonction assez longue le remplit.
#[test]
fn une_expression_demesuree_est_refusee() {
    let mut longue = std::vec::Vec::new();
    for _ in 0..super::SEARCH_KEYS_MAX {
        longue.extend_from_slice(b"SEEN ");
    }
    assert_eq!(
        Search::parse(&longue, &BORNES).err(),
        Some(Error::SearchTooComplex {
            limit: super::SEARCH_KEYS_MAX
        })
    );
}

/// **`Search::NONE` ne désigne rien**, ce qui est la seule réponse qui ne mente
/// pas à qui ne saurait plus lire une expression.
#[test]
fn l_expression_vide_ne_designe_rien() {
    let rien = Search::NONE;
    assert!(!rien.is_empty());
    for sequence in [0_u32, 1, 2, u32::MAX] {
        assert!(!rien.matches(
            &message(sequence, sequence, 0, Flags::NONE, 0),
            3,
            30,
            &mut muette()
        ));
    }
}

/// Un nœud ne référence que des nœuds d'indice strictement inférieur : c'est ce
/// qui rend le cycle impossible, et l'évaluation sûre.
#[test]
fn l_arbre_ne_designe_que_vers_le_bas() {
    let recherche = Search::parse(b"OR (SEEN DELETED) NOT UNSEEN", &BORNES).expect("lisible");
    assert!(recherche.len() > 1);
    assert!(!recherche.is_empty());
    for (rang, noeud) in recherche.noeuds.iter().take(recherche.len()).enumerate() {
        let rang = u16::try_from(rang).expect("un indice tient");
        match *noeud {
            super::Noeud::Non(clef) => assert!(clef < rang),
            super::Noeud::Ou(gauche, droite) | super::Noeud::Et(gauche, droite) => {
                assert!(gauche < rang);
                assert!(droite < rang);
            }
            _ => {}
        }
    }
}

// ── Les critères qui lisent le message ──────────────────────────────────────

/// Lit un critère, et rend ce qu'il demande de chercher.
fn demandes(critere: &[u8]) -> std::vec::Vec<(SearchScope, std::vec::Vec<u8>, std::vec::Vec<u8>)> {
    let recherche = Search::parse(critere, &BORNES).expect("lisible");
    let mut vues = std::vec::Vec::new();
    let _ = recherche.matches(
        &message(1, 10, 100, Flags::NONE, JANVIER),
        3,
        30,
        &mut Source {
            texte: |portee, champ: &[u8], texte: &[u8]| {
                vues.push((
                    portee,
                    std::vec::Vec::from(champ),
                    std::vec::Vec::from(texte),
                ));
                true
            },
            jour: None,
        },
    );
    vues
}

/// **CHAQUE MOT-CLEF NOMME SON CHAMP, SAUF `HEADER`** : c'est le client qui le
/// nomme, et les confondre ferait lire le TEXTE cherché comme un nom de champ.
#[test]
fn chaque_mot_clef_nomme_son_champ() {
    assert_eq!(
        demandes(b"SUBJECT facture"),
        std::vec![(
            SearchScope::Header,
            std::vec::Vec::from(&b"subject"[..]),
            std::vec::Vec::from(&b"facture"[..])
        )]
    );
    assert_eq!(
        demandes(b"HEADER X-Chose valeur"),
        std::vec![(
            SearchScope::Header,
            std::vec::Vec::from(&b"X-Chose"[..]),
            std::vec::Vec::from(&b"valeur"[..])
        )]
    );
    for (critere, champ) in [
        (&b"FROM jean"[..], &b"from"[..]),
        (b"TO jean", b"to"),
        (b"CC jean", b"cc"),
        (b"BCC jean", b"bcc"),
    ] {
        assert_eq!(
            demandes(critere).first().map(|vu| vu.1.clone()),
            Some(std::vec::Vec::from(champ))
        );
    }
}

/// Le corps et le message entier ne nomment aucun champ.
#[test]
fn le_corps_et_le_texte_ne_nomment_aucun_champ() {
    assert_eq!(
        demandes(b"BODY facture"),
        std::vec![(
            SearchScope::Body,
            std::vec::Vec::new(),
            std::vec::Vec::from(&b"facture"[..])
        )]
    );
    assert_eq!(
        demandes(b"TEXT facture").first().map(|vu| vu.0),
        Some(SearchScope::Text)
    );
}

/// Une chaîne citée garde ses blancs : c'est tout l'intérêt des guillemets.
#[test]
fn une_chaine_citee_garde_ses_blancs() {
    assert_eq!(
        demandes(b"SUBJECT \"la facture\"")
            .first()
            .map(|vu| vu.2.clone()),
        Some(std::vec::Vec::from(&b"la facture"[..]))
    );
    // Et une chaîne citée VIDE est licite.
    assert_eq!(
        demandes(b"HEADER X-Chose \"\"")
            .first()
            .map(|vu| vu.2.clone()),
        Some(std::vec::Vec::new())
    );
}

/// **UN TEXTE VIDE EST VRAI DE TOUT MESSAGE** (§6.4.4) — sauf pour `HEADER`, où
/// il demande que le CHAMP existe. Passer les autres au magasin lui ferait lire
/// un message pour rien.
#[test]
fn un_texte_vide_ne_fait_pas_lire_le_message() {
    // Le corps : vrai sans rien demander.
    let mut demande = false;
    let vide = Search::parse(b"BODY \"\"", &BORNES).expect("lisible");
    assert!(vide.matches(
        &message(1, 10, 100, Flags::NONE, JANVIER),
        3,
        30,
        &mut Source {
            texte: |_, _: &[u8], _: &[u8]| {
                demande = true;
                false
            },
            jour: None,
        }
    ));
    assert!(!demande, "le corps vide n'avait rien à demander");
    // L'en-tête : on demande, parce que le champ peut manquer.
    assert_eq!(demandes(b"HEADER X-Chose \"\"").len(), 1);
}

/// Les critères de contenu se combinent comme les autres.
#[test]
fn les_criteres_de_contenu_se_combinent() {
    let recherche = Search::parse(b"NOT SUBJECT facture", &BORNES).expect("lisible");
    let candidat = message(1, 10, 100, Flags::NONE, JANVIER);
    assert!(!recherche.matches(
        &candidat,
        3,
        30,
        &mut Source {
            texte: |_, _: &[u8], _: &[u8]| true,
            jour: None,
        }
    ));
    assert!(recherche.matches(&candidat, 3, 30, &mut muette()));
}

/// Une clef de contenu sans son texte est une faute.
#[test]
fn une_clef_de_contenu_sans_texte_est_une_faute() {
    for critere in [
        &b"SUBJECT"[..],
        // `HEADER` sans même son champ.
        b"HEADER",
        b"HEADER X-Chose",
        b"SUBJECT )",
        b"OR SUBJECT SEEN",
        // Une chaîne qui ne se ferme pas.
        b"SUBJECT \"facture",
    ] {
        assert_eq!(
            Search::parse(critere, &BORNES).err(),
            Some(Error::MalformedSearch),
            "{:?}",
            core::str::from_utf8(critere)
        );
    }
}

// ── LES OPTIONS DE RETOUR (§6.4.4) ──────────────────────────────────────────

/// **SANS OPTION, C'EST `ALL`** — et `()` aussi, ce que §6.4.4 dit en toutes
/// lettres.
#[test]
fn sans_option_de_retour_c_est_la_liste_entiere() {
    for arguments in [&b"ALL"[..], b"RETURN () ALL", b"  ALL"] {
        let (demande, reste) = SearchReturn::parse(arguments).expect("lisible");
        assert_eq!(demande.ecrit(), SearchReturn::TOUT.ecrit(), "{arguments:?}");
        assert!(demande.all && !demande.min && !demande.max, "{arguments:?}");
        assert_eq!(reste.trim_ascii(), b"ALL", "{arguments:?}");
    }
}

/// **`RETURN ()` N'EST PAS « RIEN ÉCRIT ».**
///
/// Les deux demandent la même chose — §6.4.4 : sans option, `ALL` est supposé —
/// et ne se répondent pas pareil. Écrire `RETURN`, c'est employer l'extension de
/// RFC 4731, dont `ESEARCH` est la réponse ; ne rien écrire, c'est le `SEARCH`
/// de RFC 3501, dont un client rev1 attend `* SEARCH 2 4 5`.
#[test]
fn une_clause_return_ecrite_se_distingue_de_son_absence() {
    let (nue, _) = SearchReturn::parse(b"ALL").expect("lisible");
    let (vide, _) = SearchReturn::parse(b"RETURN () ALL").expect("lisible");
    let (nommee, _) = SearchReturn::parse(b"RETURN (ALL) UNSEEN").expect("lisible");

    assert!(!nue.explicite, "aucune clause n'a été écrite");
    assert!(vide.explicite, "`RETURN ()` est une clause écrite");
    assert!(nommee.explicite);

    // `RETURNED` N'EST PAS `RETURN` : ce critère-là n'écrit aucune clause.
    let (critere, _) = SearchReturn::parse(b"RETURNED").expect("lisible");
    assert!(!critere.explicite);
}

/// Les cinq options se lisent, dans n'importe quel ordre et n'importe quelle
/// casse.
#[test]
fn les_cinq_options_se_lisent() {
    let (demande, reste) =
        SearchReturn::parse(b"RETURN (min MAX all Count SAVE) UNSEEN").expect("lisible");
    assert_eq!(
        demande,
        SearchReturn {
            min: true,
            max: true,
            all: true,
            count: true,
            save: true,
            explicite: true,
        }
    );
    assert_eq!(reste.trim_ascii(), b"UNSEEN");

    // `SAVE` SEUL N'ÉCRIT RIEN : §6.4.4 veut qu'il supprime alors la réponse.
    let (seul, _) = SearchReturn::parse(b"RETURN (SAVE) ALL").expect("lisible");
    assert!(seul.save);
    assert!(!seul.ecrit());
}

/// **`RETURNED` N'EST PAS `RETURN`** : un critère qui commence par ces lettres
/// reste un critère.
#[test]
fn un_critere_qui_commence_par_return_reste_un_critere() {
    let (demande, reste) = SearchReturn::parse(b"RETURNED").expect("lisible");
    assert_eq!(demande, SearchReturn::TOUT);
    assert_eq!(reste, b"RETURNED");
}

/// **UNE OPTION QU'ON NE SERT PAS EST UN `BAD`** — §6.4.4 l'exige, et non un
/// silence qui rendrait autre chose que ce qui a été demandé.
#[test]
fn une_option_de_retour_inconnue_se_refuse() {
    for arguments in [
        &b"RETURN (RELEVANCY) ALL"[..],
        b"RETURN (MIN PARTIAL) ALL",
        // Une parenthèse qui manque, d'un côté ou de l'autre.
        b"RETURN MIN ALL",
        b"RETURN (MIN ALL",
        // Un emboîtement, qui ne voudrait rien dire ici.
        b"RETURN ((MIN)) ALL",
        // Rien après `RETURN`.
        b"RETURN ",
    ] {
        assert_eq!(
            SearchReturn::parse(arguments),
            Err(Error::MalformedSearch),
            "{arguments:?}"
        );
    }
}

/// Ce qui est lu se montre — la dérive sert au fuzz et aux messages d'échec.
#[test]
fn les_options_de_retour_se_montrent() {
    let (demande, _) = SearchReturn::parse(b"RETURN (COUNT) ALL").expect("lisible");
    assert!(std::format!("{demande:?}").contains("count: true"));
    assert_eq!(demande, demande);
}

// ── LA DATE ÉCRITE N'EST PAS LA DATE D'ARRIVÉE ──────────────────────────────

/// Cherche avec une source qui dit un jour donné.
fn ecrit_le(critere: &[u8], jour: Option<u64>) -> bool {
    let recherche = Search::parse(critere, &BORNES).expect("lisible");
    recherche.matches(
        &message(1, 10, 100, Flags::NONE, JANVIER),
        3,
        30,
        &mut Source {
            texte: |_, _: &[u8], _: &[u8]| false,
            jour,
        },
    )
}

/// **`SENTBEFORE` COMPARE LE CHAMP `Date:`**, là où `BEFORE` compare la date
/// d'arrivée. Un message écrit lundi et reçu vendredi répond à l'une et pas à
/// l'autre.
#[test]
fn les_criteres_d_ecriture_lisent_le_champ_date() {
    // Le 29 août 2026, en jours depuis l'époque.
    const AOUT_ECRIT: u64 = 20_694;
    const VEILLE: u64 = AOUT_ECRIT - 1;

    assert!(ecrit_le(b"SENTON 29-Aug-2026", Some(AOUT_ECRIT)));
    assert!(!ecrit_le(b"SENTON 29-Aug-2026", Some(VEILLE)));
    assert!(ecrit_le(b"SENTBEFORE 29-Aug-2026", Some(VEILLE)));
    assert!(!ecrit_le(b"SENTBEFORE 29-Aug-2026", Some(AOUT_ECRIT)));
    assert!(ecrit_le(b"SENTSINCE 29-Aug-2026", Some(AOUT_ECRIT)));
    assert!(!ecrit_le(b"SENTSINCE 29-Aug-2026", Some(VEILLE)));

    // **LES DEUX FAMILLES NE DISENT PAS LA MÊME CHOSE** : ce message est ARRIVÉ
    // en janvier, et l'on prétend ici qu'il a été ÉCRIT en août.
    assert!(ecrit_le(b"SENTSINCE 29-Aug-2026", Some(AOUT_ECRIT)));
    assert!(!ecrit_le(b"SINCE 29-Aug-2026", Some(AOUT_ECRIT)));

    // **SANS DATE LISIBLE, AUCUN NE CORRESPOND** : on ne compare pas ce qui
    // n'est pas là, et tenir l'absence pour l'époque ferait répondre le message
    // à tous les `SENTBEFORE`.
    for critere in [
        &b"SENTBEFORE 29-Aug-2026"[..],
        b"SENTON 29-Aug-2026",
        b"SENTSINCE 29-Aug-2026",
    ] {
        assert!(!ecrit_le(critere, None), "{critere:?}");
    }
}

/// **`SENTON` NE SE LIT PAS COMME `ON`** : les mots les plus longs se
/// reconnaissent d'abord, sans quoi le second ne serait jamais atteint.
#[test]
fn les_mots_les_plus_longs_se_reconnaissent_d_abord() {
    // Si `ON` gagnait, `SENTON …` ne serait pas même lisible.
    assert!(Search::parse(b"SENTON 29-Aug-2026", &BORNES).is_ok());
    assert!(Search::parse(b"SENTBEFORE 29-Aug-2026", &BORNES).is_ok());
    assert!(Search::parse(b"SENTSINCE 29-Aug-2026", &BORNES).is_ok());
    // Et une date illisible reste illisible.
    assert!(Search::parse(b"SENTON 32-Aug-2026", &BORNES).is_err());
    assert!(Search::parse(b"SENTON", &BORNES).is_err());
}

// ── LES MOTS-CLEFS (§6.4.4) ─────────────────────────────────────────────────

/// **`KEYWORD` PORTE SON MOT-CLEF EN ARGUMENT**, là où `SEEN` le porte dans son
/// nom — et `UNKEYWORD` est le même, nié.
#[test]
fn keyword_porte_son_mot_clef_en_argument() {
    let messages = |drapeaux: Flags| message(1, 10, 100, drapeaux, JANVIER);
    let pose = Search::parse(b"KEYWORD $Junk", &BORNES).expect("lisible");
    assert!(pose.matches(&messages(Flags::JUNK), 3, 30, &mut muette()));
    assert!(!pose.matches(&messages(Flags::NONE), 3, 30, &mut muette()));

    let absent = Search::parse(b"UNKEYWORD $Junk", &BORNES).expect("lisible");
    assert!(!absent.matches(&messages(Flags::JUNK), 3, 30, &mut muette()));
    assert!(absent.matches(&messages(Flags::NONE), 3, 30, &mut muette()));

    // La casse ne compte pas, ni pour le mot-clef ni pour le critère.
    let casse = Search::parse(b"keyword $junk", &BORNES).expect("lisible");
    assert!(casse.matches(&messages(Flags::JUNK), 3, 30, &mut muette()));

    // **`$NonJunk` N'EST PAS L'INVERSE DE `$Junk`** : les deux peuvent manquer,
    // et cela veut dire « personne n'a tranché ».
    let ni = Search::parse(b"UNKEYWORD $Junk UNKEYWORD $NonJunk", &BORNES).expect("lisible");
    assert!(ni.matches(&messages(Flags::NONE), 3, 30, &mut muette()));
}

/// **UN MOT-CLEF QU'ON NE SERT PAS EST UN REFUS, PAS UNE FAUTE DE SYNTAXE** : le
/// dire ainsi évite au client de chercher l'erreur dans ce qu'il a écrit.
#[test]
fn un_mot_clef_qu_on_ne_sert_pas_se_refuse() {
    for critere in [
        &b"KEYWORD $Invente"[..],
        b"UNKEYWORD monetiquette",
        b"KEYWORD $NonExistant",
        // Sans argument non plus, il n'y a rien à servir.
        b"KEYWORD",
    ] {
        assert_eq!(
            Search::parse(critere, &BORNES).err(),
            Some(Error::UnsupportedSearchKey),
            "{critere:?}"
        );
    }
}

/// **UN GUILLEMET DANS UN TEXTE COUPERAIT L'EXPRESSION EN DEUX.**
///
/// Ce n'est pas une faute de syntaxe qu'on verrait : c'est une recherche qui
/// porterait sur la moitié du texte demandé, et qui rendrait des résultats
/// plausibles. §4.3 de RFC 9051 échappe donc le guillemet et la barre oblique
/// inverse, et rien d'autre.
#[test]
fn une_chaine_citee_echappe_ce_qui_la_fermerait() {
    let mut place = [0_u8; 64];
    let cas: [(&[u8], &str); 4] = [
        (b"facture", "\"facture\""),
        (b"", "\"\""),
        (b"dit \"oui\"", "\"dit \\\"oui\\\"\""),
        (b"c:\\dossier", "\"c:\\\\dossier\""),
    ];
    for (texte, attendu) in cas {
        let ecrits = super::write_quoted(texte, &mut place).expect("écrivable");
        assert_eq!(
            core::str::from_utf8(place.get(..ecrits).expect("écrits")),
            Ok(attendu),
            "{texte:?}"
        );
    }
}

/// **UNE CHAÎNE CITÉE NE PORTE PAS DE FIN DE LIGNE** (§4.3).
///
/// Elle ferait deux lignes d'une, et le lecteur prendrait la seconde pour du
/// protocole. On refuse plutôt que d'effacer : effacer chercherait un texte que
/// personne n'a demandé.
#[test]
fn une_chaine_citee_refuse_une_fin_de_ligne() {
    let mut place = [0_u8; 64];
    for texte in [&b"deux\r\nlignes"[..], b"avec\rretour", b"avec\nsaut"] {
        assert_eq!(
            super::write_quoted(texte, &mut place),
            Err(Error::ResponseTextNotPrintable),
            "{texte:?}"
        );
    }
}

/// **UN TAMPON TROP COURT DIT COMBIEN IL AURAIT FALLU**, et non « ça ne tient
/// pas » : l'appelant peut alors demander la bonne taille du premier coup.
///
/// **TOUTES LES TAILLES JUSQU'À LA BONNE**, et pas seulement une : chaque octet
/// écrit a son chemin d'échec — le guillemet ouvrant, l'antislash d'un
/// échappement, le caractère qu'il protège, le guillemet fermant. Une seule
/// taille n'en met en jeu qu'un.
#[test]
fn un_tampon_trop_court_dit_ce_qu_il_aurait_fallu() {
    let mut place = [0_u8; 4];
    let faute = super::write_quoted(b"facture", &mut place).expect_err("trop court");
    assert_eq!(faute, Error::BufferTooSmall { needed: 16 });

    // Un texte qui porte les deux octets à échapper, pour que chaque chemin
    // d'écriture soit atteint.
    let texte: &[u8] = b"a\"b\\c";
    let mut grand = [0_u8; 32];
    let entier = super::write_quoted(texte, &mut grand).expect("écrivable");
    for taille in 0..entier {
        let mut petit = std::vec![0_u8; taille];
        assert!(
            matches!(
                super::write_quoted(texte, &mut petit),
                Err(Error::BufferTooSmall { .. })
            ),
            "à {taille} octets, cela devait manquer de place"
        );
    }
    assert!(super::write_quoted(texte, &mut grand[..entier]).is_ok());
}
