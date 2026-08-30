//! Ce qu'une structure dit d'un message.

use super::{ENTETE_DE_PARTIE_MAX, STRUCTURE_DEPTH_MAX, STRUCTURE_PARTS_MAX};
use crate::{BodyScanner, BodySpan, Error, Limits, write_body_structure};

const BORNES: Limits = Limits::DEFAULT;

/// Compose la structure d'un message, ou panique.
fn structure(message: &[u8]) -> std::string::String {
    let mut sortie = [0_u8; 64 * 1024];
    let ecrits = write_body_structure(message, &mut sortie, &BORNES).expect("composable");
    std::string::String::from_utf8_lossy(sortie.get(..ecrits).unwrap_or_default()).into_owned()
}

/// La même chose, en poussant le message par morceaux de `taille`.
fn par_morceaux(message: &[u8], taille: usize) -> std::string::String {
    let mut balayeur = BodyScanner::new(&BORNES);
    for morceau in message.chunks(taille) {
        balayeur.push(morceau);
    }
    balayeur.finish();
    let mut sortie = [0_u8; 64 * 1024];
    let ecrits = balayeur.write(&mut sortie).expect("composable");
    std::string::String::from_utf8_lossy(sortie.get(..ecrits).unwrap_or_default()).into_owned()
}

// --- Le contenu simple ----------------------------------------------------

/// Sans `Content-Type:`, c'est du texte en US-ASCII (RFC 2045 §5.2).
#[test]
fn un_message_nu_est_du_texte_en_us_ascii() {
    assert_eq!(
        structure(b"Subject: x\r\n\r\nbonjour\r\n"),
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 9 1 NIL NIL NIL NIL)"
    );
}

/// Le type, le sous-type, les paramètres et l'encodage se lisent.
#[test]
fn ce_que_l_en_tete_declare_se_rend() {
    assert_eq!(
        structure(
            b"Content-Type: text/plain; charset=utf-8\r\n\
              Content-Transfer-Encoding: 8bit\r\n\r\nun\r\ndeux\r\n"
        ),
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"utf-8\") NIL NIL \"8BIT\" 10 2 NIL NIL NIL NIL)"
    );
}

/// Identifiant et description passent tels quels.
#[test]
fn l_identifiant_et_la_description_se_rendent() {
    let compose = structure(
        b"Content-Type: image/png\r\n\
          Content-Id: <abc@x.test>\r\n\
          Content-Description: une image\r\n\r\nPNG",
    );
    assert_eq!(
        compose,
        "(\"IMAGE\" \"PNG\" NIL \"<abc@x.test>\" \"une image\" \"7BIT\" 3 NIL NIL NIL NIL)"
    );
}

/// LES LIGNES NE SE COMPTENT QUE POUR DU TEXTE : la grammaire ne les admet nulle
/// part ailleurs, et les rendre quand même décalerait tous les champs suivants.
#[test]
fn seul_le_texte_compte_ses_lignes() {
    assert!(structure(b"Content-Type: image/png\r\n\r\nPNG\r\n").contains("\"7BIT\" 5 NIL"));
    assert!(structure(b"Content-Type: text/html\r\n\r\nPNG\r\n").contains("\"7BIT\" 5 1 NIL"));
}

/// Une dernière ligne sans `CRLF` reste une ligne.
#[test]
fn une_ligne_sans_fin_reste_une_ligne() {
    assert!(structure(b"\r\nun\r\ndeux").contains("\"7BIT\" 8 2 "));
}

/// Un corps vide ne porte aucune ligne.
#[test]
fn un_corps_vide_ne_porte_aucune_ligne() {
    assert!(structure(b"Subject: x\r\n\r\n").contains("\"7BIT\" 0 0 "));
}

// --- Les multipart --------------------------------------------------------

const DEUX_PARTIES: &[u8] = b"Content-Type: multipart/mixed; boundary=\"XY\"\r\n\r\n\
preambule\r\n\
--XY\r\n\
Content-Type: text/plain\r\n\r\n\
corps un\r\n\
--XY\r\n\
Content-Type: application/pdf; name=\"a.pdf\"\r\n\
Content-Disposition: attachment; filename=\"a.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
QUJD\r\n\
--XY--\r\n\
epilogue\r\n";

/// Les filles se suivent, puis vient ce que le `multipart` est.
#[test]
fn les_parties_se_suivent_puis_le_multipart_se_nomme() {
    assert_eq!(
        structure(DEUX_PARTIES),
        "((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 8 1 NIL NIL NIL NIL)\
         (\"APPLICATION\" \"PDF\" (\"NAME\" \"a.pdf\") NIL NIL \"BASE64\" 4 NIL \
         (\"ATTACHMENT\" (\"FILENAME\" \"a.pdf\")) NIL NIL) \
         \"MIXED\" (\"BOUNDARY\" \"XY\") NIL NIL NIL)"
    );
}

/// LE DÉCOUPAGE NE CHANGE PAS LE RÉSULTAT. C'est la propriété du balayeur : le
/// serveur pousse ce qu'il a lu, et ce qu'il a lu dépend de son tampon.
#[test]
fn le_decoupage_ne_change_pas_le_resultat() {
    let attendu = structure(DEUX_PARTIES);
    for taille in [1_usize, 2, 3, 5, 17, 64, 1024] {
        assert_eq!(par_morceaux(DEUX_PARTIES, taille), attendu, "par {taille}");
    }
}

const IMBRIQUE: &[u8] = b"Content-Type: multipart/mixed; boundary=A\r\n\r\n\
--A\r\n\
Content-Type: multipart/alternative; boundary=\"B\"\r\n\r\n\
--B\r\n\
Content-Type: text/plain\r\n\r\n\
brut\r\n\
--B\r\n\
Content-Type: text/html\r\n\r\n\
<p>riche</p>\r\n\
--B--\r\n\
--A\r\n\
Content-Type: image/png\r\n\r\n\
PNG\r\n\
--A--\r\n";

/// Un `multipart` dans un `multipart` s'emboîte.
#[test]
fn les_multipart_s_emboitent() {
    assert_eq!(
        structure(IMBRIQUE),
        "(((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 4 1 NIL NIL NIL NIL)\
         (\"TEXT\" \"HTML\" NIL NIL NIL \"7BIT\" 12 1 NIL NIL NIL NIL) \
         \"ALTERNATIVE\" (\"BOUNDARY\" \"B\") NIL NIL NIL)\
         (\"IMAGE\" \"PNG\" NIL NIL NIL \"7BIT\" 3 NIL NIL NIL NIL) \
         \"MIXED\" (\"BOUNDARY\" \"A\") NIL NIL NIL)"
    );
    let attendu = structure(IMBRIQUE);
    for taille in [1_usize, 4, 13, 512] {
        assert_eq!(par_morceaux(IMBRIQUE, taille), attendu, "par {taille}");
    }
}

/// UNE FRONTIÈRE DU DESSUS FERME CE QUI EST DESSOUS. Un `multipart` intérieur
/// qui ne se ferme pas ne doit pas avaler la suite du message.
#[test]
fn la_frontiere_du_dessus_ferme_ce_qui_est_dessous() {
    let compose = structure(
        b"Content-Type: multipart/mixed; boundary=A\r\n\r\n\
--A\r\n\
Content-Type: multipart/alternative; boundary=B\r\n\r\n\
--B\r\n\
Content-Type: text/plain\r\n\r\n\
brut\r\n\
--A\r\n\
Content-Type: image/png\r\n\r\n\
PNG\r\n\
--A--\r\n",
    );
    assert!(compose.contains("\"ALTERNATIVE\""), "{compose}");
    assert!(compose.contains("(\"IMAGE\" \"PNG\""), "{compose}");
}

/// Une frontière admet des blancs après elle (RFC 2046 §5.1.1).
#[test]
fn une_frontiere_admet_les_blancs_qui_la_suivent() {
    let compose = structure(
        b"Content-Type: multipart/mixed; boundary=A\r\n\r\n--A  \t\r\n\r\nun\r\n--A--  \r\n",
    );
    assert!(compose.contains("\"7BIT\" 2 1"), "{compose}");
}

/// Ce qui commence par `--` sans être une frontière connue est du corps.
#[test]
fn ce_qui_ressemble_a_une_frontiere_sans_l_etre_est_du_corps() {
    let compose = structure(
        b"Content-Type: multipart/mixed; boundary=A\r\n\r\n--A\r\n\r\n--Z\r\nx\r\n--A--\r\n",
    );
    assert!(compose.contains("\"7BIT\" 6 2"), "{compose}");
}

/// Une partie sans en-tête du tout prend les défauts de la RFC 2045.
#[test]
fn une_partie_sans_en_tete_prend_les_defauts() {
    let compose =
        structure(b"Content-Type: multipart/mixed; boundary=A\r\n\r\n--A\r\n\r\nnu\r\n--A--\r\n");
    assert!(
        compose.contains("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\")"),
        "{compose}"
    );
}

/// UN `multipart` VIDE RESTE LISIBLE : la grammaire de §7.5.2 exige au moins un
/// corps, et un client qui n'en trouve aucun ne peut plus lire la suite.
#[test]
fn un_multipart_sans_fille_rend_un_corps_vide() {
    let compose = structure(b"Content-Type: multipart/mixed; boundary=A\r\n\r\n--A--\r\n");
    assert!(
        compose.starts_with("((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 0 0"),
        "{compose}"
    );
}

/// UN `multipart` SANS FRONTIÈRE N'EN EST PLUS UN : MIME veut qu'une entité
/// qu'on ne sait pas interpréter soit traitée en `application/octet-stream`, et
/// un type `MULTIPART` suivi d'une taille n'existe pas dans la grammaire.
#[test]
fn un_multipart_sans_frontiere_devient_un_flot_d_octets() {
    assert_eq!(
        structure(b"Content-Type: multipart/mixed\r\n\r\ncorps\r\n"),
        "(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"7BIT\" 7 NIL NIL NIL NIL)"
    );
    // Une frontière vide ne vaut pas mieux qu'une frontière absente.
    assert!(
        structure(b"Content-Type: multipart/mixed; boundary=\"\"\r\n\r\nx\r\n")
            .starts_with("(\"APPLICATION\" \"OCTET-STREAM\"")
    );
}

/// Au-delà de la profondeur, le `multipart` est décrit comme ce qu'il est
/// devenu : un contenu qu'on n'ouvre pas.
#[test]
fn la_profondeur_est_bornee() {
    let mut message = std::vec::Vec::new();
    for niveau in 0..=STRUCTURE_DEPTH_MAX {
        message.extend_from_slice(b"Content-Type: multipart/mixed; boundary=F");
        message.extend_from_slice(std::format!("{niveau}").as_bytes());
        message.extend_from_slice(b"\r\n\r\n--F");
        message.extend_from_slice(std::format!("{niveau}").as_bytes());
        message.extend_from_slice(b"\r\n");
    }
    message.extend_from_slice(b"\r\nfond\r\n");
    let compose = structure(&message);
    assert!(
        compose.contains("\"APPLICATION\" \"OCTET-STREAM\""),
        "{compose}"
    );
}

/// Au-delà du nombre de parties, ce qui reste n'est plus décrit — mais ce qui
/// est décrit reste lisible.
#[test]
fn le_nombre_de_parties_est_borne() {
    let mut message =
        std::vec::Vec::from(&b"Content-Type: multipart/mixed; boundary=A\r\n\r\n"[..]);
    for _ in 0..(STRUCTURE_PARTS_MAX + 5) {
        message.extend_from_slice(b"--A\r\nContent-Type: text/plain\r\n\r\nx\r\n");
    }
    message.extend_from_slice(b"--A--\r\n");
    let compose = structure(&message);
    let filles = compose.matches("\"TEXT\" \"PLAIN\"").count();
    assert_eq!(filles, STRUCTURE_PARTS_MAX - 1, "{filles}");
}

// --- Les messages encapsulés ----------------------------------------------

/// Un `message/rfc822` porte l'enveloppe et la structure de ce qu'il contient.
#[test]
fn un_message_encapsule_porte_son_enveloppe_et_sa_structure() {
    assert_eq!(
        structure(
            b"Content-Type: message/rfc822\r\n\r\n\
              From: a@b.test\r\n\
              Subject: dedans\r\n\r\n\
              le corps\r\n"
        ),
        "(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 45 \
         (NIL \"dedans\" ((NIL NIL \"a\" \"b.test\")) ((NIL NIL \"a\" \"b.test\")) \
         ((NIL NIL \"a\" \"b.test\")) NIL NIL NIL NIL NIL) \
         (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 10 1 NIL NIL NIL NIL) \
         4 NIL NIL NIL NIL)"
    );
}

/// LES LIGNES D'UN MESSAGE ENCAPSULÉ SONT CELLES DU MESSAGE ENTIER, en-tête
/// compris — c'est ce que §7.5.2 appelle sa taille en lignes.
#[test]
fn un_message_encapsule_compte_son_en_tete() {
    let compose = structure(
        b"Content-Type: multipart/mixed; boundary=A\r\n\r\n\
--A\r\n\
Content-Type: message/rfc822\r\n\r\n\
Subject: x\r\n\r\n\
un\r\n\
deux\r\n\
--A--\r\n",
    );
    // « Subject: x », la ligne vide, « un », « deux » : quatre lignes.
    assert!(compose.contains(" 4 NIL NIL NIL NIL)"), "{compose}");
}

/// Un `message/rfc822` vide reste lisible.
#[test]
fn un_message_encapsule_vide_reste_lisible() {
    let compose = structure(b"Content-Type: message/rfc822\r\n\r\n");
    assert!(
        compose.contains("(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)"),
        "{compose}"
    );
    assert!(
        compose.contains("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\")"),
        "{compose}"
    );
}

// --- Les paramètres -------------------------------------------------------

/// Un paramètre cité, un paramètre nu, et un point-virgule qui ne mène à rien.
#[test]
fn les_parametres_se_lisent_cites_ou_nus() {
    let compose =
        structure(b"Content-Type: text/plain; charset=utf-8; format=\"flowed\"; ;\r\n\r\nx\r\n");
    assert!(
        compose.contains("(\"CHARSET\" \"utf-8\" \"FORMAT\" \"flowed\")"),
        "{compose}"
    );
}

/// Un nom sans valeur ne fait pas un paramètre.
#[test]
fn un_nom_sans_valeur_ne_fait_pas_un_parametre() {
    assert!(structure(b"Content-Type: text/plain; seul\r\n\r\nx\r\n").contains("\"PLAIN\" NIL"));
}

/// Une chaîne qui ne se ferme pas se lit jusqu'au bout.
#[test]
fn une_valeur_qui_ne_se_ferme_pas_se_lit_jusqu_au_bout() {
    let compose = structure(b"Content-Type: text/plain; charset=\"utf-8\r\n\r\nx\r\n");
    assert!(compose.contains("(\"CHARSET\" \"utf-8\")"), "{compose}");
}

/// Un échappement dans une valeur citée ne ferme pas la chaîne.
#[test]
fn un_echappement_ne_ferme_pas_la_valeur() {
    let compose = structure(b"Content-Type: text/plain; name=\"a\\\"b\"; x=1\r\n\r\nz\r\n");
    assert!(
        compose.contains("\"NAME\" \"a\\\"b\" \"X\" \"1\""),
        "{compose}"
    );
}

/// La disposition porte ses propres paramètres, ou rien.
#[test]
fn la_disposition_se_rend_avec_ses_parametres() {
    assert!(structure(b"Content-Disposition: inline\r\n\r\nx\r\n").contains("(\"INLINE\" NIL)"));
    assert!(structure(b"Content-Disposition: ;\r\n\r\nx\r\n").ends_with("NIL NIL NIL NIL)"));
}

/// Un commentaire dans le type ne fait pas partie du sous-type.
#[test]
fn un_commentaire_ne_fait_pas_partie_du_sous_type() {
    assert!(
        structure(b"Content-Type: text/plain (du texte)\r\n\r\nx\r\n")
            .starts_with("(\"TEXT\" \"PLAIN\"")
    );
}

/// Un type sans barre n'a pas de sous-type : le défaut sert.
#[test]
fn un_type_sans_barre_prend_le_sous_type_par_defaut() {
    assert!(structure(b"Content-Type: text\r\n\r\nx\r\n").starts_with("(\"TEXT\" \"PLAIN\""));
}

// --- Les bornes -----------------------------------------------------------

/// Un en-tête de partie plus long que ce qu'on retient ne fait pas échouer.
#[test]
fn un_en_tete_de_partie_trop_long_ne_fait_pas_echouer() {
    let mut message = std::vec::Vec::from(&b"Content-Type: text/plain\r\n"[..]);
    while message.len() < ENTETE_DE_PARTIE_MAX + 2048 {
        message.extend_from_slice(b"X-Bourrage: 0123456789012345678901234567890123456789\r\n");
    }
    message.extend_from_slice(b"\r\ncorps\r\n");
    assert!(structure(&message).starts_with("(\"TEXT\" \"PLAIN\""));
}

/// Une ligne plus longue que ce qu'on retient ne fait pas échouer non plus.
#[test]
fn une_ligne_trop_longue_ne_fait_pas_echouer() {
    let mut message = std::vec::Vec::from(&b"\r\n"[..]);
    message.extend_from_slice(&[b'x'; 4096]);
    message.extend_from_slice(b"\r\n");
    assert!(structure(&message).contains("\"7BIT\" 4098 1"));
}

/// L'arène des en-têtes est bornée : au-delà, les parties prennent les défauts.
#[test]
fn l_arene_des_en_tetes_est_bornee() {
    let mut message =
        std::vec::Vec::from(&b"Content-Type: multipart/mixed; boundary=A\r\n\r\n"[..]);
    let bourrage = "0123456789".repeat(60);
    // Assez de parties pour que l'arène finisse par ne plus rien accepter : les
    // premières gardent leur en-tête, les dernières n'en ont plus du tout.
    for _ in 0..(STRUCTURE_PARTS_MAX - 4) {
        message.extend_from_slice(b"--A\r\nContent-Type: text/html\r\nX-Bourrage: ");
        message.extend_from_slice(bourrage.as_bytes());
        message.extend_from_slice(b"\r\n\r\nx\r\n");
    }
    message.extend_from_slice(b"--A--\r\n");
    let compose = structure(&message);
    assert!(compose.contains("\"TEXT\" \"HTML\""), "html attendu");
    assert!(
        compose.contains("(\"CHARSET\" \"us-ascii\")"),
        "défauts attendus"
    );
}

/// Une frontière plus longue que ce que la RFC 2046 permet est tronquée, et le
/// balayage reste cohérent avec lui-même.
#[test]
fn une_frontiere_trop_longue_est_tronquee() {
    let longue = "F".repeat(100);
    let message = std::format!(
        "Content-Type: multipart/mixed; boundary=\"{longue}\"\r\n\r\n--{longue}\r\n\r\nx\r\n--{longue}--\r\n"
    );
    let compose = structure(message.as_bytes());
    assert!(compose.contains("\"MIXED\""), "{compose}");
}

/// Un tampon trop court le dit, et n'écrit pas une structure à moitié.
///
/// Le balayage passe par des chemins très différents selon ce que le message
/// porte ; le manque de place doit se dire sur CHACUN, et non seulement sur
/// celui qu'on a écrit en premier.
#[test]
fn un_tampon_trop_court_le_dit() {
    const ENCAPSULE: &[u8] = b"Content-Type: message/rfc822\r\n\r\n\
From: a@b.test\r\nSubject: dedans\r\n\r\nle corps\r\n";
    const VIDE: &[u8] = b"Content-Type: multipart/mixed; boundary=A\r\n\r\n--A--\r\n";
    const PARAMS: &[u8] = b"Content-Type: text/plain; charset=utf-8; format=flowed\r\n\r\nx\r\n";
    // Et le cas où un `message/rfc822` ne trouve plus de place pour ce qu'il
    // porte : son corps vide s'écrit là où presque rien d'autre ne passe.
    let sature = message_encapsule_sature();
    for message in [DEUX_PARTIES, IMBRIQUE, ENCAPSULE, VIDE, PARAMS, &sature] {
        let complet = structure(message);
        for place in 0..complet.len() {
            let mut sortie = std::vec![0_u8; place];
            assert_eq!(
                write_body_structure(message, &mut sortie, &BORNES),
                Err(Error::BufferTooSmall),
                "avec {place} octets"
            );
        }
    }
}

/// Un en-tête que la grammaire refuse laisse la partie à ses défauts.
#[test]
fn un_en_tete_illisible_laisse_les_defauts() {
    let bornes = Limits {
        max_fields: 1,
        ..Limits::DEFAULT
    };
    let mut sortie = [0_u8; 1024];
    let ecrits = write_body_structure(
        b"Content-Type: image/png\r\nSubject: x\r\n\r\nPNG\r\n",
        &mut sortie,
        &bornes,
    )
    .expect("composable");
    let compose = std::string::String::from_utf8_lossy(&sortie[..ecrits]).into_owned();
    assert!(compose.starts_with("(\"TEXT\" \"PLAIN\""), "{compose}");
}

/// Un message vide se décrit quand même.
#[test]
fn un_message_vide_se_decrit_quand_meme() {
    assert_eq!(
        structure(b""),
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 0 0 NIL NIL NIL NIL)"
    );
}

/// Les blancs autour du `=` d'un paramètre ne changent rien.
#[test]
fn les_blancs_autour_du_signe_ne_changent_rien() {
    let compose = structure(b"Content-Type: text/plain; charset = utf-8\r\n\r\nx\r\n");
    assert!(compose.contains("(\"CHARSET\" \"utf-8\")"), "{compose}");
}

/// La frontière se trouve où qu'elle soit dans les paramètres.
#[test]
fn la_frontiere_se_trouve_apres_les_autres_parametres() {
    let compose = structure(
        b"Content-Type: multipart/mixed; charset=utf-8; boundary=A\r\n\r\n--A\r\n\r\nx\r\n--A--\r\n",
    );
    assert!(compose.contains("\"MIXED\""), "{compose}");
    assert!(
        compose.contains("\"CHARSET\" \"utf-8\" \"BOUNDARY\" \"A\""),
        "{compose}"
    );
}

/// UN PLI NE PART PAS SUR LE FIL, ici non plus : une valeur de paramètre repliée
/// porte le `CRLF` du pli, et une chaîne IMAP n'en admet pas.
#[test]
fn un_pli_dans_un_parametre_ne_part_pas_sur_le_fil() {
    let compose = structure(b"Content-Type: text/plain; name=\"un\r\n deux\"\r\n\r\nx\r\n");
    assert!(compose.contains("\"NAME\" \"un deux\""), "{compose}");
    assert!(
        !compose.contains('\r') && !compose.contains('\n'),
        "{compose}"
    );
}

/// Un message qui s'arrête au milieu de son en-tête se décrit quand même.
#[test]
fn un_en_tete_sans_fin_se_decrit_quand_meme() {
    assert!(structure(b"Subject: x").starts_with("(\"TEXT\" \"PLAIN\""));
}

/// Un message dont la table de parties est déjà pleine quand vient un
/// `message/rfc822`.
fn message_encapsule_sature() -> std::vec::Vec<u8> {
    let mut message =
        std::vec::Vec::from(&b"Content-Type: multipart/mixed; boundary=A\r\n\r\n"[..]);
    for _ in 0..(STRUCTURE_PARTS_MAX - 2) {
        message.extend_from_slice(b"--A\r\nContent-Type: text/plain\r\n\r\nx\r\n");
    }
    message
        .extend_from_slice(b"--A\r\nContent-Type: message/rfc822\r\n\r\nSubject: y\r\n\r\nz\r\n");
    message.extend_from_slice(b"--A--\r\n");
    message
}

/// Un `message/rfc822` qui ne trouve plus de place pour ce qu'il porte reste
/// lisible : enveloppe vide, corps vide.
#[test]
fn un_message_encapsule_sans_place_reste_lisible() {
    let compose = structure(&message_encapsule_sature());
    assert!(compose.contains("\"MESSAGE\" \"RFC822\""), "{compose}");
    assert!(
        compose.contains("(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)"),
        "{compose}"
    );
    assert!(compose.contains("(\"CHARSET\" \"US-ASCII\")"), "{compose}");
}

// --- Les parties désignées (§6.4.5) ---------------------------------------

/// Rend le texte exact que `BODY[chemin]` servirait.
fn tranche(message: &[u8], chemin: &[u32], quoi: BodySpan) -> Option<std::string::String> {
    let mut balayeur = BodyScanner::new(&BORNES);
    balayeur.push(message);
    balayeur.finish();
    let (debut, fin) = balayeur.span(chemin, quoi)?;
    let debut = usize::try_from(debut).unwrap_or(usize::MAX);
    let fin = usize::try_from(fin).unwrap_or(usize::MAX);
    Some(
        std::string::String::from_utf8_lossy(message.get(debut..fin).unwrap_or_default())
            .into_owned(),
    )
}

/// UN MESSAGE SIMPLE N'A QU'UNE PARTIE, et c'est lui-même (§6.4.5).
#[test]
fn un_message_simple_n_a_qu_une_partie() {
    const NU: &[u8] = b"Subject: x\r\n\r\nbonjour\r\n";
    assert_eq!(
        tranche(NU, &[1], BodySpan::Content).as_deref(),
        Some("bonjour\r\n")
    );
    assert_eq!(
        tranche(NU, &[1], BodySpan::Mime).as_deref(),
        Some("Subject: x\r\n\r\n")
    );
    // Rien ne suit la seule partie d'un contenu simple.
    assert_eq!(tranche(NU, &[1, 1], BodySpan::Content), None);
    // Et il n'y a pas de partie deux.
    assert_eq!(tranche(NU, &[2], BodySpan::Content), None);
    // Ni de partie zéro : la grammaire dit `nz-number`, et le magasin le
    // vérifie aussi — une vérification faite ailleurs est une vérification
    // qu'on ne voit pas en lisant l'endroit qui en dépend.
    assert_eq!(tranche(NU, &[0], BodySpan::Content), None);
}

/// Les parties d'un `multipart` se numérotent dans l'ordre.
#[test]
fn les_parties_d_un_multipart_se_numerotent() {
    assert_eq!(
        tranche(DEUX_PARTIES, &[1], BodySpan::Content).as_deref(),
        Some("corps un")
    );
    assert_eq!(
        tranche(DEUX_PARTIES, &[2], BodySpan::Content).as_deref(),
        Some("QUJD")
    );
    assert_eq!(
        tranche(DEUX_PARTIES, &[1], BodySpan::Mime).as_deref(),
        Some("Content-Type: text/plain\r\n\r\n")
    );
    assert_eq!(tranche(DEUX_PARTIES, &[3], BodySpan::Content), None);
}

/// Les parties emboîtées se désignent par un chemin.
#[test]
fn les_parties_emboitees_se_designent_par_un_chemin() {
    assert_eq!(
        tranche(IMBRIQUE, &[1, 1], BodySpan::Content).as_deref(),
        Some("brut")
    );
    assert_eq!(
        tranche(IMBRIQUE, &[1, 2], BodySpan::Content).as_deref(),
        Some("<p>riche</p>")
    );
    assert_eq!(
        tranche(IMBRIQUE, &[2], BodySpan::Content).as_deref(),
        Some("PNG")
    );
    // La partie 1 est le `multipart` lui-même : son corps est tout ce qui tient
    // entre ses frontières.
    let interieur = tranche(IMBRIQUE, &[1], BodySpan::Content).expect("la partie 1 existe");
    assert!(interieur.starts_with("--B\r\n"), "{interieur}");
    assert!(interieur.ends_with("--B--"), "{interieur}");
    assert_eq!(tranche(IMBRIQUE, &[1, 3], BodySpan::Content), None);
}

const PORTEUR: &[u8] = b"Content-Type: multipart/mixed; boundary=A\r\n\r\n\
--A\r\n\
Content-Type: text/plain\r\n\r\n\
dehors\r\n\
--A\r\n\
Content-Type: message/rfc822\r\n\r\n\
From: a@b.test\r\n\
Subject: dedans\r\n\r\n\
le corps\r\n\
--A--\r\n";

/// UN `message/rfc822` NE COMPTE PAS POUR UN NIVEAU : `2.1` est la première
/// partie du message qu'il porte, et non une partie de lui.
#[test]
fn un_message_encapsule_ne_compte_pas_pour_un_niveau() {
    // La partie deux entière : le message porté, en-tête compris.
    assert_eq!(
        tranche(PORTEUR, &[2], BodySpan::Content).as_deref(),
        Some("From: a@b.test\r\nSubject: dedans\r\n\r\nle corps")
    );
    // Son en-tête, et son corps.
    assert_eq!(
        tranche(PORTEUR, &[2], BodySpan::Header).as_deref(),
        Some("From: a@b.test\r\nSubject: dedans\r\n\r\n")
    );
    assert_eq!(
        tranche(PORTEUR, &[2], BodySpan::Text).as_deref(),
        Some("le corps")
    );
    // Et sa seule partie, qui est le corps du message porté.
    assert_eq!(
        tranche(PORTEUR, &[2, 1], BodySpan::Content).as_deref(),
        Some("le corps")
    );
    // Ses propres lignes d'en-tête MIME, elles, appartiennent à la partie.
    assert_eq!(
        tranche(PORTEUR, &[2], BodySpan::Mime).as_deref(),
        Some("Content-Type: message/rfc822\r\n\r\n")
    );
}

/// `HEADER` ET `TEXT` NE VEULENT RIEN DIRE AILLEURS que sur un message
/// encapsulé : c'est SON en-tête et SON corps qu'ils désignent.
#[test]
fn l_en_tete_d_une_partie_qui_ne_porte_pas_de_message_n_existe_pas() {
    assert_eq!(tranche(PORTEUR, &[1], BodySpan::Header), None);
    assert_eq!(tranche(PORTEUR, &[1], BodySpan::Text), None);
    assert_eq!(tranche(DEUX_PARTIES, &[2], BodySpan::Text), None);
}

/// Un chemin vide désigne le message entier — c'est ce dont `BODY[]` est fait.
#[test]
fn un_chemin_vide_designe_le_message() {
    assert_eq!(
        tranche(b"Subject: x\r\n\r\ncorps\r\n", &[], BodySpan::Content).as_deref(),
        Some("corps\r\n")
    );
}

/// `HEADER` et `TEXT` ne veulent rien dire non plus sur un `multipart` : il ne
/// porte pas un message, il porte des parties.
#[test]
fn l_en_tete_d_un_multipart_n_existe_pas() {
    assert_eq!(tranche(IMBRIQUE, &[1], BodySpan::Header), None);
    assert_eq!(tranche(IMBRIQUE, &[1], BodySpan::Text), None);
}

/// Il n'y a pas de partie zéro, même dans un `multipart` : la grammaire dit
/// `nz-number`, et le magasin le vérifie à son tour — une vérification faite
/// ailleurs est une vérification qu'on ne voit pas en lisant l'endroit qui en
/// dépend.
#[test]
fn il_n_y_a_pas_de_partie_zero_dans_un_multipart() {
    assert_eq!(tranche(DEUX_PARTIES, &[0], BodySpan::Content), None);
    assert_eq!(tranche(DEUX_PARTIES, &[1, 0], BodySpan::Content), None);
}

/// Un `message/rfc822` qui n'a pas trouvé de place pour ce qu'il porte ne mène
/// nulle part : le chemin s'arrête là, plutôt que de désigner autre chose.
#[test]
fn un_message_encapsule_sans_place_ne_mene_nulle_part() {
    let sature = message_encapsule_sature();
    // La partie qui le porte existe ; ce qu'il contient, non.
    assert!(tranche(&sature, &[63], BodySpan::Content).is_some());
    assert_eq!(tranche(&sature, &[63, 1], BodySpan::Content), None);
    assert_eq!(tranche(&sature, &[63], BodySpan::Header), None);
}

// --- Ce que porte chaque partie (pour chercher dedans) ---------------------

/// Rend les parties qui portent un contenu.
fn portees(message: &[u8]) -> std::vec::Vec<(std::string::String, std::string::String, bool)> {
    let mut balayeur = BodyScanner::new(&BORNES);
    balayeur.push(message);
    balayeur.finish();
    (0..balayeur.part_count())
        .filter_map(|rang| balayeur.part(rang))
        .map(|partie| {
            let debut = usize::try_from(partie.start).unwrap_or(usize::MAX);
            let fin = usize::try_from(partie.end).unwrap_or(usize::MAX);
            (
                std::string::String::from_utf8_lossy(message.get(debut..fin).unwrap_or_default())
                    .into_owned(),
                std::string::String::from_utf8_lossy(partie.encoding).into_owned(),
                partie.text,
            )
        })
        .collect()
}

/// **LES `multipart` ET LES `message/rfc822` NE PORTENT RIEN EN PROPRE** : leur
/// contenu, ce sont leurs filles. Les rendre aussi ferait compter deux fois les
/// mêmes octets.
#[test]
fn seules_les_feuilles_portent_un_contenu() {
    let vues = portees(DEUX_PARTIES);
    assert_eq!(
        vues,
        std::vec![
            (
                std::string::String::from("corps un"),
                std::string::String::new(),
                true
            ),
            (
                std::string::String::from("QUJD"),
                std::string::String::from("base64"),
                false
            ),
        ]
    );
}

/// Un message encapsulé ne compte pas deux fois : seule sa feuille porte.
#[test]
fn un_message_encapsule_ne_compte_pas_deux_fois() {
    let vues = portees(PORTEUR);
    assert_eq!(vues.len(), 2, "{vues:?}");
    assert_eq!(
        vues.get(1).map(|vu| vu.0.clone()),
        Some(std::string::String::from("le corps"))
    );
}

/// Sans `Content-Type:`, c'est du texte (RFC 2045 §5.2).
#[test]
fn sans_type_c_est_du_texte() {
    let vues = portees(b"Subject: x\r\n\r\nbonjour\r\n");
    assert_eq!(vues.first().map(|vu| vu.2), Some(true));
    // Et un rang au-delà des parties ne rend rien.
    let mut balayeur = BodyScanner::new(&BORNES);
    balayeur.push(b"Subject: x\r\n\r\nbonjour\r\n");
    balayeur.finish();
    assert_eq!(balayeur.part(balayeur.part_count()), None);
}

/// **UN CHEMIN VIDE DÉSIGNE LE MESSAGE** — ce que `BINARY[]` demande — et un
/// chemin qui ne mène nulle part ne porte rien.
#[test]
fn un_chemin_designe_la_partie_qui_porte() {
    let mut balayeur = BodyScanner::new(&BORNES);
    balayeur.push(DEUX_PARTIES);
    balayeur.finish();
    // La première partie porte du texte, la seconde du base64.
    assert_eq!(
        balayeur.part_of(&[2]).map(|partie| partie.encoding),
        Some(&b"base64"[..])
    );
    assert_eq!(balayeur.part_of(&[1]).map(|partie| partie.text), Some(true));
    // Le message lui-même est un `multipart` : il ne porte rien en propre.
    assert!(balayeur.part_of(&[]).is_none());
    assert!(balayeur.part_of(&[9]).is_none());

    // Sur un message simple, le chemin vide désigne bien son corps.
    let mut nu = BodyScanner::new(&BORNES);
    nu.push(b"Subject: x\r\n\r\nbonjour\r\n");
    nu.finish();
    assert_eq!(nu.part_of(&[]).map(|partie| partie.text), Some(true));
}
