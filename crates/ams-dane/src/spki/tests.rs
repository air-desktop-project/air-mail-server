//! Ce qu'on retrouve dans un certificat, et ce qu'on refuse d'y chercher.

use super::subject_public_key_info;

/// Un vrai certificat, fabriqué une fois — voir `vecteurs/README.md`.
const FEUILLE: &[u8] = include_bytes!("../../vecteurs/leaf.der");
const AUTORITE: &[u8] = include_bytes!("../../vecteurs/ca.der");

#[test]
fn la_clef_se_retrouve_dans_un_vrai_certificat() {
    for certificat in [FEUILLE, AUTORITE] {
        let clef = subject_public_key_info(certificat).expect("une clef");
        // **LA TRANCHE PORTE SON PROPRE EN-TÊTE** : c'est une `SEQUENCE`, et
        // c'est elle qui se hache. Rendre seulement son contenu donnerait une
        // empreinte qui ne correspondrait à aucun `TLSA` du monde.
        assert_eq!(clef.first(), Some(&0x30));
        // Une clé ECDSA P-256 : l'identifiant d'algorithme et le point, en tout
        // quelques dizaines d'octets.
        let combien = clef.len();
        assert!((60..120).contains(&combien), "{combien} octets");
        // Et elle est bien DANS le certificat, à sa place.
        assert!(
            certificat
                .windows(clef.len())
                .any(|fenetre| fenetre == clef),
            "la tranche ne vient pas du certificat"
        );
    }
}

/// **DEUX CERTIFICATS DIFFÉRENTS N'ONT PAS LA MÊME CLEF.**
///
/// Un extracteur qui rendrait toujours le même morceau — le premier venu, par
/// exemple — passerait le test précédent et ferait pourtant correspondre
/// n'importe quel certificat à n'importe quel `TLSA`.
#[test]
fn deux_certificats_donnent_deux_clefs() {
    let feuille = subject_public_key_info(FEUILLE).expect("une clef");
    let autorite = subject_public_key_info(AUTORITE).expect("une clef");
    assert_ne!(feuille, autorite);
}

#[test]
fn ce_qui_n_est_pas_un_certificat_ne_rend_rien() {
    for mauvais in [
        &b""[..],
        b"\x30",                         // une étiquette sans longueur
        b"\x30\x05",                     // une longueur sans contenu
        b"\x02\x01\x00",                 // un INTEGER, pas une SEQUENCE
        b"\x30\x03\x02\x01\x00",         // une SEQUENCE dont le contenu n'en est pas une
        b"\x30\x05\x30\x03\x02\x01\x00", // une SEQUENCE trop courte pour six champs
    ] {
        assert_eq!(
            subject_public_key_info(mauvais),
            None,
            "{mauvais:?} aurait dû être refusé"
        );
    }
}

/// **LE CERTIFICAT TRONQUÉ NE REND JAMAIS DE TRANCHE.**
///
/// Un décodeur qui lirait au-delà de ce qu'on lui donne rendrait une empreinte
/// calculée sur de la mémoire voisine.
#[test]
fn un_certificat_tronque_ne_rend_rien() {
    //
    // **AUCUNE TRONCATURE NE REND QUOI QUE CE SOIT**, et c'est plus fort que « ce
    // qu'elle rend tient dans ce qu'on a lu » : la longueur que le certificat
    // annonce dépasse toujours ce qui reste, et le `get` final refuse.
    for combien in 1..FEUILLE.len() {
        let tronque = FEUILLE.get(..combien).expect("tranche");
        assert_eq!(
            subject_public_key_info(tronque),
            None,
            "une troncature à {combien} octets a rendu une clef"
        );
    }
    // Le certificat entier, lui, en rend une.
    assert!(subject_public_key_info(FEUILLE).is_some());
    // Et un certificat amputé de sa clef ne rend rien du tout : la clé se trouve
    // après plus de la moitié du `tbsCertificate`.
    assert_eq!(subject_public_key_info(&FEUILLE[..40]), None);
}

/// **LE DER N'ADMET QU'UNE ÉCRITURE PAR LONGUEUR** (§10.1 de X.690).
///
/// Deux écritures d'une même valeur donneraient deux tranches pour un même
/// certificat, donc deux empreintes — et un `TLSA` satisfait par l'une et pas
/// par l'autre.
#[test]
fn les_longueurs_non_canoniques_sont_refusees() {
    for mauvais in [
        // Longueur indéfinie : `0x80`.
        &b"\x30\x80\x30\x00\x00\x00"[..],
        // Longue forme sur zéro octet.
        b"\x30\x80",
        // Longue forme dont le premier octet est nul.
        b"\x30\x82\x00\x05\x30\x03\x02\x01\x00",
        // Longue forme pour une valeur qui tiendrait dans la courte.
        b"\x30\x81\x05\x30\x03\x02\x01\x00",
        // Longue forme sur plus de quatre octets.
        b"\x30\x85\x01\x02\x03\x04\x05",
    ] {
        assert_eq!(
            subject_public_key_info(mauvais),
            None,
            "{mauvais:?} aurait dû être refusé"
        );
    }
}

/// **LA VERSION EST FACULTATIVE**, et son absence décale tout d'un cran.
///
/// On la reconnaît à son étiquette contextuelle plutôt que de supposer une
/// version : un certificat v1 n'en porte pas, et compter les champs à sa place
/// rendrait alors la mauvaise tranche.
#[test]
fn un_certificat_sans_version_se_lit_aussi() {
    // Un `tbsCertificate` minimal SANS `[0] version` : six éléments, dont le
    // sixième est la clef qu'on cherche.
    let mut tbs = std::vec::Vec::new();
    for _ in 0..5_u8 {
        tbs.extend_from_slice(&[0x02, 0x01, 0x00]); // INTEGER 0
    }
    let clef = [0x30_u8, 0x03, 0x02, 0x01, 0x7f];
    tbs.extend_from_slice(&clef);

    let mut certificat = std::vec![
        0x30,
        u8::try_from(tbs.len() + 2).expect("court"),
        0x30,
        u8::try_from(tbs.len()).expect("court"),
    ];
    certificat.extend_from_slice(&tbs);

    assert_eq!(subject_public_key_info(&certificat), Some(&clef[..]));
}

/// Et le sixième élément doit être une `SEQUENCE` : autre chose n'est pas une
/// clef, et le hacher donnerait une empreinte de rien.
#[test]
fn un_sixieme_element_qui_n_est_pas_une_sequence_est_refuse() {
    let mut tbs = std::vec::Vec::new();
    for _ in 0..6_u8 {
        tbs.extend_from_slice(&[0x02, 0x01, 0x00]);
    }
    let mut certificat = std::vec![
        0x30,
        u8::try_from(tbs.len() + 2).expect("court"),
        0x30,
        u8::try_from(tbs.len()).expect("court"),
    ];
    certificat.extend_from_slice(&tbs);

    assert_eq!(subject_public_key_info(&certificat), None);
}

/// **CHAQUE `?` DU PARCOURS SE FRANCHIT.**
///
/// Un décodeur dont certains refus ne sont jamais éprouvés est un décodeur dont
/// on ne sait pas ce qu'il fait de ce qu'il n'a jamais vu.
#[test]
fn chaque_refus_du_parcours_s_atteint() {
    for (quoi, octets) in [
        // Le `tbsCertificate` n'est pas un élément : une étiquette sans longueur.
        ("tbs tronqué", &b"\x30\x01\x30"[..]),
        // Le `tbsCertificate` est vide : pas même un premier champ.
        ("tbs vide", b"\x30\x02\x30\x00"),
        // Un `tbsCertificate` qui s'arrête avant le sixième champ.
        ("champs manquants", b"\x30\x07\x30\x05\x02\x01\x00\x02\x01"),
        // Cinq champs bien formés, et RIEN à la place du sixième.
        (
            "sixième champ absent",
            b"\x30\x11\x30\x0f\x02\x01\x00\x02\x01\x00\x02\x01\x00\x02\x01\x00\x02\x01\x00",
        ),
        // Une longueur sur huit octets à `0xff` : elle déborde l'`usize`.
        // Une longueur sur plus de quatre octets : plus de quatre gibioctets.
        ("longueur démesurée", b"\x30\x85\x01\x00\x00\x00\x00"),
        // Quatre octets à `0xff` : la longueur est lisible, mais rien ne suit.
        ("longueur maximale", b"\x30\x84\xff\xff\xff\xff"),
        // Une longueur qui dépasse ce qu'on a lu.
        ("longueur trop grande", b"\x30\x82\x01\x00\x30\x03"),
    ] {
        assert_eq!(
            subject_public_key_info(octets),
            None,
            "{quoi} aurait dû être refusé"
        );
    }
}

/// **UN `tbsCertificate` AVEC VERSION SE LIT AUSSI**, et la version se saute.
#[test]
fn un_certificat_avec_version_saute_la_version() {
    // `[0] { INTEGER 2 }`, puis les cinq champs, puis la clef.
    let mut tbs = std::vec![0xa0_u8, 0x03, 0x02, 0x01, 0x02];
    for _ in 0..5_u8 {
        tbs.extend_from_slice(&[0x02, 0x01, 0x00]);
    }
    let clef = [0x30_u8, 0x03, 0x02, 0x01, 0x7f];
    tbs.extend_from_slice(&clef);

    let mut certificat = std::vec![
        0x30,
        u8::try_from(tbs.len() + 2).expect("court"),
        0x30,
        u8::try_from(tbs.len()).expect("court"),
    ];
    certificat.extend_from_slice(&tbs);
    assert_eq!(subject_public_key_info(&certificat), Some(&clef[..]));
}
