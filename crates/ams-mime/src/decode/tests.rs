//! Ce que le décodage rend.

use super::{decode_chunk, decode_encoded_words, decode_transfer, decoded_max};
use crate::Error;

/// Décode une valeur d'en-tête, ou panique.
fn mots(valeur: &[u8]) -> std::string::String {
    let mut sortie = std::vec![0_u8; decoded_max(valeur.len())];
    let ecrits = decode_encoded_words(valeur, &mut sortie).expect("décodable");
    std::string::String::from_utf8_lossy(sortie.get(..ecrits).unwrap_or_default()).into_owned()
}

/// Décode un corps, ou panique.
fn corps(encodage: &[u8], texte: &[u8]) -> std::string::String {
    let mut sortie = std::vec![0_u8; decoded_max(texte.len()).max(1)];
    let ecrits = decode_transfer(encodage, texte, &mut sortie).expect("décodable");
    std::string::String::from_utf8_lossy(sortie.get(..ecrits).unwrap_or_default()).into_owned()
}

// --- Les mots encodés (RFC 2047) -------------------------------------------

/// Les deux encodages se lisent.
#[test]
fn les_deux_encodages_se_lisent() {
    assert_eq!(mots(b"=?utf-8?B?ZmFjdHVyZQ==?="), "facture");
    assert_eq!(mots(b"=?utf-8?Q?facture?="), "facture");
    // Le `_` d'un mot encodé vaut une espace, et c'est ce qu'on oublie.
    assert_eq!(mots(b"=?utf-8?Q?la_facture?="), "la facture");
    assert_eq!(mots(b"=?utf-8?Q?=C3=A9t=C3=A9?="), "été");
    // La casse de l'encodage ne compte pas.
    assert_eq!(mots(b"=?utf-8?b?ZmFjdHVyZQ==?="), "facture");
}

/// `iso-8859-1` se convertit en UTF-8, sans table.
#[test]
fn le_latin1_se_convertit() {
    assert_eq!(mots(b"=?iso-8859-1?Q?=E9t=E9?="), "été");
    assert_eq!(mots(b"=?ISO-8859-1?B?6XTp?="), "été");
    assert_eq!(mots(b"=?latin1?Q?caf=E9?="), "café");
}

/// **LE BLANC ENTRE DEUX MOTS ENCODÉS DISPARAÎT** (§6.2) : il ne sert qu'à les
/// séparer, et le garder couperait en deux un texte que l'expéditeur a dû
/// découper pour tenir dans une ligne.
#[test]
fn le_blanc_entre_deux_mots_encodes_disparait() {
    assert_eq!(mots(b"=?utf-8?Q?fac?= =?utf-8?Q?ture?="), "facture");
    // Un pli entre les deux ne change rien : c'est du blanc.
    assert_eq!(mots(b"=?utf-8?Q?fac?=\r\n =?utf-8?Q?ture?="), "facture");
    // Mais le blanc autour du texte ordinaire, lui, reste.
    assert_eq!(
        mots(b"la =?utf-8?Q?facture?= de mars"),
        "la facture de mars"
    );
}

/// **CE QU'ON NE SAIT PAS LIRE RESTE TEL QUEL.** Mieux vaut ne pas trouver que
/// de trouver autre chose.
#[test]
fn un_jeu_inconnu_reste_tel_quel() {
    assert_eq!(
        mots(b"=?koi8-r?B?ZmFjdHVyZQ==?="),
        "=?koi8-r?B?ZmFjdHVyZQ==?="
    );
}

/// Un mot mal formé est du texte ordinaire (§6.3), et non une erreur.
#[test]
fn un_mot_mal_forme_est_du_texte() {
    for brut in [
        &b"=?utf-8?X?facture?="[..],
        b"=?utf-8?B?facture",
        b"=?utf-8facture?=",
        // Un jeu suivi de rien : il n'y a pas d'encodage à lire.
        b"=?utf-8?",
        b"=?",
        b"=",
        // Un mot encodé ne porte ni blanc ni fin de ligne (§2).
        b"=?utf-8?Q?la facture?=",
    ] {
        assert_eq!(
            mots(brut),
            std::string::String::from_utf8_lossy(brut),
            "{brut:?}"
        );
    }
}

/// La langue qui suit le jeu (RFC 2231 §5) ne change pas le décodage.
#[test]
fn la_langue_ne_change_pas_le_decodage() {
    assert_eq!(mots(b"=?utf-8*fr?Q?facture?="), "facture");
}

/// Ce qui n'est pas encodé traverse sans changer.
#[test]
fn ce_qui_n_est_pas_encode_traverse() {
    assert_eq!(mots(b"une facture ordinaire"), "une facture ordinaire");
    assert_eq!(mots(b""), "");
    // Le blanc de fin reste : il appartient à la valeur.
    assert_eq!(mots(b"facture  "), "facture  ");
}

// --- Les encodages de transfert (RFC 2045 §6) -------------------------------

/// Le base64 se lit, pliage compris.
#[test]
fn le_base64_se_lit() {
    assert_eq!(corps(b"base64", b"bGEgZmFjdHVyZQ=="), "la facture");
    assert_eq!(corps(b"BASE64", b"bGEgZmFj\r\ndHVyZQ=="), "la facture");
    // `+` et `/` sont les deux derniers caractères de l'alphabet, et ceux qu'un
    // vecteur d'épreuve trop poli ne porte jamais.
    assert_eq!(corps(b"base64", b"Pz8/Pj4+"), "???>>>");
}

/// Le quoted-printable se lit, coupures molles comprises.
#[test]
fn le_quoted_printable_se_lit() {
    assert_eq!(corps(b"quoted-printable", b"la facture"), "la facture");
    assert_eq!(corps(b"quoted-printable", b"caf=C3=A9"), "café");
    // **LA COUPURE MOLLE DISPARAÎT** : l'oublier ferait apparaître des fins de
    // ligne au milieu des mots.
    assert_eq!(corps(b"quoted-printable", b"fac=\r\nture"), "facture");
    assert_eq!(corps(b"quoted-printable", b"fac=\nture"), "facture");
    // Un `=` qui n'échappe rien reste un `=`.
    assert_eq!(corps(b"quoted-printable", b"a=zb"), "a=zb");
    assert_eq!(corps(b"quoted-printable", b"a="), "a=");
    // Et le `_` n'y vaut PAS une espace : c'est la différence avec un mot
    // encodé, et celle qu'on oublie.
    assert_eq!(corps(b"quoted-printable", b"la_facture"), "la_facture");
}

/// Un encodage qu'on ne connaît pas laisse le corps tel quel.
#[test]
fn un_encodage_inconnu_laisse_le_corps() {
    for encodage in [&b"7bit"[..], b"8bit", b"binary", b"", b"x-uuencode"] {
        assert_eq!(corps(encodage, b"la facture"), "la facture", "{encodage:?}");
    }
}

/// Un tampon trop court le dit, pour l'un comme pour l'autre.
#[test]
fn un_tampon_trop_court_le_dit() {
    let mut vide = [0_u8; 0];
    assert_eq!(
        decode_encoded_words(b"a", &mut vide),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        decode_encoded_words(b"=?koi8-r?B?YQ==?=", &mut vide),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        decode_encoded_words(b" a", &mut vide),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        decode_encoded_words(b" ", &mut vide),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        decode_transfer(b"base64", b"YQ==", &mut vide),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        decode_transfer(b"quoted-printable", b"a", &mut vide),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        decode_transfer(b"7bit", b"a", &mut vide),
        Err(Error::BufferTooSmall)
    );
    // Ce qu'on recopie sans savoir le lire s'écrit en six morceaux, et chacun
    // peut manquer de place. Le balayage les éprouve tous.
    for place in 0..17_usize {
        let mut petit = std::vec![0_u8; place];
        assert_eq!(
            decode_encoded_words(b"=?koi8-r?B?YQ==?=", &mut petit),
            Err(Error::BufferTooSmall),
            "avec {place} octets"
        );
    }
    // Une espace tirée d'un `_` a besoin de place, elle aussi.
    assert_eq!(
        decode_encoded_words(b"=?utf-8?Q?_?=", &mut vide),
        Err(Error::BufferTooSmall)
    );
    // Un mot encodé en `iso-8859-1` grandit : `decoded_max` le majore.
    let mut juste = [0_u8; 1];
    assert_eq!(
        decode_encoded_words(b"=?iso-8859-1?Q?=E9?=", &mut juste),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(decoded_max(3), 6);
}

// --- Le décodage reprenable -------------------------------------------------

/// Décode tout un contenu, morceau par morceau, comme un magasin le ferait.
fn reprendre(encodage: &[u8], brut: &[u8], place: usize) -> std::string::String {
    let mut sortie = std::vec![0_u8; place.max(1)];
    let mut rendu = std::vec::Vec::new();
    let mut vu = 0_usize;
    while vu < brut.len() {
        let reste = brut.get(vu..).unwrap_or_default();
        let (lus, ecrits) = decode_chunk(encodage, reste, true, &mut sortie).expect("décodable");
        if lus == 0 {
            break;
        }
        rendu.extend_from_slice(sortie.get(..ecrits).unwrap_or_default());
        vu = vu.saturating_add(lus);
    }
    std::string::String::from_utf8_lossy(&rendu).into_owned()
}

/// **LE DÉCOUPAGE NE CHANGE PAS LE RÉSULTAT**, quelle que soit la place offerte.
/// C'est la propriété qui permet de décoder une pièce jointe sans la tenir en
/// mémoire.
#[test]
fn le_decoupage_ne_change_pas_le_resultat() {
    const BASE64: &[u8] = b"bGEgZmFjdHVyZSBkZSBtYXJz\r\nIGV0IGQnYXZyaWw=";
    const QP: &[u8] = b"la fac=\r\nture de mars, caf=C3=A9 compris.";
    for place in [3_usize, 4, 5, 7, 16, 64, 4096] {
        assert_eq!(
            reprendre(b"base64", BASE64, place),
            "la facture de mars et d'avril",
            "base64 par {place}"
        );
        assert_eq!(
            reprendre(b"quoted-printable", QP, place),
            "la facture de mars, café compris.",
            "quoted-printable par {place}"
        );
        assert_eq!(
            reprendre(b"7bit", b"tel quel", place),
            "tel quel",
            "7bit par {place}"
        );
    }
}

/// **ON S'ARRÊTE LÀ OÙ IL N'Y A RIEN À RETENIR** : un groupe complet de base64,
/// et jamais au milieu.
#[test]
fn le_base64_s_arrete_sur_un_groupe_entier() {
    let mut sortie = [0_u8; 4];
    // Quatre octets de place : un seul groupe tient (trois octets), le second
    // non — et l'on s'arrête donc après le premier.
    let (lus, ecrits) =
        decode_chunk(b"base64", b"YWJjZGVm", false, &mut sortie).expect("décodable");
    assert_eq!((lus, ecrits), (4, 3));
    assert_eq!(sortie.get(..ecrits), Some(&b"abc"[..]));

    // Moins de trois octets de place : rien n'avance, et le dire évite à
    // l'appelant de tourner en rond.
    let mut minuscule = [0_u8; 2];
    assert_eq!(
        decode_chunk(b"base64", b"YWJjZGVm", false, &mut minuscule).expect("décodable"),
        (0, 0)
    );
}

/// **LE BLANC AVANCE LE CURSEUR**, tant qu'aucun groupe n'est entamé : sans
/// cela, une fenêtre entière de pliage ne consommerait rien.
#[test]
fn le_blanc_avance_le_curseur() {
    let mut sortie = [0_u8; 64];
    let (lus, ecrits) =
        decode_chunk(b"base64", b"\r\n\r\n  ", false, &mut sortie).expect("décodable");
    assert_eq!((lus, ecrits), (6, 0));
    // Un groupe entamé, lui, retient : ses trois premiers caractères ne sont pas
    // consommés tant que le quatrième n'est pas venu.
    let (lus, ecrits) = decode_chunk(b"base64", b"YWJ", false, &mut sortie).expect("décodable");
    assert_eq!((lus, ecrits), (0, 0));
}

/// **UN ÉCHAPPEMENT À CHEVAL SUR DEUX MORCEAUX NE SE DEVINE PAS** : on s'arrête
/// avant lui, et le morceau suivant le lira entier.
#[test]
fn un_echappement_coupe_arrete_le_morceau() {
    let mut sortie = [0_u8; 64];
    // `=C` seul : la suite dira si c'est `=C3` ou autre chose.
    let (lus, ecrits) =
        decode_chunk(b"quoted-printable", b"caf=C", false, &mut sortie).expect("ok");
    assert_eq!((lus, ecrits), (3, 3));
    assert_eq!(sortie.get(..ecrits), Some(&b"caf"[..]));
    // Un `=` en toute fin : même chose.
    let (lus, _) = decode_chunk(b"quoted-printable", b"caf=", false, &mut sortie).expect("ok");
    assert_eq!(lus, 3);
    // Mais un `=` suivi d'un `\n` est une coupure molle, qu'on sait lire.
    let (lus, ecrits) =
        decode_chunk(b"quoted-printable", b"caf=\n", false, &mut sortie).expect("ok");
    assert_eq!((lus, ecrits), (5, 3));
    // La place qui manque arrête aussi, mais à un rang lisible.
    let mut juste = [0_u8; 2];
    let (lus, ecrits) = decode_chunk(b"quoted-printable", b"cafe", false, &mut juste).expect("ok");
    assert_eq!((lus, ecrits), (2, 2));
}

/// Les encodages transparents rendent les octets tels quels, bornés par la place.
#[test]
fn les_encodages_transparents_rendent_les_octets() {
    let mut sortie = [0_u8; 3];
    for encodage in [&b""[..], b"7bit", b"8BIT", b"binary"] {
        assert_eq!(
            decode_chunk(encodage, b"abcdef", false, &mut sortie).expect("décodable"),
            (3, 3),
            "{encodage:?}"
        );
        assert_eq!(sortie, *b"abc");
    }
}

/// **UN ENCODAGE QU'ON NE SAIT PAS DÉFAIRE LE DIT** : §6.4.5 veut qu'un serveur
/// le dise plutôt que de rendre les octets encodés en les faisant passer pour le
/// contenu.
#[test]
fn un_encodage_inconnu_se_refuse() {
    let mut sortie = [0_u8; 64];
    for encodage in [&b"x-uuencode"[..], b"uuencode", b"base85"] {
        assert_eq!(
            decode_chunk(encodage, b"abc", true, &mut sortie),
            Err(Error::UnknownEncoding),
            "{encodage:?}"
        );
    }
    // Et l'erreur se dit.
    assert!(!std::format!("{}", Error::UnknownEncoding).is_empty());
    assert!(std::format!("{:?}", Error::UnknownEncoding).contains("UnknownEncoding"));
}
