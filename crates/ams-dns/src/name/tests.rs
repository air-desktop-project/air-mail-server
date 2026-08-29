//! Ce que la lecture et l'écriture des noms doivent tenir.

use super::{MAX_NAME, Name, ecrire, lire, sauter};
use crate::Error;

/// Les octets d'un nom, tel qu'il s'écrit sur le fil.
fn fil(nom: &str) -> std::vec::Vec<u8> {
    let mut octets = std::vec::Vec::new();
    for etiquette in nom.split('.').filter(|e| !e.is_empty()) {
        octets.push(u8::try_from(etiquette.len()).expect("étiquette courte"));
        octets.extend_from_slice(etiquette.as_bytes());
    }
    octets.push(0);
    octets
}

fn texte(nom: &Name) -> std::string::String {
    std::string::String::from_utf8_lossy(nom.as_bytes()).into_owned()
}

#[test]
fn un_nom_simple_se_lit() {
    let message = fil("example.com");
    let (nom, apres) = lire(&message, 0).expect("nom lisible");
    assert_eq!(texte(&nom), "example.com");
    assert_eq!(apres, message.len());
    assert!(!nom.is_root());
}

#[test]
fn la_racine_est_un_nom_vide() {
    let (nom, apres) = lire(&[0], 0).expect("la racine se lit");
    assert!(nom.is_root());
    assert_eq!(nom.as_bytes(), b"");
    assert_eq!(apres, 1);
    assert_eq!(Name::root().as_bytes(), b"");
}

#[test]
fn un_pointeur_ramene_au_nom_deja_ecrit() {
    // « mx.example.com » où « example.com » est un pointeur vers l'octet 0.
    let mut message = fil("example.com");
    let retour = message.len();
    message.extend_from_slice(&[2, b'm', b'x', 0xC0, 0x00]);
    let (nom, apres) = lire(&message, retour).expect("nom lisible");
    assert_eq!(texte(&nom), "mx.example.com");
    // L'OFFSET RENDU EST CELUI DU FLUX, pas celui où la lecture s'est arrêtée :
    // un nom compressé finit sur ses deux octets de pointeur.
    assert_eq!(apres, message.len());
}

#[test]
fn deux_pointeurs_s_enchainent_et_le_premier_seul_compte() {
    // 0 : « example.com » ; 13 : « b » puis pointeur vers 0 ; 17 : pointeur
    // vers 13. La lecture depuis 17 traverse les deux.
    let mut message = fil("example.com");
    assert_eq!(message.len(), 13);
    message.extend_from_slice(&[1, b'b', 0xC0, 0x00]);
    message.extend_from_slice(&[0xC0, 13]);
    let (nom, apres) = lire(&message, 17).expect("nom lisible");
    assert_eq!(texte(&nom), "b.example.com");
    assert_eq!(apres, 19);
}

#[test]
fn un_pointeur_qui_ne_recule_pas_est_refuse() {
    // C'EST LA GARDE QUI EMPÊCHE LA BOUCLE INFINIE, et elle est structurelle :
    // les cibles décroissent, donc la lecture s'arrête. Sans elle, ces quatre
    // octets suffisent à faire tourner un serveur indéfiniment.
    assert_eq!(lire(&[0xC0, 0x00], 0), Err(Error::BadPointer));
    // Un pointeur vers lui-même, plus loin dans le message.
    let mut message = fil("example.com");
    let ici = message.len();
    message.extend_from_slice(&[0xC0, u8::try_from(ici).expect("court")]);
    assert_eq!(lire(&message, ici), Err(Error::BadPointer));
    // Et un cycle de deux, que le seul « ne pas pointer sur soi » laisserait
    // passer : après un saut vers 13, un pointeur vers 15 ne recule plus.
    let mut cycle = fil("example.com");
    cycle.extend_from_slice(&[0xC0, 15]);
    cycle.extend_from_slice(&[0xC0, 13]);
    assert_eq!(lire(&cycle, 15), Err(Error::BadPointer));
}

#[test]
fn un_message_qui_s_arrete_au_milieu_d_un_nom_est_refuse() {
    // La tête manque.
    assert_eq!(lire(&[], 0), Err(Error::Truncated));
    // L'étiquette annoncée déborde.
    assert_eq!(lire(&[5, b'a', b'b'], 0), Err(Error::Truncated));
    // Le second octet du pointeur manque.
    assert_eq!(lire(&[0, 0xC0], 1), Err(Error::Truncated));
}

#[test]
fn les_bits_reserves_sont_refuses() {
    // `01` et `10` : réservés en 1987, jamais attribués.
    assert_eq!(lire(&[0x40], 0), Err(Error::Malformed));
    assert_eq!(lire(&[0x80], 0), Err(Error::Malformed));
    assert_eq!(sauter(&[0x40], 0), Err(Error::Malformed));
}

#[test]
fn un_nom_plus_long_que_deux_cent_cinquante_cinq_est_refuse() {
    // Chaque étiquette fait 60 octets ; la cinquième déborde.
    let mut message = std::vec::Vec::new();
    for _ in 0..5 {
        message.push(60);
        message.extend_from_slice(&[b'a'; 60]);
    }
    message.push(0);
    assert_eq!(lire(&message, 0), Err(Error::NameTooLong));
}

#[test]
fn une_etiquette_de_plus_de_soixante_trois_octets_ne_peut_pas_s_ecrire() {
    let longue = "a".repeat(64);
    let mut sortie = [0_u8; MAX_NAME];
    assert_eq!(
        ecrire(&mut sortie, longue.as_bytes()),
        Err(Error::NameTooLong)
    );
}

#[test]
fn sauter_ne_reconstitue_rien_mais_rend_le_meme_offset() {
    let message = fil("mx.example.com");
    assert_eq!(sauter(&message, 0), Ok(message.len()));
    // Après un pointeur, le nom s'arrête : il n'y a rien à lire de plus.
    let mut compresse = fil("example.com");
    let retour = compresse.len();
    compresse.extend_from_slice(&[2, b'm', b'x', 0xC0, 0x00]);
    assert_eq!(sauter(&compresse, retour), Ok(compresse.len()));
}

#[test]
fn sauter_refuse_ce_qui_deborde() {
    // Une étiquette qui annonce plus que le message ne porte.
    assert_eq!(sauter(&[9, b'a'], 0), Err(Error::Truncated));
    // Un pointeur dont le second octet manque.
    assert_eq!(sauter(&[0xC0], 0), Err(Error::Truncated));
    // Plus rien à lire du tout.
    assert_eq!(sauter(&[], 0), Err(Error::Truncated));
}

#[test]
fn ecrire_rend_les_octets_du_fil() {
    let mut sortie = [0_u8; MAX_NAME];
    let ecrits = ecrire(&mut sortie, b"example.com").expect("nom écrit");
    assert_eq!(&sortie[..ecrits], &fil("example.com")[..]);

    // LE POINT FINAL EST TOLÉRÉ : un administrateur en écrit un une fois sur
    // deux, et refuser la forme absolue d'un nom serait pédant.
    let ecrits = ecrire(&mut sortie, b"example.com.").expect("nom écrit");
    assert_eq!(&sortie[..ecrits], &fil("example.com")[..]);

    // La racine : un seul octet nul.
    let ecrits = ecrire(&mut sortie, b"").expect("racine écrite");
    assert_eq!(&sortie[..ecrits], &[0]);
    let ecrits = ecrire(&mut sortie, b".").expect("racine écrite");
    assert_eq!(&sortie[..ecrits], &[0]);
}

#[test]
fn une_etiquette_vide_au_milieu_ne_designe_rien() {
    let mut sortie = [0_u8; MAX_NAME];
    assert_eq!(ecrire(&mut sortie, b"a..b"), Err(Error::EmptyLabel));
    assert_eq!(ecrire(&mut sortie, b".a"), Err(Error::EmptyLabel));
}

#[test]
fn ecrire_refuse_un_tampon_trop_petit() {
    // Il manque la place de l'étiquette…
    let mut court = [0_u8; 4];
    assert_eq!(
        ecrire(&mut court, b"example.com"),
        Err(Error::BufferTooSmall)
    );
    // … puis celle du seul octet nul final.
    let mut pile = [0_u8; 8];
    assert_eq!(ecrire(&mut pile, b"example"), Err(Error::BufferTooSmall));
    assert_eq!(ecrire(&mut [], b""), Err(Error::BufferTooSmall));
}

#[test]
fn un_nom_trop_long_pour_le_fil_est_refuse_a_l_ecriture() {
    // Quatre étiquettes de 63 octets : 4 × 64 + 1 = 257, au-dessus de 255.
    let long = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(63),
    ]
    .join(".");
    let mut sortie = [0_u8; 512];
    assert_eq!(
        ecrire(&mut sortie, long.as_bytes()),
        Err(Error::NameTooLong)
    );
}

#[test]
fn les_noms_se_comparent_sans_casse() {
    // RFC 4343. Certains serveurs répondent en majuscules exprès ; une
    // comparaison sensible ferait échouer une correspondance sur cette seule
    // fantaisie.
    let message = fil("Example.COM");
    let (haut, _) = lire(&message, 0).expect("nom lisible");
    let message = fil("example.com");
    let (bas, _) = lire(&message, 0).expect("nom lisible");
    assert_eq!(haut, bas);
    let message = fil("example.net");
    let (autre, _) = lire(&message, 0).expect("nom lisible");
    assert_ne!(haut, autre);
}

#[test]
fn un_nom_se_debogue_sans_ecrire_d_octets_de_controle() {
    // Un nom vient d'ailleurs : le journal d'un administrateur n'a pas à
    // recevoir des séquences d'échappement choisies par un tiers.
    let message = [3, b'a', 0x1B, b'c', 0];
    let (nom, _) = lire(&message, 0).expect("nom lisible");
    assert_eq!(std::format!("{nom:?}"), "Name(\"a?c\")");
    let message = fil("example.com");
    let (propre, _) = lire(&message, 0).expect("nom lisible");
    assert_eq!(std::format!("{propre:?}"), "Name(\"example.com\")");
    let copie = propre;
    assert_eq!(copie, propre);
}
