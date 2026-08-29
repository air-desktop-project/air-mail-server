//! Ce que le base64 de DKIM doit tenir.

use super::{decoder_base64, encoder_base64};
use crate::Error;

fn decode(base64: &str) -> std::vec::Vec<u8> {
    let mut sortie = std::vec![0_u8; base64.len()];
    let ecrits = decoder_base64(base64.as_bytes(), &mut sortie).expect("base64 lisible");
    sortie.truncate(ecrits);
    sortie
}

// ── LE BASE64, ET SA STRICTESSE ─────────────────────────────────────────────

#[test]
fn le_base64_se_decode() {
    let mut sortie = [0_u8; 8];
    for (encode, attendu) in [
        ("", &b""[..]),
        ("Zg==", b"f"),
        ("Zm8=", b"fo"),
        ("Zm9v", b"foo"),
        ("Zm9vYmFy", b"foobar"),
    ] {
        let ecrits = decoder_base64(encode.as_bytes(), &mut sortie).expect("lisible");
        assert_eq!(&sortie[..ecrits], attendu, "{encode}");
    }
    // Les blancs du pliage se traversent.
    let ecrits = decoder_base64(b"Zm9v\r\n YmFy", &mut sortie).expect("lisible");
    assert_eq!(&sortie[..ecrits], b"foobar");
}

#[test]
fn le_base64_n_admet_qu_une_ecriture_par_valeur() {
    // `Zg==` et `Zh==` décodent tous deux vers `f`. Accepter le second donnerait
    // plusieurs formes pour un même condensat — de quoi passer à côté d'une
    // comparaison, ou d'un journal.
    let mut sortie = [0_u8; 8];
    for mechant in [
        "Zh==",     // des bits de remplissage non nuls
        "Zg=",      // remplissage incomplet
        "Zg",       // remplissage absent
        "Zg===",    // remplissage de trop
        "Zg==Zg==", // deux valeurs collées
        "Zm9!",     // un octet qui n'est pas du base64
        "Z",        // un seul sextet : rien à en faire
    ] {
        assert_eq!(
            decoder_base64(mechant.as_bytes(), &mut sortie),
            Err(Error::MalformedBase64),
            "{mechant}"
        );
    }
}

#[test]
fn le_base64_refuse_plutot_que_de_tronquer() {
    let mut minuscule = [0_u8; 2];
    assert_eq!(
        decoder_base64(b"Zm9vYmFy", &mut minuscule),
        Err(Error::BufferTooSmall)
    );
}

// ── L'ÉCRITURE ──────────────────────────────────────────────────────────────

fn encode(valeur: &[u8], largeur: usize) -> std::string::String {
    let mut sortie = std::vec![0_u8; 512];
    let ecrit = encoder_base64(valeur, largeur, &mut sortie).expect("tient");
    std::string::String::from_utf8(ecrit.to_vec()).expect("ASCII")
}

#[test]
fn l_encodage_est_celui_de_tout_le_monde() {
    // Les vecteurs de la RFC 4648 §10.
    for (brut, attendu) in [
        (&b""[..], ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(encode(brut, 0), attendu, "{brut:?}");
    }
}

#[test]
fn ce_qu_on_ecrit_se_relit() {
    // LA PROPRIÉTÉ QUI COMPTE : notre vérificateur lira ce que notre signataire
    // écrit. Un aller-retour qui perdrait un octet ferait échouer toutes nos
    // propres signatures.
    for longueur in 0..64_usize {
        let brut: std::vec::Vec<u8> = (0..longueur)
            .map(|rang| u8::try_from(rang % 251).unwrap_or(0))
            .collect();
        let ecrit = encode(&brut, 0);
        assert_eq!(decode(&ecrit), brut, "{longueur} octets");
        // Et plié, ce qui est la forme qu'un en-tête portera.
        let plie = encode(&brut, 8);
        assert_eq!(decode(&plie), brut, "{longueur} octets, plié");
    }
}

#[test]
fn le_pliage_ecrit_un_repli_de_la_rfc_5322() {
    // `CRLF` suivi d'une espace : sans elle, la ligne suivante serait un nouvel
    // en-tête.
    let plie = encode(b"foobarfoobarfoobar", 4);
    assert_eq!(plie, "Zm9v\r\n YmFy\r\n Zm9v\r\n YmFy\r\n Zm9v\r\n YmFy");
    for suite in plie.split("\r\n").skip(1) {
        assert!(suite.starts_with(' '), "repli sans espace : {suite:?}");
    }
    // Largeur nulle : aucun repli.
    assert!(!encode(b"foobarfoobar", 0).contains('\r'));
}

#[test]
fn l_encodage_refuse_plutot_que_de_tronquer() {
    // TOUTES les tailles, pas quelques-unes : chaque écriture a sa borne — celle
    // du repli comme celle des lettres — et celles qu'on ne visite pas sont
    // celles qui déborderont un jour.
    let entier = encode(b"foobarfoobar", 4).len();
    for taille in 0..entier {
        let mut sortie = std::vec![0_u8; taille];
        assert_eq!(
            encoder_base64(b"foobarfoobar", 4, &mut sortie),
            Err(Error::BufferTooSmall),
            "taille {taille}"
        );
    }
    let mut juste = std::vec![0_u8; entier];
    assert!(encoder_base64(b"foobarfoobar", 4, &mut juste).is_ok());
}
