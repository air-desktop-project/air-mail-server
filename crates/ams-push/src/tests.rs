//! Le chiffrement de Web Push et le jeton VAPID, contre leurs RFC.

use std::string::String;
use std::vec::Vec;

use super::{
    AUTH_OCTETS, Error, HEADER_OCTETS, OVERHEAD_OCTETS, PLAINTEXT_MAX, PRIVATE_KEY_OCTETS,
    PUBLIC_KEY_OCTETS, SALT_OCTETS, encode_base64url, encrypt, vapid_public_key, write_vapid,
};

/// Décode du base64url, blancs ignorés — la forme des annexes de RFC.
fn lire(texte: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let valeur = |c: u8| -> u32 {
        let rang = ALPHABET
            .iter()
            .position(|signe| *signe == c)
            .expect("un signe base64url");
        u32::try_from(rang).expect("petit")
    };
    let signes: Vec<u8> = texte.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut octets = Vec::new();
    for bloc in signes.chunks(4) {
        let mut n = 0_u32;
        for (c, decalage) in bloc.iter().zip([18_u32, 12, 6, 0]) {
            n |= valeur(*c) << decalage;
        }
        for decalage in [16_u32, 8, 0]
            .into_iter()
            .take(bloc.len().saturating_sub(1))
        {
            octets.push(u8::try_from((n >> decalage) & 0xff).expect("un octet"));
        }
    }
    octets
}

fn fixe<const N: usize>(octets: &[u8]) -> [u8; N] {
    octets.try_into().expect("la bonne longueur")
}

/// **LE VECTEUR DE L'ANNEXE A DE LA RFC 8291, OCTET POUR OCTET** : même clef
/// éphémère, même sel, même navigateur — même message.
#[test]
fn le_vecteur_de_la_rfc_8291_se_reproduit() {
    let clair = lire("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24");
    let as_private =
        fixe::<PRIVATE_KEY_OCTETS>(&lire("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"));
    let ua_public = fixe::<PUBLIC_KEY_OCTETS>(&lire(
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    ));
    let sel = fixe::<SALT_OCTETS>(&lire("DGv6ra1nlYgDCS1FRnbzlw"));
    let auth = fixe::<AUTH_OCTETS>(&lire("BTBZMqHH6r4Tts7J_aSIgg"));
    // L'en-tête et le chiffré, DÉCODÉS À PART PUIS MIS BOUT À BOUT : quatre-
    // vingt-six octets ne tombent pas sur une frontière de base64, et coller les
    // deux textes ferait un autre message.
    let mut attendu = lire(
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z 9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml
         mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz AC8wEqKK6PBru3jl7A8",
    );
    attendu.extend(lire(
        "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs
         bI_0LpXMuGvnzQ",
    ));
    let mut out = [0_u8; 256];
    let ecrits =
        encrypt(&clair, &ua_public, &auth, &as_private, &sel, &mut out).expect("chiffrable");
    assert_eq!(&out[..ecrits], attendu.as_slice());
    assert_eq!(ecrits, clair.len() + OVERHEAD_OCTETS);
    assert_eq!(&out[..HEADER_OCTETS][21..], lire(
        "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
    ).as_slice());
}

/// Ce qui ne se chiffre pas se dit.
#[test]
fn ce_qui_ne_se_chiffre_pas_se_dit() {
    let bonne = vapid_public_key(&[7; 32]).expect("une clef");
    let mut out = [0_u8; 4096];
    assert_eq!(
        encrypt(
            &[0; PLAINTEXT_MAX + 1],
            &bonne,
            &[0; 16],
            &[7; 32],
            &[0; 16],
            &mut out
        ),
        Err(Error::TooLong)
    );
    assert_eq!(
        encrypt(b"x", &bonne, &[0; 16], &[7; 32], &[0; 16], &mut [0; 10]),
        Err(Error::BufferTooSmall)
    );
    let mut hors = bonne;
    hors[64] ^= 1;
    assert_eq!(
        encrypt(b"x", &hors, &[0; 16], &[7; 32], &[0; 16], &mut out),
        Err(Error::BadPublicKey)
    );
    assert_eq!(
        encrypt(b"x", &bonne, &[0; 16], &[0; 32], &[0; 16], &mut out),
        Err(Error::BadPrivateKey)
    );
    // Le plus long clair admis tient dans un enregistrement de 4 096 octets.
    assert_eq!(
        encrypt(
            &[0; PLAINTEXT_MAX],
            &bonne,
            &[0; 16],
            &[7; 32],
            &[0; 16],
            &mut out
        ),
        Ok(4096)
    );
}

/// Un jeton VAPID : trois morceaux, un en-tête ES256, des revendications
/// lisibles, une signature que la clef publique annoncée vérifie.
#[test]
fn un_jeton_vapid_se_verifie() {
    use p256::ecdsa::signature::Verifier as _;
    let cle = [9_u8; 32];
    let mut out = [0_u8; 1024];
    let ecrits = write_vapid(
        "https://fcm.googleapis.com",
        1_790_000_000,
        "mailto:postmaster@narro.ch",
        &cle,
        &mut out,
    )
    .expect("écrivable");
    let valeur = String::from_utf8(out[..ecrits].to_vec()).expect("ASCII");
    let (jeton, clef) = valeur
        .strip_prefix("vapid t=")
        .and_then(|reste| reste.split_once(", k="))
        .expect("la forme de §3");
    let publique = vapid_public_key(&cle).expect("une clef");
    assert_eq!(lire(clef), publique.to_vec());
    let morceaux: Vec<&str> = jeton.split('.').collect();
    assert_eq!(morceaux.len(), 3);
    assert_eq!(
        lire(morceaux[0]),
        br#"{"typ":"JWT","alg":"ES256"}"#.to_vec()
    );
    assert_eq!(
        String::from_utf8(lire(morceaux[1])).expect("UTF-8"),
        r#"{"aud":"https://fcm.googleapis.com","exp":1790000000,"sub":"mailto:postmaster@narro.ch"}"#
    );
    let verifiante = p256::ecdsa::VerifyingKey::from_sec1_bytes(&publique).expect("un point");
    let signature = p256::ecdsa::Signature::from_slice(&lire(morceaux[2])).expect("64 octets");
    let signe = std::format!("{}.{}", morceaux[0], morceaux[1]);
    assert!(verifiante.verify(signe.as_bytes(), &signature).is_ok());
    // Une expiration nulle s'écrit aussi.
    assert!(write_vapid("https://a.b", 0, "https://narro.ch", &cle, &mut out).is_ok());
}

/// Des revendications hors forme ne se signent pas.
#[test]
fn des_revendications_douteuses_se_refusent() {
    let mut out = [0_u8; 1024];
    let long = "x".repeat(256);
    for (audience, contact) in [
        ("http://a.b", "mailto:x@y"),
        ("https://", "mailto:x@y"),
        ("https://a.b/chemin", "mailto:x@y"),
        ("https://a\".b", "mailto:x@y"),
        ("https://a.b", "tel:+33"),
        ("https://a.b", "mailto:x\\y"),
        ("https://a.b", "mailto:\u{e9}"),
        ("https://a.b", ""),
        ("https://a.b", long.as_str()),
    ] {
        assert_eq!(
            write_vapid(audience, 1, contact, &[9; 32], &mut out),
            Err(Error::BadClaim),
            "{audience} {contact}"
        );
    }
    assert_eq!(
        write_vapid("https://a.b", 1, "mailto:x@y", &[0; 32], &mut out),
        Err(Error::BadPrivateKey)
    );
    assert_eq!(vapid_public_key(&[0; 32]), Err(Error::BadPrivateKey));
    for taille in [0, 8, 20, 200] {
        assert_eq!(
            write_vapid(
                "https://a.b",
                1,
                "mailto:x@y",
                &[9; 32],
                &mut [0; 1024][..taille]
            ),
            Err(Error::BufferTooSmall),
            "{taille}"
        );
    }
}

/// Le base64url sans remplissage : un, deux et trois octets par groupe.
#[test]
fn le_base64url_s_ecrit_sans_remplissage() {
    for (octets, attendu) in [
        (&b""[..], ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"\xfb\xff", "-_8"),
    ] {
        let mut out = [0_u8; 8];
        let n = encode_base64url(octets, &mut out).expect("tient");
        assert_eq!(&out[..n], attendu.as_bytes());
    }
    assert_eq!(
        encode_base64url(b"foo", &mut [0; 3]),
        Err(Error::BufferTooSmall)
    );
}
