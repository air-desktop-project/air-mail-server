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

// ── APNs ────────────────────────────────────────────────────────────────────

use super::{decode_p8, write_apns_token};

/// Une clef `.p8` d'ESSAI, fabriquée par `openssl pkcs8 -topk8` comme celles
/// qu'Apple livre — et son scalaire, tel qu'`openssl ec -text` le lit. Elle ne
/// sert nulle part ailleurs.
const P8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvbUYvu4iOcQREByj
YQmsWz/cMxaW+fDpfMxgAmlBXbKhRANCAASUJeciHAlEyyIZxIt5RYgS8mhuLF4Q
xgwD6RstvOSWGz2m1fqnUVKuiXCBeM1sUwHqlUBiUa+VvK51hxhKtQZR
-----END PRIVATE KEY-----
";
const SCALAIRE: [u8; 32] = [
    0xbd, 0xb5, 0x18, 0xbe, 0xee, 0x22, 0x39, 0xc4, 0x11, 0x10, 0x1c, 0xa3, 0x61, 0x09, 0xac, 0x5b,
    0x3f, 0xdc, 0x33, 0x16, 0x96, 0xf9, 0xf0, 0xe9, 0x7c, 0xcc, 0x60, 0x02, 0x69, 0x41, 0x5d, 0xb2,
];

/// **LA CLEF QU'OPENSSL ÉCRIT SE LIT À L'OCTET** — la forme exacte d'Apple.
#[test]
fn une_clef_p8_se_lit() {
    assert_eq!(decode_p8(P8.as_bytes()), Ok(SCALAIRE));
    // Du texte autour ne gêne pas.
    let entouree = std::format!("Clef d'essai\n{P8}\nfin\n");
    assert_eq!(decode_p8(entouree.as_bytes()), Ok(SCALAIRE));
}

/// Ce qui n'a pas la forme d'une clef `.p8` P-256 se refuse.
#[test]
fn ce_qui_n_est_pas_une_clef_p8_se_refuse() {
    let remplacer = |de: &str, par: &str| P8.replacen(de, par, 1);
    let fautes = [
        String::from("rien"),
        String::from("-----BEGIN PRIVATE KEY-----\nMIGH"),
        remplacer(
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
        ),
        // Un signe hors de l'alphabet, ou après le remplissage.
        remplacer("MIGH", "MI!H"),
        remplacer("tQZR", "tQ=R"),
        // Des octets tronqués : le DER ne se ferme pas.
        remplacer(
            "xgwD6RstvOSWGz2m1fqnUVKuiXCBeM1sUwHqlUBiUa+VvK51hxhKtQZR\n",
            "",
        ),
        // La version (0 → 1), la courbe (prime256v1 → secp384r1 tronquée),
        // la version de l'ECPrivateKey (1 → 2).
        remplacer("MIGHAgEAMBMG", "MIGHAgEBMBMG"),
        remplacer("AwEHBG0w", "AwEIBG0w"),
        remplacer("awIBAQQg", "awIBAgQg"),
        // Une longueur de scalaire qui n'est pas trente-deux.
        remplacer("awIBAQQg", "awIBAQQf"),
        // Un en-tête d'élément qui n'est ni court, ni sur un ou deux octets.
        String::from("-----BEGIN PRIVATE KEY-----\nMIQAAAAA\n-----END PRIVATE KEY-----"),
        // Un élément qui annonce plus qu'il ne porte, et des octets après la
        // séquence.
        String::from("-----BEGIN PRIVATE KEY-----\nMIIBAAAA\n-----END PRIVATE KEY-----"),
        String::from("-----BEGIN PRIVATE KEY-----\nMAAA\n-----END PRIVATE KEY-----"),
        String::from("-----BEGIN PRIVATE KEY-----\nMIEA\n-----END PRIVATE KEY-----"),
        String::from("-----BEGIN PRIVATE KEY-----\nMA==\n-----END PRIVATE KEY-----"),
        String::from("-----BEGIN PRIVATE KEY-----\nMIE=\n-----END PRIVATE KEY-----"),
        String::from("-----BEGIN PRIVATE KEY-----\nMII=\n-----END PRIVATE KEY-----"),
        String::from("-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----"),
        // Plus long que ce qu'une clef P-256 occupe.
        std::format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            "A".repeat(400)
        ),
    ];
    for faute in fautes {
        assert_eq!(
            decode_p8(faute.as_bytes()),
            Err(Error::BadKeyFile),
            "{faute}"
        );
    }
    // Trente-deux octets nuls : la forme est bonne, le scalaire non.
    let nul = "-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END PRIVATE KEY-----";
    assert_eq!(decode_p8(nul.as_bytes()), Err(Error::BadPrivateKey));
}

/// Le jeton de fournisseur d'APNs : `bearer`, un en-tête ES256 qui nomme la
/// clef, l'équipe et l'instant — et une signature que la clef vérifie.
#[test]
fn un_jeton_apns_se_verifie() {
    use p256::ecdsa::signature::Verifier as _;
    let mut out = [0_u8; 512];
    let n = write_apns_token(
        "ABC123DEFG",
        "DEF123GHIJ",
        1_790_000_000,
        &SCALAIRE,
        &mut out,
    )
    .expect("écrivable");
    let texte = String::from_utf8(out[..n].to_vec()).expect("ASCII");
    let jeton = texte.strip_prefix("bearer ").expect("bearer");
    let morceaux: Vec<&str> = jeton.split('.').collect();
    assert_eq!(morceaux.len(), 3);
    assert_eq!(
        lire(morceaux[0]),
        br#"{"alg":"ES256","kid":"ABC123DEFG"}"#.to_vec()
    );
    assert_eq!(
        lire(morceaux[1]),
        br#"{"iss":"DEF123GHIJ","iat":1790000000}"#.to_vec()
    );
    let publique = super::vapid_public_key(&SCALAIRE).expect("une clef");
    let verifiante = p256::ecdsa::VerifyingKey::from_sec1_bytes(&publique).expect("un point");
    let signature = p256::ecdsa::Signature::from_slice(&lire(morceaux[2])).expect("64 octets");
    let signe = std::format!("{}.{}", morceaux[0], morceaux[1]);
    assert!(verifiante.verify(signe.as_bytes(), &signature).is_ok());
    // Des identifiants hors forme, une clef nulle, une place trop courte.
    for (id, equipe) in [
        ("", "E"),
        ("K", ""),
        ("K-1", "E"),
        ("K", "é"),
        ("K", &"E".repeat(33)),
    ] {
        assert_eq!(
            write_apns_token(id, equipe, 1, &SCALAIRE, &mut out),
            Err(Error::BadClaim),
            "{id} {equipe}"
        );
    }
    assert_eq!(
        write_apns_token("K", "E", 1, &[0; 32], &mut out),
        Err(Error::BadPrivateKey)
    );
    assert_eq!(
        write_apns_token("K", "E", 1, &SCALAIRE, &mut out[..20]),
        Err(Error::BufferTooSmall)
    );
}

/// Enveloppe du DER en PEM `PRIVATE KEY`.
fn pem(der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut texte = String::new();
    for groupe in der.chunks(3) {
        let octets = [
            groupe.first().copied().unwrap_or(0),
            groupe.get(1).copied().unwrap_or(0),
            groupe.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from_be_bytes([0, octets[0], octets[1], octets[2]]);
        for (rang, decalage) in [18_u32, 12, 6, 0].into_iter().enumerate() {
            let signe = ALPHABET[usize::try_from((n >> decalage) & 63).expect("six bits")];
            texte.push(if rang <= groupe.len() {
                char::from(signe)
            } else {
                '='
            });
        }
    }
    std::format!("-----BEGIN PRIVATE KEY-----\n{texte}\n-----END PRIVATE KEY-----\n")
}

/// Chaque élément de la structure se vérifie, à sa place.
#[test]
fn chaque_element_du_der_se_verifie() {
    const ALGORITHME: [u8; 21] = [
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    let sequence = |corps: &[u8]| {
        let mut der = std::vec![0x30, u8::try_from(corps.len()).expect("court")];
        der.extend_from_slice(corps);
        der
    };
    let avec = |suite: &[u8]| {
        let mut corps = std::vec![0x02, 0x01, 0x00];
        corps.extend_from_slice(&ALGORITHME);
        corps.extend_from_slice(suite);
        sequence(&corps)
    };
    for der in [
        // Un algorithme qui n'est pas une séquence.
        sequence(&[0x02, 0x01, 0x00, 0x31, 0x00]),
        // Pas de clef privée derrière l'algorithme.
        avec(&[]),
        // Une clef privée qui n'est pas une `ECPrivateKey`.
        avec(&[0x04, 0x01, 0x05]),
        // Une `ECPrivateKey` sans version, puis sans scalaire.
        avec(&[0x04, 0x02, 0x30, 0x00]),
        avec(&[0x04, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01]),
    ] {
        assert_eq!(
            decode_p8(pem(&der).as_bytes()),
            Err(Error::BadKeyFile),
            "{der:02x?}"
        );
    }
    // Et la bonne forme, reconstruite ici, se lit.
    let mut ec = std::vec![0x02, 0x01, 0x01, 0x04, 0x20];
    ec.extend_from_slice(&SCALAIRE);
    let mut octets = std::vec![0x04, u8::try_from(ec.len() + 2).expect("court")];
    octets.extend(sequence(&ec));
    assert_eq!(decode_p8(pem(&avec(&octets)).as_bytes()), Ok(SCALAIRE));
}
