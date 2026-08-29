//! Ce que la vérification d'une signature doit tenir.
//!
//! # D'où viennent ces vecteurs, et pourquoi ils ne viennent pas d'ici
//!
//! Une épreuve écrite avec le code qu'elle éprouve passe toujours. Les deux
//! ancrages de ce fichier viennent donc d'ailleurs :
//!
//! - **le condensat de corps de la RFC 6376 annexe A** — le message de son
//!   exemple, et le `bh=` qu'elle en publie. Rien de ce projet n'a servi à le
//!   calculer ;
//! - **des signatures produites par OpenSSL**, sur un condensat fixe pour la
//!   cryptographie seule, et sur un bloc d'en-têtes canonicalisé par une
//!   implémentation Python écrite séparément pour la chaîne entière. Si notre
//!   canonicalisation dérivait d'un octet, la signature ne vérifierait plus.

use super::{BodyHasher, DIGEST_LEN, HeaderHasher, decoder_base64, verifier_la_signature, verify};
use crate::canonical::Canon;
use crate::signature::{Algorithm, Signature};
use crate::{Error, PublicKeyRecord};

/// La clé publique RSA-2048 des épreuves, en `SubjectPublicKeyInfo`.
const RSA_PUB: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx6X1Z8atmh0Hi6UhKel/kQjPVpzANayrU7CW+Ds8LPQfHgnHu2xys6Telb22NitOEcIL3BufK1wzm+6AXU42QbSxIXOlzwbiM1r6/1nzaLd0iGrrZyBIlAoAAE5jM/7Hh12Pgf5WFyV1fAfof1OcN5/jqs/PKIn12zer+nBX2XFRHUWeT9mBmCHe2LaP2mbEkeq3waiOvlGQ1N9IrHPYeuiPlB3yAxBn9+FXI1lEamF7u4lVBNc921dGMxDZvE9XPNL9qHRRU8RHwhEeQjO4yVaLGxNlmNOnIukKpdic/WyxcjiK951IEjVj2EOzPxd+N574bs57d9A8RmOa3uU9OQIDAQAB";

/// Une clé RSA de 8192 bits — c'est-à-dire du calcul offert à qui la publie.
const RSA_8192: &str = "MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAn+sY83AkyNVb5G6VihZzgxLs5GIJ1upO\
     M+0r5V8k/mzc0hYm/zgDw551CRiEUwFn5C05erTPXTNcu0h/4aykYCAasssjdgZtWIBbAi+qhItA\
     GP4xWDgbhrzFJFqt7h+Oa//b+UeM1+k77Pc/GYeypgyH4aXr96SFvjWIHZaeQIUn/9LGWk4ovxPc\
     /ythRJDF9x5ukg22zC0LZ9J1JXI8D2auIe2KlgATbtkuZvBZp42Zy42T8+JSRx6vrq02/nal/L3c\
     g0x7YQCT2qDZAM9Id416ZqCZanzyKs5LSKEgGtoO4vxuhVjlo7OIGHP3ZzEgxhR1TEX7+JMwnfg6\
     WqaykQJl5wX3XW4VSi7HUk4ubyscoE6en8OyN3FSjdzdDgYLrfcTV+ohQu8n95ZddtRI/GJ9iRTT\
     RhDKDvH1Ed8lQ6aJf8x/gej7qsh76t3/awqlHy8eai/40bzpRLQJEGI5mlm2h5Z1wI1uVUSCHUWT\
     1wTyUWkzzBdGvdo1yxwxlIvhk9h2NEVv33OtWL1nu4R3i/RNqe+/7DY9RkVD5ujS+Rc9ZnM8e0fc\
     qMGHlAcntfIsQsImijm3BSbm6X8kj8ZnSVEavBFK4D8hdIzd18MdzWS5ba25mloY06jo3k2JO7Lr\
     HOdNPZI/7uVP6f5C7GRHprH0mKgibBw9VpkJZn488xwd9I2VmP+kiASfeGlne1Cb6JqrevmjV4HA\
     zF5vjcDu5lGIcmwQjd/WaKErwmAEHdKmMAqo8sbZXu6iyd5+lkJEIFUNI8bC3ZA5ImARjOg94tOH\
     EHSHYOAh8xRQcpwsM3/J0Z56tDPR1AoBl3wIBHKoAVC5GGqxgWDas4CKfPZJclbLjVYm7bVAkiHT\
     2iapYZ7sdx4CGXebS666mST6Yt9OeC6+1g0eG4TpKXc0Z+ob4Aqhr2i44kGEtrNVj5jtimWE9enP\
     lxi7kxc8iN50GOS5U4/hzVCYCT0fThTQTQ0lwgMc9K8RbKXPTq3jWvwaIPn6hffHxc40do/s8V46\
     52SojWY9uYm0Zo6hsC8Ce4+E6Urs0waOEMhBkaytxUqCng9AukM9WGqZxPIaebCgSF21FJdgGVuB\
     7XgvLoyHgzExnma0LooY4Q0y9cg8qBFy/ZTR3nbE5UdgeiyJ9dEJG/YlUf4bnup86nvzwP4iNIwj\
     F8aYy2/6Vfh6PgRjjrhy5t7v/KinkVyUvDSv5frnujBUp45lnZbioDbPHX+rB+I+58aNf/vp0orJ\
     igooUTzltmvteDc3dvQjIHNKkty9YKmiEpmV4TwJfWpP44Y0OXtFz/XbAk1Y6Q/9cxweWI0CwzWE\
     sirQbRcyFeHpFXnPu24O06WS3zUhSY7WiugshhaHYwIDAQAB";

/// Une clé RSA de 512 bits — c'est-à-dire une clé qui se factorise.
const RSA_512: &str = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANAViFwl2MYomvNEPAa4mzHqv+XHsXU54pcf7oKHnVVCdblSfQvwtA7amwo8WiacZvf2bPE+lK//pWd7r4PBi6kCAwEAAQ==";

/// La clé publique Ed25519, NUE comme la RFC 8463 la veut.
const ED_PUB: &str = "5jXkIF37GsaskgrFqSFWtrngVp9j+KSvs0hBzkVQs60=";

/// Le corps de l'exemple de la RFC 6376 annexe A.
const CORPS_RFC: &[u8] = b"Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n";

/// Le `bh=` que la RFC en publie.
const BH_RFC: &str = "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=";

/// Le condensat de `air-mail-server`, sur lequel OpenSSL a signé.
const CONDENSAT_FIXE: [u8; DIGEST_LEN] = [
    0x96, 0x5c, 0xf3, 0x1f, 0x3e, 0xf7, 0xa3, 0xff, 0xad, 0x21, 0x81, 0x44, 0x81, 0xcc, 0x42, 0x5f,
    0x45, 0x03, 0x69, 0x21, 0x68, 0xfc, 0x48, 0x87, 0xc1, 0x43, 0xf4, 0x31, 0x02, 0x3d, 0x49, 0x6d,
];

/// La signature Ed25519 de ce condensat.
const ED_SIG: &str =
    "6A7GnF26CEHoLrr2fD7a+fUEDXLyhoYbvaxKvc2prPkzeoBlbFCJ4KBR8iCjSZTVMiyFedlUmpDd1qVsb62YCg==";

/// Les champs signés du message d'épreuve, dans l'ordre du `h=`.
const CHAMPS: [(&[u8], &[u8]); 4] = [
    (b"From", b" Joe SixPack <joe@football.example.com>"),
    (b"To", b" Suzie Q <suzie@shopping.example.net>"),
    (b"Subject", b" Is dinner ready?"),
    (b"Date", b" Fri, 11 Jul 2003 21:00:37 -0700 (PDT)"),
];

/// La valeur du champ `DKIM-Signature`, telle qu'elle figure dans le message.
fn signature_du_message() -> std::string::String {
    std::format!(
        " v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=brisbane;\r\n \
         h=from:to:subject:date;\r\n bh={BH_RFC};\r\n b={}",
        "g5OKVTgIYQUyq9A2gE95pwI7a1A9SaKub+1WiXm/7aSYmgfJK6unxdE21/i4YhlC8pTrUukqkKf+YICy5WfITO4Nt+0x6lvfWcFLM1yHzL/3eDXjBd0na63VVIfv827zgdIXVNDYCtsL1Il2RPiJ2WmAAmP/lMvx4/yISRVN+z5B6RtQ7QzGLveNzfBf6I35Iz1OrWz6QQ4A7/BwKLUeKCWSjpnFK+wJeZ5is2dnz1cEaP9IERGu9jSeMwK3mjVVfmD9HHCeS5PUr5i1nLoidl/KXx52jnPcgDSldaYlINPssxdahtzJW+Treq03CUSCrAIIEmcXaISEhmfT538Piw=="
    )
}

fn decode(base64: &str) -> std::vec::Vec<u8> {
    let mut sortie = std::vec![0_u8; base64.len()];
    let ecrits = decoder_base64(base64.as_bytes(), &mut sortie).expect("base64 lisible");
    sortie.truncate(ecrits);
    sortie
}

/// Le condensat des en-têtes du message d'épreuve.
fn condensat_des_entetes(valeur: &str) -> [u8; DIGEST_LEN] {
    let mut condensat = HeaderHasher::new(Canon::Relaxed);
    for (nom, valeur_du_champ) in CHAMPS {
        condensat.field(nom, valeur_du_champ);
    }
    condensat
        .signature_field(b"DKIM-Signature", valeur.as_bytes())
        .expect("le `b=` est là");
    condensat.finish()
}

// ── L'ANCRAGE DE LA RFC ─────────────────────────────────────────────────────

#[test]
fn le_condensat_du_corps_est_celui_que_la_rfc_publie() {
    // Rien de ce projet n'a servi à calculer ce `bh=`. S'il correspond, c'est
    // que la canonicalisation ET le condensat sont ceux du reste du monde.
    let mut corps = BodyHasher::new(Canon::Simple, None);
    corps.update(CORPS_RFC);
    let (condensat, ecrits) = corps.finish();
    assert_eq!(condensat.to_vec(), decode(BH_RFC));
    assert_eq!(ecrits, u64::try_from(CORPS_RFC.len()).expect("petit"));
}

#[test]
fn le_corps_se_condense_par_morceaux_comme_d_un_seul_tenant() {
    let mut entier = BodyHasher::new(Canon::Relaxed, None);
    entier.update(CORPS_RFC);
    let (attendu, _) = entier.finish();

    let mut morceau_par_morceau = BodyHasher::new(Canon::Relaxed, None);
    for octet in CORPS_RFC {
        morceau_par_morceau.update(core::slice::from_ref(octet));
    }
    let (obtenu, _) = morceau_par_morceau.finish();
    assert_eq!(obtenu, attendu);
}

#[test]
fn la_borne_du_corps_se_compte_sur_le_canonicalise() {
    // §6.1.1 : si `l=` annonce plus d'octets que le corps n'en porte, la
    // vérification échoue. Sans ce compte, un pair ferait signer un long corps
    // et n'en livrerait qu'un début.
    let mut borne = BodyHasher::new(Canon::Simple, Some(3));
    borne.update(CORPS_RFC);
    let (_, ecrits) = borne.finish();
    assert_eq!(ecrits, 3);

    let mut trop = BodyHasher::new(Canon::Simple, Some(10_000));
    trop.update(CORPS_RFC);
    let (_, ecrits) = trop.finish();
    assert!(ecrits < 10_000, "le corps est plus court que la borne");
}

// ── LA CHAÎNE ENTIÈRE ───────────────────────────────────────────────────────

#[test]
fn une_signature_juste_se_verifie() {
    // Le condensat des en-têtes a été calculé par une implémentation Python
    // écrite séparément, et OpenSSL a signé CE condensat-là. Si notre
    // canonicalisation dérivait d'un octet, la signature ne vérifierait plus.
    let valeur = signature_du_message();
    let signature = Signature::parse(valeur.as_bytes()).expect("lisible");
    let brut = std::format!("v=DKIM1; k=rsa; p={RSA_PUB}");
    let enregistrement = PublicKeyRecord::parse(brut.as_bytes()).expect("lisible");

    let mut corps = BodyHasher::new(signature.canonicalization.body, signature.body_length);
    corps.update(CORPS_RFC);
    let (condensat_du_corps, _) = corps.finish();

    let entetes = condensat_des_entetes(&valeur);
    let cle = decode(RSA_PUB);
    let scellee = signature_brute(&signature);

    verify(
        &signature,
        &enregistrement,
        &cle,
        &condensat_du_corps,
        &entetes,
        &scellee,
    )
    .expect("la signature devrait se vérifier");
}

/// La signature `b=`, dépliée puis décodée.
fn signature_brute(signature: &Signature<'_>) -> std::vec::Vec<u8> {
    let mut tampon = std::vec![0_u8; signature.signature.len()];
    let sans_blancs = signature
        .signature_base64(&mut tampon)
        .expect("le dépliage tient")
        .to_vec();
    let mut brut = std::vec![0_u8; sans_blancs.len()];
    let combien = decoder_base64(&sans_blancs, &mut brut).expect("base64 lisible");
    brut.truncate(combien);
    brut
}

/// Le montage complet, pour les épreuves qui en altèrent une pièce.
fn verifier_avec(valeur: &str, corps: &[u8], enregistrement: &str) -> Result<(), Error> {
    let signature = Signature::parse(valeur.as_bytes())?;
    let cle_lue = PublicKeyRecord::parse(enregistrement.as_bytes())?;
    let mut condensat = BodyHasher::new(signature.canonicalization.body, signature.body_length);
    condensat.update(corps);
    let (du_corps, _) = condensat.finish();
    let entetes = condensat_des_entetes(valeur);
    let mut tampon = std::vec![0_u8; cle_lue.key.len()];
    let sans_blancs = cle_lue.key_base64(&mut tampon).expect("dépliage").to_vec();
    let mut cle = std::vec![0_u8; sans_blancs.len()];
    let combien = decoder_base64(&sans_blancs, &mut cle).expect("base64");
    cle.truncate(combien);
    verify(
        &signature,
        &cle_lue,
        &cle,
        &du_corps,
        &entetes,
        &signature_brute(&signature),
    )
}

#[test]
fn un_corps_modifie_echoue_avant_la_cryptographie() {
    // Le condensat du corps se compare en premier : c'est gratuit, là où
    // vérifier une signature RSA coûte une exponentiation modulaire. Un pair qui
    // envoie mille messages falsifiés ne fait pas travailler la machine pour
    // autant.
    let enregistrement = std::format!("v=DKIM1; k=rsa; p={RSA_PUB}");
    let mut altere = std::vec::Vec::from(CORPS_RFC);
    altere.extend_from_slice(b"Une ligne de plus.\r\n");
    assert_eq!(
        verifier_avec(&signature_du_message(), &altere, &enregistrement),
        Err(Error::BodyHashMismatch)
    );
}

#[test]
fn un_en_tete_modifie_fait_echouer_la_signature() {
    // Le corps est intact, donc le premier contrôle passe ; c'est la
    // cryptographie qui refuse.
    let enregistrement = std::format!("v=DKIM1; k=rsa; p={RSA_PUB}");
    let altere = signature_du_message().replace("s=brisbane", "s=melbourne");
    assert_eq!(
        verifier_avec(&altere, CORPS_RFC, &enregistrement),
        Err(Error::SignatureMismatch)
    );
}

#[test]
fn une_signature_d_un_octet_pres_echoue() {
    let enregistrement = std::format!("v=DKIM1; k=rsa; p={RSA_PUB}");
    let juste = signature_du_message();
    // On retourne le dernier caractère du base64 de `b=`.
    let mut octets = juste.into_bytes();
    let dernier = octets.len().saturating_sub(2);
    octets[dernier] = if octets[dernier] == b'A' { b'B' } else { b'A' };
    let altere = std::string::String::from_utf8(octets).expect("ASCII");
    assert_eq!(
        verifier_avec(&altere, CORPS_RFC, &enregistrement),
        Err(Error::SignatureMismatch)
    );
}

#[test]
fn une_cle_qui_ne_va_pas_avec_l_algorithme_est_refusee() {
    // Une clé Ed25519 ne vérifie pas une signature RSA, et l'essayer quand même
    // ne rendrait pas « faux » mais « illisible ».
    let enregistrement = std::format!("v=DKIM1; k=ed25519; p={ED_PUB}");
    assert_eq!(
        verifier_avec(&signature_du_message(), CORPS_RFC, &enregistrement),
        Err(Error::UnsupportedKeyType)
    );
}

#[test]
fn une_cle_qui_refuse_le_condensat_est_refusee() {
    // Le détenteur du domaine a restreint ce que sa clé couvre ; passer outre
    // reviendrait à décider à sa place.
    let enregistrement = std::format!("v=DKIM1; k=rsa; h=sha1; p={RSA_PUB}");
    assert_eq!(
        verifier_avec(&signature_du_message(), CORPS_RFC, &enregistrement),
        Err(Error::UnsupportedAlgorithm)
    );
}

// ── LES BORNES SUR LES CLÉS ─────────────────────────────────────────────────

#[test]
fn une_cle_rsa_de_512_bits_est_refusee() {
    // Elle se factorise pour le prix de quelques heures de calcul. RFC 8301
    // §3.2 l'interdit aux signataires ; l'accepter en vérification reviendrait à
    // valider ce qu'on sait falsifiable.
    let cle = decode(RSA_512);
    assert_eq!(
        verifier_la_signature(Algorithm::RsaSha256, &cle, &CONDENSAT_FIXE, &[0; 64]),
        Err(Error::KeyTooSmall)
    );
}

#[test]
fn une_cle_illisible_est_refusee() {
    for mauvaise in [&b""[..], b"pas du DER", &[0x30, 0x82, 0xFF, 0xFF]] {
        assert_eq!(
            verifier_la_signature(Algorithm::RsaSha256, mauvaise, &CONDENSAT_FIXE, &[0; 64]),
            Err(Error::MalformedKey)
        );
    }
}

#[test]
fn la_forme_pkcs1_nue_est_acceptee_aussi() {
    // RFC 6376 §3.6.1 veut un `SubjectPublicKeyInfo`, mais des zones publient
    // la forme nue de PKCS#1 — et un vérificateur qui les refuserait ferait
    // échouer des signataires par ailleurs corrects.
    //
    // On extrait le PKCS#1 du SPKI : c'est la chaîne de bits qui le termine.
    let spki = decode(RSA_PUB);
    let debut = spki
        .windows(2)
        .position(|paire| paire == [0x03, 0x82])
        .expect("la chaîne de bits est là");
    let pkcs1 = &spki[debut.saturating_add(5)..];
    let valeur = signature_du_message();
    let signature = Signature::parse(valeur.as_bytes()).expect("lisible");
    let entetes = condensat_des_entetes(&valeur);
    assert_eq!(
        verifier_la_signature(
            Algorithm::RsaSha256,
            pkcs1,
            &entetes,
            &signature_brute(&signature)
        ),
        Ok(())
    );
}

// ── ED25519 (RFC 8463) ──────────────────────────────────────────────────────

#[test]
fn une_signature_ed25519_juste_se_verifie() {
    // OpenSSL a signé CE condensat-là, avec cette clé-là.
    let cle = decode(ED_PUB);
    let scellee = decode(ED_SIG);
    assert_eq!(
        verifier_la_signature(Algorithm::Ed25519Sha256, &cle, &CONDENSAT_FIXE, &scellee),
        Ok(())
    );
}

#[test]
fn une_signature_ed25519_alteree_echoue() {
    let cle = decode(ED_PUB);
    let mut scellee = decode(ED_SIG);
    scellee[0] ^= 1;
    assert_eq!(
        verifier_la_signature(Algorithm::Ed25519Sha256, &cle, &CONDENSAT_FIXE, &scellee),
        Err(Error::SignatureMismatch)
    );
    // Et un condensat qui n'est pas celui qu'on a signé.
    let autre = [0_u8; DIGEST_LEN];
    assert_eq!(
        verifier_la_signature(Algorithm::Ed25519Sha256, &cle, &autre, &decode(ED_SIG)),
        Err(Error::SignatureMismatch)
    );
}

#[test]
fn une_cle_ou_une_signature_ed25519_de_la_mauvaise_taille_est_refusee() {
    // La RFC 8463 fixe les deux : trente-deux octets pour la clé, soixante-quatre
    // pour la signature. Rien d'autre n'est une clé, ni une signature.
    let cle = decode(ED_PUB);
    let scellee = decode(ED_SIG);
    for mauvaise in [&cle[..31], &cle[..], &[0_u8; 33][..]] {
        if mauvaise.len() == 32 {
            continue;
        }
        assert_eq!(
            verifier_la_signature(
                Algorithm::Ed25519Sha256,
                mauvaise,
                &CONDENSAT_FIXE,
                &scellee
            ),
            Err(Error::MalformedKey),
            "{} octets",
            mauvaise.len()
        );
    }
    for mauvaise in [&scellee[..63], &[0_u8; 65][..]] {
        assert_eq!(
            verifier_la_signature(Algorithm::Ed25519Sha256, &cle, &CONDENSAT_FIXE, mauvaise),
            Err(Error::SignatureMismatch),
            "{} octets",
            mauvaise.len()
        );
    }
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

#[test]
fn un_condensat_de_corps_illisible_est_refuse() {
    // `bh=` n'est pas du base64, ou ne fait pas trente-deux octets.
    let enregistrement = std::format!("v=DKIM1; k=rsa; p={RSA_PUB}");
    for mauvais in ["bh=!!!;", "bh=Zm9v;"] {
        let altere = signature_du_message().replace(&std::format!("bh={BH_RFC};"), mauvais);
        let obtenu = verifier_avec(&altere, CORPS_RFC, &enregistrement);
        assert!(
            matches!(
                obtenu,
                Err(Error::MalformedBase64 | Error::BodyHashMismatch)
            ),
            "{mauvais} : {obtenu:?}"
        );
    }
}

#[test]
fn le_champ_de_signature_doit_porter_un_b() {
    let mut condensat = HeaderHasher::new(Canon::Relaxed);
    assert_eq!(
        condensat.signature_field(b"DKIM-Signature", b" v=1; a=rsa-sha256"),
        Err(Error::MissingTag("b"))
    );
}

#[test]
fn le_retrait_du_b_ne_touche_pas_au_bh() {
    // `bh=` commence par les mêmes deux octets que `b=` suivi de `h`. Un
    // analyseur qui chercherait « b= » sans regarder les limites d'étiquette
    // effacerait le condensat du corps — et toutes les signatures échoueraient.
    let valeur = " v=1; bh=AAAA; b=BBBB; d=example.com";
    let mut simple = HeaderHasher::new(Canon::Simple);
    simple
        .signature_field(b"DKIM-Signature", valeur.as_bytes())
        .expect("le `b=` est là");
    let obtenu = simple.finish();

    let mut attendu = HeaderHasher::new(Canon::Simple);
    attendu
        .signature_field(b"DKIM-Signature", b" v=1; bh=AAAA; b=; d=example.com")
        .expect("le `b=` est là");
    assert_eq!(obtenu, attendu.finish());
}

#[test]
fn les_machines_se_deboguent_et_se_copient() {
    let corps = BodyHasher::new(Canon::Simple, None);
    let copie = corps.clone();
    assert!(!std::format!("{copie:?}").is_empty());
    let entetes = HeaderHasher::new(Canon::Relaxed);
    let copie = entetes.clone();
    assert!(!std::format!("{copie:?}").is_empty());
}

#[test]
fn une_cle_rsa_de_8192_bits_est_refusee() {
    // Elle ne protège personne de plus, et coûte à NOUS : c'est une zone
    // hostile qui la publierait, pour faire brûler du calcul à qui lui écrit.
    let cle = decode(RSA_8192);
    assert_eq!(
        verifier_la_signature(Algorithm::RsaSha256, &cle, &CONDENSAT_FIXE, &[0; 64]),
        Err(Error::KeyTooLarge)
    );
}

#[test]
fn trente_deux_octets_ne_font_pas_toujours_une_cle_ed25519() {
    // Une clé Ed25519 est un POINT de la courbe. Trente-deux octets quelconques
    // n'en désignent pas un — celui-ci ne se décompresse pas — et les accepter
    // ferait vérifier contre rien.
    let mut pas_un_point = [0_u8; 32];
    pas_un_point[0] = 2;
    assert_eq!(
        verifier_la_signature(
            Algorithm::Ed25519Sha256,
            &pas_un_point,
            &CONDENSAT_FIXE,
            &[0; 64]
        ),
        Err(Error::MalformedKey)
    );
    // Et trente-deux octets qui EN désignent un ne font pas pour autant une
    // signature juste : la clé se lit, la vérification refuse.
    assert_eq!(
        verifier_la_signature(
            Algorithm::Ed25519Sha256,
            &[0xFF; 32],
            &CONDENSAT_FIXE,
            &[0; 64]
        ),
        Err(Error::SignatureMismatch)
    );
}

// ── LE CHOIX DES CHAMPS SIGNÉS (§5.4.2) ─────────────────────────────────────

/// Condense les champs de `message` que `h=` nomme, et rend le condensat.
fn condensat_choisi(h: &str, message: &[(&[u8], &[u8])]) -> [u8; DIGEST_LEN] {
    let valeur = std::format!(
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=x; bh={BH_RFC}; h={h}; b=AAAA"
    );
    let signature = Signature::parse(valeur.as_bytes()).expect("lisible");
    let mut condensat = HeaderHasher::new(Canon::Relaxed);
    super::hash_signed_headers(&signature, &mut condensat, || message.iter().copied());
    condensat.finish()
}

#[test]
fn les_champs_se_prennent_depuis_le_bas() {
    // RFC 6376 §5.4.2. Un relais qui AJOUTE un champ l'écrit en haut : cette
    // règle fait qu'un champ ajouté n'est jamais celui qu'on condense.
    let deux_sujets: [(&[u8], &[u8]); 3] = [
        (b"Subject", b" ajoute par un relais"),
        (b"From", b" jean@example.com"),
        (b"Subject", b" le vrai"),
    ];
    let un_seul: [(&[u8], &[u8]); 2] = [(b"From", b" jean@example.com"), (b"Subject", b" le vrai")];
    assert_eq!(
        condensat_choisi("from:subject", &deux_sujets),
        condensat_choisi("from:subject", &un_seul),
        "le sujet ajouté en haut a été condensé"
    );
}

#[test]
fn un_nom_nomme_deux_fois_prend_deux_instances() {
    let deux: [(&[u8], &[u8]); 3] = [
        (b"Received", b" par le premier"),
        (b"Received", b" par le second"),
        (b"From", b" jean@example.com"),
    ];
    // `received:received` prend le dernier PUIS l'avant-dernier. (`from` est
    // là parce qu'une signature qui ne le couvre pas est refusée à la lecture.)
    let attendu = {
        let mut condensat = HeaderHasher::new(Canon::Relaxed);
        condensat.field(b"From", b" jean@example.com");
        condensat.field(b"Received", b" par le second");
        condensat.field(b"Received", b" par le premier");
        condensat.finish()
    };
    assert_eq!(condensat_choisi("from:received:received", &deux), attendu);
}

#[test]
fn un_nom_qu_on_ne_trouve_plus_se_traite_comme_absent() {
    // C'EST CE QUI FERME L'ATTAQUE PAR AJOUT : un signataire qui nomme `subject`
    // deux fois alors qu'il n'y en a qu'un fait échouer la signature dès qu'un
    // second apparaît — parce qu'alors, ce second sera condensé.
    let un_seul: [(&[u8], &[u8]); 2] = [(b"From", b" jean@example.com"), (b"Subject", b" le vrai")];
    let attendu = {
        let mut condensat = HeaderHasher::new(Canon::Relaxed);
        condensat.field(b"From", b" jean@example.com");
        condensat.field(b"Subject", b" le vrai");
        condensat.finish()
    };
    assert_eq!(condensat_choisi("from:subject:subject", &un_seul), attendu);

    // Et le même message avec un sujet AJOUTÉ ne rend plus le même condensat :
    // la seconde mention trouve désormais quelque chose.
    let ajoute: [(&[u8], &[u8]); 3] = [
        (b"Subject", b" ajoute"),
        (b"From", b" jean@example.com"),
        (b"Subject", b" le vrai"),
    ];
    assert_ne!(condensat_choisi("from:subject:subject", &ajoute), attendu);

    // Un nom que le message ne porte pas du tout ne condense rien non plus.
    assert_eq!(condensat_choisi("from:subject:absent", &un_seul), attendu);
}
