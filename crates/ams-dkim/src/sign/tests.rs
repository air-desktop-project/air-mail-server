//! Ce que la signature à l'émission doit tenir.
//!
//! # L'aller-retour est l'épreuve centrale
//!
//! Ce que ce module écrit, [`crate::verify`] doit le vérifier. Les deux
//! partagent le condensat — c'est voulu — et cette épreuve-là garantit que le
//! partage est complet : si le signataire écrivait un champ que le vérificateur
//! lit autrement, la signature tomberait, et rien d'autre ne le dirait.
//!
//! La clé de ces essais vient d'OpenSSL, et la même clé a servi à éprouver la
//! vérification contre des signatures qu'OpenSSL avait produites.

use super::{SIGNATURE_FIELD_MAX, Signer, SigningKey, decimal};
use crate::canonical::{Canon, Canonicalization};
use crate::signature::Algorithm;
use crate::verify::{BodyHasher, DIGEST_LEN, HeaderHasher, hash_signed_headers, verify};
use crate::{Error, PublicKeyRecord, Signature, decoder_base64};

/// La clé privée RSA-2048 des épreuves, au format PKCS#8.
const CLE_PRIVEE: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDHpfVnxq2aHQeLpSEp6X+R\
     CM9WnMA1rKtTsJb4Ozws9B8eCce7bHKzpN6VvbY2K04RwgvcG58rXDOb7oBdTjZBtLEhc6XP\
     BuIzWvr/WfNot3SIautnIEiUCgAATmMz/seHXY+B/lYXJXV8B+h/U5w3n+Oqz88oifXbN6v6\
     cFfZcVEdRZ5P2YGYId7Yto/aZsSR6rfBqI6+UZDU30isc9h66I+UHfIDEGf34VcjWURqYXu7\
     iVUE1z3bV0YzENm8T1c80v2odFFTxEfCER5CM7jJVosbE2WY06ci6Qql2Jz9bLFyOIr3nUgS\
     NWPYQ7M/F343nvhuznt30DxGY5re5T05AgMBAAECggEAPs+hKhGRK4PHjHEawm9iQXR2msa9\
     GAXnbvCHRriIIZJ6Ob6U9ovTeF494vlpGpi8Oo0Eoy6TgJZE7GF4RCKnojthYOdb+oqtXr/Y\
     aL7ZfA//my2cOvkmrGCLCI2g20pkZtuSGzEzz5tq32czh997rephO6uefqAM1/enZSa0FMXp\
     dbGSWZYcdM4zY57EVQLF25M9P9aQtgUaZ0c2V5/Nz5utQuRsWdzwWcmqtkh+n91RYNXcvYL5\
     l3YTMD96M6ZF+hdELyl4DRL4KHcKMqXaN7S9/DFVMQj3LgcLOttv9q0pB//ST2aonUhppKiX\
     vE8zB68jWayWMxN/tJYtW52vAwKBgQD5F13Bq+Fl7vuIzeWk1m1QL4NLDkaeixdME5J9810V\
     YmdWs4nkwc667qAJjDoko8gftuC+n/gf92GFpRfgbpm7O4h+0wQz2Whl/Nqs9o5Ig7QDDcIm\
     BpzhRciXqK6mfR6F6AP6GU/xj0NGB9deIFL/JKfqQ5YEzV1+eZQscWEnNwKBgQDNL4ey+5VZ\
     stBNkHdvrwEGGdGT4n9dGZ8xeXWYfve3c1jKfdzDZQLZH2ezHennaKKeaTm2Gyxq7sjg9m7L\
     4lX6wntBiWNJZ8WYaTncdLlcnElxrEULeAn8UHs5zt/3LsLyTmFopNQjfRECK0GF+OfaYHhW\
     PXK1btx3dk8peMIXDwKBgBzEnxZsFHciV7igFwKnpS5anm4/stZCuCkYJZYYUkrS955i0+0w\
     mQCr6J3RrTFoHQfUpjY94XlHp+K4g35vJ6AhKw2Cr3yRgmYtAtBxFVO4qkSkBSVBJEM8PQOO\
     /sTJtInAlxz+aWY7pohjBXOghhVjlWUP8zaQxViDECLl4VOXAoGAJwqiMWY5dsXVaMzSTQfp\
     k/WZsR/pyBc1+T35KDkQfXGPNYhZVzyDHDkjjCtm9EcumiG/f20QOJCS3GtHjbfVUE9tEH1J\
     zQ/XwzZSciYrlvmN5/k1cgc3LzFJISjB6NCW+2/6jOTAELidYeJFJ27C/wRYIWCz0N31SS3T\
     xjpaA/UCgYBL5PzED2qYJGxVe5QGXKByyZGtE+FOapI57K7k/RtzQjEfCpfplrCNNMM4+URf\
     S7Ofkf+10hN8CYLN9lZ0Rn0/qHl/E4MablkY2PTLnlVigpHM/2Tdd7jU+9M+C+mn82uJI2Cu\
     44CL4CLJIfYDKVlcANMpFUjLdQDnX0ZBBzHpUg==";

/// Sa clé publique, telle qu'un `p=` la publie.
const CLE_PUBLIQUE: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx6X1Z8atmh0Hi6UhKel/kQjPVpzA\
     NayrU7CW+Ds8LPQfHgnHu2xys6Telb22NitOEcIL3BufK1wzm+6AXU42QbSxIXOlzwbiM1r6\
     /1nzaLd0iGrrZyBIlAoAAE5jM/7Hh12Pgf5WFyV1fAfof1OcN5/jqs/PKIn12zer+nBX2XFR\
     HUWeT9mBmCHe2LaP2mbEkeq3waiOvlGQ1N9IrHPYeuiPlB3yAxBn9+FXI1lEamF7u4lVBNc9\
     21dGMxDZvE9XPNL9qHRRU8RHwhEeQjO4yVaLGxNlmNOnIukKpdic/WyxcjiK951IEjVj2EOz\
     Pxd+N574bs57d9A8RmOa3uU9OQIDAQAB";

/// Une clé RSA de 512 bits : trop petite pour porter un condensat SHA-256.
const CLE_512: &str = "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA0BWIXCXYxiia80Q8BribMeq/\
     5cexdTnilx/ugoedVUJ1uVJ9C/C0DtqbCjxaJpxm9/Zs8T6Ur/+lZ3uvg8GLqQIDAQABAkAV\
     AMdlvbA2uCyDt3RznTiU/kPmVpSz52bWqDNz22pnC4KANkC5+u4rwtUCYaMcUvnkbADJMfup\
     ysvXp57QVcKdAiEA+5yuLggSQ07u+G2TWHIT0EEWZHsFLLzZFuUmHH9SWVMCIQDTtoWzC59G\
     u8eJfMj+EaRn1VYFZZebbe19Cbo287GbkwIhAMRZndeQNuhNxdEaeZzQ0UN4N4hMNFqYOPVT\
     92zPsyy/AiEArt6wCHetE8u+wP1lNxZzaaB48PQ9CZD+/KywNvuK1CkCICXhKvL3K1AKsXiW\
     71pHCfoszGoJavhy1j81nVxQzg8d";

/// Sa clé publique.
const CLE_512_PUBLIQUE: &str = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANAViFwl2MYomvNEPAa4mzHqv+XHsXU54pcf7oKH\
     nVVCdblSfQvwtA7amwo8WiacZvf2bPE+lK//pWd7r4PBi6kCAwEAAQ==";

/// Les champs du message d'épreuve, du haut vers le bas.
const CHAMPS: [(&[u8], &[u8]); 4] = [
    (b"From", b" Joe SixPack <joe@football.example.com>"),
    (b"To", b" Suzie Q <suzie@shopping.example.net>"),
    (b"Subject", b" Is dinner ready?"),
    (b"Date", b" Fri, 11 Jul 2003 21:00:37 -0700 (PDT)"),
];

const CORPS: &[u8] = b"Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n";

fn decode(base64: &str) -> std::vec::Vec<u8> {
    let mut sortie = std::vec![0_u8; base64.len()];
    let ecrits = decoder_base64(base64.as_bytes(), &mut sortie).expect("base64 lisible");
    sortie.truncate(ecrits);
    sortie
}

fn cle() -> SigningKey {
    SigningKey::rsa_from_pkcs8_der(&decode(CLE_PRIVEE)).expect("clé lisible")
}

fn signataire<'a>(noms: &'a [&'a [u8]], canon: Canonicalization) -> Signer<'a> {
    Signer {
        domain: b"example.com",
        selector: b"brisbane",
        canonicalization: canon,
        headers: noms,
        timestamp: Some(1_732_000_000),
        expiration: None,
        identity: None,
    }
}

/// Signe le message d'épreuve, et rend le champ écrit.
fn signer(canon: Canonicalization) -> std::string::String {
    let noms: [&[u8]; 4] = [b"from", b"to", b"subject", b"date"];
    let mut corps = BodyHasher::new(canon.body, None);
    corps.update(CORPS);
    let (condensat, _) = corps.finish();
    let mut sortie = [0_u8; SIGNATURE_FIELD_MAX];
    let champ = signataire(&noms, canon)
        .sign(&cle(), &condensat, &CHAMPS, &mut sortie)
        .expect("signable");
    std::string::String::from_utf8(champ.to_vec()).expect("ASCII")
}

/// Vérifie un champ signé avec NOTRE vérificateur.
fn verifier(champ: &str, canon: Canonicalization, corps: &[u8]) -> Result<(), Error> {
    let valeur = champ
        .strip_prefix("DKIM-Signature:")
        .expect("le champ porte son nom")
        .strip_suffix("\r\n")
        .expect("il finit par un CRLF");
    let signature = Signature::parse(valeur.as_bytes())?;
    let brut = std::format!("v=DKIM1; k=rsa; p={CLE_PUBLIQUE}");
    let enregistrement = PublicKeyRecord::parse(brut.as_bytes())?;

    let mut condenseur = BodyHasher::new(canon.body, signature.body_length);
    condenseur.update(corps);
    let (du_corps, _) = condenseur.finish();

    let mut condensat = HeaderHasher::new(canon.header);
    hash_signed_headers(&signature, &mut condensat, || CHAMPS.iter().copied());
    condensat.signature_field(b"DKIM-Signature", valeur.as_bytes())?;

    let mut tampon = std::vec![0_u8; signature.signature.len()];
    let deplie = signature.signature_base64(&mut tampon)?.to_vec();
    let mut scellee = std::vec![0_u8; deplie.len()];
    let combien = decoder_base64(&deplie, &mut scellee)?;
    scellee.truncate(combien);

    verify(
        &signature,
        &enregistrement,
        &decode(CLE_PUBLIQUE),
        &du_corps,
        &condensat.finish(),
        &scellee,
    )
}

// ── L'ALLER-RETOUR ──────────────────────────────────────────────────────────

#[test]
fn ce_qu_on_signe_se_verifie() {
    // LA PROPRIÉTÉ QUI COMPTE, et sur les quatre couples de canonicalisation :
    // si le signataire écrivait un champ que le vérificateur lit autrement, la
    // signature tomberait, et rien d'autre ne le dirait.
    for canon in [
        Canonicalization {
            header: Canon::Relaxed,
            body: Canon::Relaxed,
        },
        Canonicalization {
            header: Canon::Simple,
            body: Canon::Simple,
        },
        Canonicalization {
            header: Canon::Relaxed,
            body: Canon::Simple,
        },
        Canonicalization {
            header: Canon::Simple,
            body: Canon::Relaxed,
        },
    ] {
        let champ = signer(canon);
        assert_eq!(
            verifier(&champ, canon, CORPS),
            Ok(()),
            "{canon:?} : {champ}"
        );
    }
}

#[test]
fn un_corps_modifie_apres_signature_ne_verifie_plus() {
    let canon = Canonicalization {
        header: Canon::Relaxed,
        body: Canon::Relaxed,
    };
    let champ = signer(canon);
    let mut altere = std::vec::Vec::from(CORPS);
    altere.extend_from_slice(b"Une ligne de plus.\r\n");
    assert_eq!(
        verifier(&champ, canon, &altere),
        Err(Error::BodyHashMismatch)
    );
}

// ── CE QUE LE CHAMP DIT ─────────────────────────────────────────────────────

#[test]
fn le_champ_porte_ce_qu_on_lui_a_demande() {
    let canon = Canonicalization {
        header: Canon::Relaxed,
        body: Canon::Simple,
    };
    let plat = signer(canon).replace("\r\n ", " ");
    assert!(plat.starts_with("DKIM-Signature: v=1;"), "{plat}");
    assert!(plat.contains(" a=rsa-sha256;"), "{plat}");
    assert!(plat.contains(" c=relaxed/simple;"), "{plat}");
    assert!(plat.contains(" d=example.com;"), "{plat}");
    assert!(plat.contains(" s=brisbane;"), "{plat}");
    assert!(plat.contains(" t=1732000000;"), "{plat}");
    assert!(plat.contains(" h=from:to:subject:date;"), "{plat}");
    assert!(plat.contains(" bh="), "{plat}");
    assert!(plat.contains(" b="), "{plat}");
    // `l=` N'EST PAS ÉCRIT : il laisse ajouter ce qu'on veut après les `n`
    // premiers octets sans invalider la signature (§8.2).
    assert!(!plat.contains(" l="), "{plat}");
}

#[test]
fn les_etiquettes_facultatives_ne_s_ecrivent_que_si_on_les_demande() {
    let noms: [&[u8]; 1] = [b"from"];
    let canon = Canonicalization::default();
    let mut corps = BodyHasher::new(canon.body, None);
    corps.update(CORPS);
    let (condensat, _) = corps.finish();

    let mut sortie = [0_u8; SIGNATURE_FIELD_MAX];
    let mut sobre = signataire(&noms, canon);
    sobre.timestamp = None;
    let champ = sobre
        .sign(&cle(), &condensat, &CHAMPS, &mut sortie)
        .expect("signable");
    let plat = std::string::String::from_utf8_lossy(champ).replace("\r\n ", " ");
    assert!(!plat.contains(" t="), "{plat}");
    assert!(!plat.contains(" x="), "{plat}");
    assert!(!plat.contains(" i="), "{plat}");

    let mut sortie = [0_u8; SIGNATURE_FIELD_MAX];
    let mut tout = signataire(&noms, canon);
    tout.expiration = Some(1_732_003_600);
    tout.identity = Some(b"joe@example.com");
    let champ = tout
        .sign(&cle(), &condensat, &CHAMPS, &mut sortie)
        .expect("signable");
    let plat = std::string::String::from_utf8_lossy(champ).replace("\r\n ", " ");
    assert!(plat.contains(" t=1732000000;"), "{plat}");
    assert!(plat.contains(" x=1732003600;"), "{plat}");
    assert!(plat.contains(" i=joe@example.com;"), "{plat}");
}

#[test]
fn aucune_ligne_ne_depasse_ce_qu_une_ligne_peut_faire() {
    // RFC 5322 §2.1.1. Un champ plus long qu'une ligne se fait couper en aval,
    // là où personne ne décide — et un champ coupé n'est plus celui qu'on a
    // signé.
    let champ = signer(Canonicalization::default());
    for ligne in champ.trim_end_matches("\r\n").split("\r\n") {
        assert!(ligne.len() <= 998, "ligne de {} octets", ligne.len());
    }
    for suite in champ.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
        assert!(suite.starts_with(' '), "repli sans espace : {suite:?}");
    }
    assert!(champ.ends_with("\r\n"), "{champ:?}");
}

// ── CE QU'IL REFUSE D'ÉCRIRE ────────────────────────────────────────────────

#[test]
fn une_signature_qui_ne_couvre_pas_from_est_refusee() {
    // La relecture le dit. C'est le seul endroit où l'on vérifie que ce qu'on
    // vient d'écrire est ce qu'on croit avoir écrit — et une signature qui ne
    // couvre pas l'auteur ne dit rien de l'auteur.
    let noms: [&[u8]; 2] = [b"to", b"subject"];
    let canon = Canonicalization::default();
    let mut corps = BodyHasher::new(canon.body, None);
    corps.update(CORPS);
    let (condensat, _) = corps.finish();
    let mut sortie = [0_u8; SIGNATURE_FIELD_MAX];
    assert_eq!(
        signataire(&noms, canon).sign(&cle(), &condensat, &CHAMPS, &mut sortie),
        Err(Error::FromNotSigned)
    );
}

#[test]
fn un_tampon_trop_petit_refuse_plutot_que_de_tronquer() {
    // ON SIGNE EN ED25519 POUR CETTE ÉPREUVE-LÀ. Le balayage signe une fois par
    // taille, et une signature RSA en construction de débogage coûte des
    // dizaines de millisecondes : le même balayage prendrait un quart d'heure.
    // Les chemins éprouvés ici sont ceux de l'écriture, que l'algorithme ne
    // change pas.
    let signe = SigningKey::ed25519_from_seed(&[3_u8; 32]);
    // Plusieurs noms et TOUTES les étiquettes facultatives : chaque écriture a
    // sa borne, y compris le deux-points qui sépare deux noms.
    let noms: [&[u8]; 3] = [b"from", b"to", b"subject"];
    let canon = Canonicalization::default();
    let mut corps = BodyHasher::new(canon.body, None);
    corps.update(CORPS);
    let (condensat, _) = corps.finish();
    // TOUTES les tailles : chaque écriture a sa borne, et celles qu'on ne
    // visite pas sont celles qui déborderont un jour.
    let mut complet = signataire(&noms, canon);
    complet.expiration = Some(1_732_003_600);
    complet.identity = Some(b"joe@example.com");
    let mut entiere = [0_u8; SIGNATURE_FIELD_MAX];
    let entier = complet
        .sign(&signe, &condensat, &CHAMPS, &mut entiere)
        .expect("signable")
        .len();
    for taille in 0..entier {
        let mut sortie = std::vec![0_u8; taille];
        assert_eq!(
            complet.sign(&signe, &condensat, &CHAMPS, &mut sortie),
            Err(Error::BufferTooSmall),
            "taille {taille}"
        );
    }
}

// ── LES CLÉS ────────────────────────────────────────────────────────────────

#[test]
fn une_cle_illisible_est_refusee() {
    for mauvaise in [&b""[..], b"pas du DER", &[0x30, 0x82, 0xFF, 0xFF]] {
        assert_eq!(
            SigningKey::rsa_from_pkcs8_der(mauvaise).err(),
            Some(Error::MalformedKey)
        );
    }
}

#[test]
fn chaque_cle_impose_son_algorithme() {
    assert_eq!(cle().algorithm(), Algorithm::RsaSha256);
    let ed = SigningKey::ed25519_from_seed(&[7_u8; 32]);
    assert_eq!(ed.algorithm(), Algorithm::Ed25519Sha256);
}

#[test]
fn une_signature_ed25519_se_verifie_aussi() {
    // RFC 8463. La clé publique se déduit de la graine, et c'est celle-là qu'un
    // `p=` publierait.
    let graine = [7_u8; 32];
    let ed = SigningKey::ed25519_from_seed(&graine);
    let condensat = [0x42_u8; DIGEST_LEN];
    let scellee = ed.sign(&condensat).expect("signable");
    assert_eq!(scellee.len(), 64);

    let publique = ed25519_dalek::SigningKey::from_bytes(&graine).verifying_key();
    assert_eq!(
        crate::verifier_la_signature(
            Algorithm::Ed25519Sha256,
            publique.as_bytes(),
            &condensat,
            &scellee
        ),
        Ok(())
    );
}

#[test]
fn signer_deux_fois_le_meme_condensat_rend_la_meme_signature() {
    // PKCS#1 v1.5 est déterministe, et Ed25519 aussi. C'est ce qui permet à ces
    // épreuves de comparer des octets.
    let condensat = [0x11_u8; DIGEST_LEN];
    assert_eq!(
        cle().sign(&condensat).expect("signable"),
        cle().sign(&condensat).expect("signable")
    );
}

/// **UN SERVEUR SIGNE AVEC AVEUGLEMENT**, et le champ qu'il écrit est le même :
/// l'aveuglement protège LA CLÉ, pas la signature. C'est ce qui permet de
/// l'employer sans rien changer d'autre.
#[test]
fn le_champ_signe_avec_aveuglement_est_le_meme() {
    let noms: [&[u8]; 2] = [b"from", b"subject"];
    let canon = Canonicalization {
        header: Canon::Relaxed,
        body: Canon::Relaxed,
    };
    let mut corps = BodyHasher::new(canon.body, None);
    corps.update(b"Bonjour.\r\n");
    let (condensat, _) = corps.finish();
    let signataire = signataire(&noms, canon);

    let mut sans = [0_u8; SIGNATURE_FIELD_MAX];
    let attendu = signataire
        .sign(&cle(), &condensat, &CHAMPS, &mut sans)
        .expect("signable");
    let mut avec = [0_u8; SIGNATURE_FIELD_MAX];
    let mut alea = AleaFixe(0x0f1e_2d3c_4b5a_6978);
    let vu = signataire
        .sign_with(&cle(), &condensat, &CHAMPS, &mut alea, &mut avec)
        .expect("signable");
    assert_eq!(vu, attendu);
}

#[test]
fn l_aveuglement_rend_la_meme_signature_qu_un_signataire_sans_alea() {
    // L'aveuglement protège LA CLÉ, pas la signature : le résultat est le même,
    // et c'est ce qui permet de l'employer sans rien changer d'autre.
    let condensat = [0x33_u8; DIGEST_LEN];
    let mut alea = AleaFixe(0x1234_5678_9abc_def0);
    assert_eq!(
        cle().sign_with(&condensat, &mut alea).expect("signable"),
        cle().sign(&condensat).expect("signable")
    );
    // Ed25519 ne s'en sert pas : il est déterministe par construction.
    let ed = SigningKey::ed25519_from_seed(&[9_u8; 32]);
    assert_eq!(
        ed.sign_with(&condensat, &mut alea).expect("signable"),
        ed.sign(&condensat).expect("signable")
    );
}

/// Un aléa d'épreuve : reproductible, et suffisant pour aveugler.
struct AleaFixe(u64);

impl rsa::rand_core::TryRng for AleaFixe {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::try_from(self.try_next_u64()? >> 32).unwrap_or(0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        // Un xorshift : ce n'est pas de l'aléa, c'est une suite reproductible —
        // et c'est exactement ce qu'une épreuve veut.
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        Ok(self.0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for morceau in dst.chunks_mut(8) {
            let octets = self.try_next_u64()?.to_be_bytes();
            let combien = morceau.len();
            morceau.copy_from_slice(octets.get(..combien).unwrap_or_default());
        }
        Ok(())
    }
}

impl rsa::rand_core::TryCryptoRng for AleaFixe {}

#[test]
fn les_nombres_s_ecrivent_en_decimal() {
    let mut tampon = [0_u8; 20];
    assert_eq!(decimal(0, &mut tampon), b"0");
    assert_eq!(decimal(1, &mut tampon), b"1");
    assert_eq!(decimal(1_732_000_000, &mut tampon), b"1732000000");
    assert_eq!(decimal(u64::MAX, &mut tampon), b"18446744073709551615");
}

/// La signature que notre code produit sur le message d'épreuve, en
/// `relaxed/relaxed`.
///
/// **OpenSSL l'a vérifiée**, contre un condensat recalculé par une
/// canonicalisation Python écrite séparément. Ce n'est donc pas un témoin de
/// notre propre code : c'est un tiers qui dit que ce qu'on écrit est vrai.
const SIGNATURE_ATTESTEE: &str = concat!(
    "qTUKmqyyvicCb2+CSKZR4eFvrm9XQdA61f/HeHRJkj+SI1On4AEDKAHd9wlLUYPe",
    "15Z2DnjyIriHkgQUD7edlDP6zaDkHd1Mgn+iwq9T63bmRaUUYYZ7AQwA4sQ+Up1c",
    "L541gANtAhsk7y8uK8VaX6vW5YzJwz1d4ahcr7pOsPFgSoKFnkPXsGL62/vW5Hnn",
    "of8JGQt4rzYxXScNx6B3a+QXBRk0BWqUXa1gsvHan1KmEoeAlBx9NC7/IkbEh673",
    "4wvUmVW6FB0eN4yx6XZbP0rA2o1Y8FEdhXmG9KCIF0cNMfzfnPa4nI/J/x8CJXnP",
    "LfJxHld7hVqnU42uJ0NVCQ==",
);

#[test]
fn la_signature_produite_est_celle_qu_openssl_verifie() {
    // L'ALLER-RETOUR NE SUFFIT PAS : si le signataire et le vérificateur se
    // trompaient de la même façon, il passerait quand même. Ce vecteur-ci vient
    // d'ailleurs — OpenSSL a vérifié cette signature contre un condensat
    // recalculé par une canonicalisation écrite séparément, en Python.
    let champ = signer(Canonicalization {
        header: Canon::Relaxed,
        body: Canon::Relaxed,
    });
    let plat = champ.replace("\r\n ", "");
    let rang = plat.rfind("b=").expect("le champ porte un `b=`");
    let produite = plat
        .get(rang.saturating_add(2)..)
        .expect("il y a quelque chose après")
        .trim_end();
    assert_eq!(produite, SIGNATURE_ATTESTEE, "{champ}");

    // Et le `bh=` est celui que la RFC 6376 annexe A publie pour ce corps.
    assert!(
        plat.contains("bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;"),
        "{plat}"
    );
}

#[test]
fn un_champ_plus_long_qu_une_ligne_est_refuse() {
    // Le pliage n'a lieu qu'AUX POINTS DE PLIAGE : une seule étiquette de mille
    // octets ne se plie nulle part, et le champ est refusé plutôt qu'émis
    // au-delà de ce qu'une ligne peut porter.
    let noms: [&[u8]; 1] = [b"from"];
    let canon = Canonicalization::default();
    let mut corps = BodyHasher::new(canon.body, None);
    corps.update(CORPS);
    let (condensat, _) = corps.finish();
    let long = std::vec![b'a'; 1000];
    let mut sortie = [0_u8; SIGNATURE_FIELD_MAX];
    let mut demesure = signataire(&noms, canon);
    demesure.domain = &long;
    assert_eq!(
        demesure.sign(&cle(), &condensat, &CHAMPS, &mut sortie),
        Err(Error::BufferTooSmall)
    );
}

#[test]
fn l_alea_qui_n_existe_pas_ne_rend_jamais_rien() {
    // `Option<&mut R>` veut un type même quand la valeur est `None` : celui-ci
    // en est un. Ses méthodes ne sont appelées par personne — c'est ce que
    // `None` veut dire — mais elles existent, et l'on éprouve qu'elles ne
    // rendent rien plutôt que d'affirmer qu'on ne les appelle pas.
    use rsa::rand_core::TryRng as _;
    let mut jamais = super::Jamais;
    assert!(jamais.try_next_u32().is_err());
    assert!(jamais.try_next_u64().is_err());
    assert!(jamais.try_fill_bytes(&mut [0_u8; 4]).is_err());
    let dit = std::format!("{}", super::PasDAlea);
    assert!(dit.contains("aléa"), "{dit}");
    assert!(!std::format!("{:?}", super::PasDAlea).is_empty());
}

#[test]
fn une_cle_trop_petite_pour_le_remplissage_ne_signe_pas() {
    // PKCS#1 v1.5 enveloppe le condensat : dix-neuf octets de préfixe, trente
    // deux de condensat, onze de remplissage au moins — soixante-deux en tout.
    // Une clé de 384 bits n'en porte que quarante-huit, et elle REFUSE de
    // signer plutôt que de tronquer. Une de 512 bits, elle, y arrive tout juste
    // — et c'est le vérificateur qui la refusera, pour une autre raison.
    // La clé est FABRIQUÉE À LA MAIN : `rsa` refuse d'en engendrer d'aussi
    // petites, et OpenSSL aussi. Elle est pourtant cohérente — `e·d ≡ 1` modulo
    // λ(n) — et c'est tout ce qu'il faut pour éprouver ce refus-là.
    let composantes = |valeur: u64| rsa::BoxedUint::from(valeur);
    let minuscule = rsa::RsaPrivateKey::from_components(
        composantes(1_000_036_000_099),
        composantes(65_537),
        composantes(149_902_609_889),
        std::vec![composantes(1_000_003), composantes(1_000_033)],
    )
    .expect("clé cohérente");
    let minuscule = SigningKey::Rsa(std::boxed::Box::new(minuscule));
    let mut alea = AleaFixe(0x0f1e_2d3c_4b5a_6978);
    assert_eq!(
        minuscule.sign(&[0x55_u8; DIGEST_LEN]),
        Err(Error::SignatureMismatch)
    );
    assert_eq!(
        minuscule.sign_with(&[0x55_u8; DIGEST_LEN], &mut alea),
        Err(Error::SignatureMismatch)
    );

    // Et le champ entier ne s'écrit pas davantage : une clé qui ne signe pas ne
    // produit pas de signature, et l'on n'en émet pas une vide.
    let noms: [&[u8]; 1] = [b"from"];
    let canon = Canonicalization::default();
    let mut corps = BodyHasher::new(canon.body, None);
    corps.update(CORPS);
    let (condensat, _) = corps.finish();
    let mut sortie = [0_u8; SIGNATURE_FIELD_MAX];
    assert_eq!(
        signataire(&noms, canon).sign(&minuscule, &condensat, &CHAMPS, &mut sortie),
        Err(Error::SignatureMismatch)
    );

    // Celle de 512 bits signe : la borne du vérificateur est ailleurs.
    let petite = SigningKey::rsa_from_pkcs8_der(&decode(CLE_512)).expect("clé lisible");
    let scellee = petite.sign(&[0x55_u8; DIGEST_LEN]).expect("signable");
    assert_eq!(
        crate::verifier_la_signature(
            Algorithm::RsaSha256,
            &decode(CLE_512_PUBLIQUE),
            &[0x55_u8; DIGEST_LEN],
            &scellee
        ),
        Err(Error::KeyTooSmall)
    );
}

#[test]
fn les_types_se_deboguent_et_se_copient() {
    let noms: [&[u8]; 1] = [b"from"];
    let signataire = signataire(&noms, Canonicalization::default());
    let copie = signataire;
    assert_eq!(copie.domain, signataire.domain);
    let rendu = std::format!("{signataire:?}");
    // Les octets s'affichent en nombres — c'est ce que `Debug` fait d'un
    // `&[u8]` — et le sélecteur est là, en toutes lettres décimales.
    assert!(rendu.contains("Signer {"), "{rendu}");
    assert!(rendu.contains("timestamp: Some(1732000000)"), "{rendu}");
}

#[test]
fn ce_qui_ne_peut_pas_s_ecrire_est_refuse() {
    // UN `d=` QUI PORTERAIT UN `CRLF` terminerait l'en-tête et en ouvrirait un
    // autre : c'est l'injection d'en-tête. Le fuzzing l'a trouvée en donnant au
    // signataire un domaine fait de deux points et de sauts de ligne.
    let noms: [&[u8]; 1] = [b"from"];
    let canon = Canonicalization::default();
    let mut corps = BodyHasher::new(canon.body, None);
    corps.update(CORPS);
    let (condensat, _) = corps.finish();
    let mut sortie = [0_u8; SIGNATURE_FIELD_MAX];

    let mechants: [&[u8]; 6] = [
        b"exemple\r\nX-Admin: oui",
        b"exemple\n",
        b"exemple ",
        b"exemple;",
        b"exemple\t",
        b"",
    ];
    for mechant in mechants {
        let mut avec = signataire(&noms, canon);
        avec.domain = mechant;
        assert_eq!(
            avec.sign(&cle(), &condensat, &CHAMPS, &mut sortie),
            Err(Error::MalformedTagValue),
            "d={}",
            std::string::String::from_utf8_lossy(mechant)
        );

        let mut avec = signataire(&noms, canon);
        avec.selector = mechant;
        assert_eq!(
            avec.sign(&cle(), &condensat, &CHAMPS, &mut sortie),
            Err(Error::MalformedTagValue),
            "s={}",
            std::string::String::from_utf8_lossy(mechant)
        );

        let mut avec = signataire(&noms, canon);
        avec.identity = Some(mechant);
        assert_eq!(
            avec.sign(&cle(), &condensat, &CHAMPS, &mut sortie),
            Err(Error::MalformedTagValue),
            "i={}",
            std::string::String::from_utf8_lossy(mechant)
        );
    }

    // Les noms de champ suivent `ftext` : ni blanc, ni deux-points — celui-ci
    // les sépare, et un nom qui en porte en nommerait deux.
    for mechant in [&b"from:to"[..], b"from ", b"", b"fr\rom"] {
        let mauvais: [&[u8]; 2] = [b"from", mechant];
        assert_eq!(
            signataire(&mauvais, canon).sign(&cle(), &condensat, &CHAMPS, &mut sortie),
            Err(Error::MalformedTagValue),
            "h={}",
            std::string::String::from_utf8_lossy(mechant)
        );
    }
}

// ── Lire une clé écrite par un administrateur ───────────────────────────────

/// Enveloppe un corps base64 dans un bloc PEM.
fn pem(etiquette: &str, corps: &str) -> std::string::String {
    std::format!("-----BEGIN {etiquette}-----\n{corps}\n-----END {etiquette}-----\n")
}

/// La même clé RSA que ci-dessus, au format PKCS#1 (`BEGIN RSA PRIVATE KEY`).
const CLE_PKCS1: &str = "MIIEogIBAAKCAQEAx6X1Z8atmh0Hi6UhKel/kQjPVpzANayrU7CW+Ds8LPQfHgnHu2xys6Telb\
     22NitOEcIL3BufK1wzm+6AXU42QbSxIXOlzwbiM1r6/1nzaLd0iGrrZyBIlAoAAE5jM/7Hh12P\
     gf5WFyV1fAfof1OcN5/jqs/PKIn12zer+nBX2XFRHUWeT9mBmCHe2LaP2mbEkeq3waiOvlGQ1N\
     9IrHPYeuiPlB3yAxBn9+FXI1lEamF7u4lVBNc921dGMxDZvE9XPNL9qHRRU8RHwhEeQjO4yVaL\
     GxNlmNOnIukKpdic/WyxcjiK951IEjVj2EOzPxd+N574bs57d9A8RmOa3uU9OQIDAQABAoIBAD\
     7PoSoRkSuDx4xxGsJvYkF0dprGvRgF527wh0a4iCGSejm+lPaL03hePeL5aRqYvDqNBKMuk4CW\
     ROxheEQip6I7YWDnW/qKrV6/2Gi+2XwP/5stnDr5JqxgiwiNoNtKZGbbkhsxM8+bat9nM4ffe6\
     3qYTurnn6gDNf3p2UmtBTF6XWxklmWHHTOM2OexFUCxduTPT/WkLYFGmdHNlefzc+brULkbFnc\
     8FnJqrZIfp/dUWDV3L2C+Zd2EzA/ejOmRfoXRC8peA0S+Ch3CjKl2je0vfwxVTEI9y4HCzrbb/\
     atKQf/0k9mqJ1IaaSol7xPMwevI1msljMTf7SWLVudrwMCgYEA+RddwavhZe77iM3lpNZtUC+D\
     Sw5GnosXTBOSffNdFWJnVrOJ5MHOuu6gCYw6JKPIH7bgvp/4H/dhhaUX4G6ZuzuIftMEM9loZf\
     zarPaOSIO0Aw3CJgac4UXIl6iupn0ehegD+hlP8Y9DRgfXXiBS/ySn6kOWBM1dfnmULHFhJzcC\
     gYEAzS+HsvuVWbLQTZB3b68BBhnRk+J/XRmfMXl1mH73t3NYyn3cw2UC2R9nsx3p52iinmk5th\
     ssau7I4PZuy+JV+sJ7QYljSWfFmGk53HS5XJxJcaxFC3gJ/FB7Oc7f9y7C8k5haKTUI30RAitB\
     hfjn2mB4Vj1ytW7cd3ZPKXjCFw8CgYAcxJ8WbBR3Ile4oBcCp6UuWp5uP7LWQrgpGCWWGFJK0v\
     eeYtPtMJkAq+id0a0xaB0H1KY2PeF5R6fiuIN+byegISsNgq98kYJmLQLQcRVTuKpEpAUlQSRD\
     PD0Djv7EybSJwJcc/mlmO6aIYwVzoIYVY5VlD/M2kMVYgxAi5eFTlwKBgCcKojFmOXbF1WjM0k\
     0H6ZP1mbEf6cgXNfk9+Sg5EH1xjzWIWVc8gxw5I4wrZvRHLpohv39tEDiQktxrR4231VBPbRB9\
     Sc0P18M2UnImK5b5jef5NXIHNy8xSSEowejQlvtv+ozkwBC4nWHiRSduwv8EWCFgs9Dd9Ukt08\
     Y6WgP1AoGAS+T8xA9qmCRsVXuUBlygcsmRrRPhTmqSOeyu5P0bc0IxHwqX6ZawjTTDOPlEX0uz\
     n5H/tdITfAmCzfZWdEZ9P6h5fxODGm5ZGNj0y55VYoKRzP9k3Xe41PvTPgvpp/NriSNgruOAi+\
     AiySH2AylZXADTKRVIy3UA519GQQcx6VI=";

/// Une clé Ed25519 jetable, en PKCS#8 v1 (RFC 8410 §7).
const CLE_ED25519: &str = "MC4CAQAwBQYDK2VwBCIEIPycWR71gsJjQjlyixhg1EFwd/RmkyoHfIBubnK3v8rE";

/// **C'EST L'ÉTIQUETTE QUI DIT LE FORMAT** : PKCS#8 et PKCS#1 se lisent tous
/// deux, et chacun par le chemin que son bloc annonce.
#[test]
fn les_deux_formats_de_cle_se_lisent() {
    let pkcs8 = SigningKey::from_pem(pem("PRIVATE KEY", CLE_PRIVEE).as_bytes()).expect("PKCS#8");
    assert_eq!(pkcs8.algorithm(), Algorithm::RsaSha256);
    let pkcs1 = SigningKey::from_pem(pem("RSA PRIVATE KEY", CLE_PKCS1).as_bytes()).expect("PKCS#1");
    assert_eq!(pkcs1.algorithm(), Algorithm::RsaSha256);
    // Et c'est bien la MÊME clé : elle signe pareil.
    let condensat = [0x42_u8; DIGEST_LEN];
    assert_eq!(
        pkcs8.sign(&condensat).expect("signable"),
        pkcs1.sign(&condensat).expect("signable")
    );
}

/// Une clé Ed25519 se reconnaît à ses quarante-huit octets et à son préfixe.
#[test]
fn une_cle_ed25519_se_reconnait() {
    let cle = SigningKey::from_pem(pem("PRIVATE KEY", CLE_ED25519).as_bytes()).expect("Ed25519");
    assert_eq!(cle.algorithm(), Algorithm::Ed25519Sha256);
    // Elle signe comme celle qu'on aurait construite depuis sa graine.
    let mut graine = [0_u8; 32];
    let der = decode(CLE_ED25519);
    graine.copy_from_slice(der.get(16..48).expect("graine"));
    let condensat = [0x11_u8; DIGEST_LEN];
    assert_eq!(
        cle.sign(&condensat).expect("signable"),
        SigningKey::ed25519_from_seed(&graine)
            .sign(&condensat)
            .expect("signable")
    );
}

/// Ce qui n'est pas une clé le dit, et ne devine rien.
#[test]
fn ce_qui_n_est_pas_une_cle_le_dit() {
    for mechant in [
        std::string::String::from("pas de PEM du tout"),
        // Un bloc qui ne se ferme pas.
        std::format!("-----BEGIN PRIVATE KEY-----\n{CLE_ED25519}\n"),
        // Une étiquette qui ne se ferme pas non plus.
        std::string::String::from("-----BEGIN PRIVATE KEY"),
        // Une étiquette qu'on ne sert pas : on ne devine pas le format.
        pem("EC PRIVATE KEY", CLE_ED25519),
        pem("CERTIFICATE", CLE_PRIVEE),
        // Du base64 qui n'est pas du DER.
        pem("PRIVATE KEY", "AAAA"),
        pem("RSA PRIVATE KEY", "AAAA"),
        // Un préfixe Ed25519 sans sa graine.
        pem("PRIVATE KEY", "MC4CAQAwBQYDK2Vw"),
    ] {
        assert_eq!(
            SigningKey::from_pem(mechant.as_bytes()).err(),
            Some(Error::MalformedKey),
            "{mechant}"
        );
    }
    // Et un corps plus long que ce qu'on retient : la taille du fichier sert à
    // BORNER, jamais à réserver.
    let enorme = pem("PRIVATE KEY", &"A".repeat(64 * 1024));
    assert!(SigningKey::from_pem(enorme.as_bytes()).is_err());
}
