//! Ce qu'un `TLSA` autorise, et ce qu'il refuse d'autoriser.

use super::{Match, Matching, Selector, Tlsa, Usage};
use sha2::{Digest as _, Sha256, Sha512};

/// De vrais certificats, fabriqués une fois — voir `vecteurs/README.md`.
pub(crate) const FEUILLE: &[u8] = include_bytes!("../../vecteurs/leaf.der");
pub(crate) const AUTORITE: &[u8] = include_bytes!("../../vecteurs/ca.der");

/// **LES EMPREINTES DE RÉFÉRENCE VIENNENT D'`openssl`**, et non de ce code.
///
/// Les calculer ici avec `Sha256::digest(subject_public_key_info(…))` rendrait
/// l'essai circulaire : un extracteur qui rendrait la mauvaise tranche
/// passerait, puisque les deux côtés se tromperaient de la même façon. Ces
/// quatre valeurs sont ce qu'une autre implémentation calcule sur les mêmes
/// octets, et `vecteurs/README.md` dit comment les refaire.
const FEUILLE_CLEF_SHA256: &str =
    "2e33cf366868663c12573145506fdf1173cb360294fcca9b361cbdc8d7aaffe2";
const FEUILLE_CERT_SHA256: &str =
    "87cdb56c098d8e38651770ad13df992bf964d016488c718421bc3312b9dd2990";
const AUTORITE_CLEF_SHA256: &str =
    "8b48daf37bbecb619ce29fb512d662ac553d9f8fc6c11ded18b3ef0305b08cec";

/// Des octets écrits en hexadécimal.
pub(crate) fn octets(hexa: &str) -> std::vec::Vec<u8> {
    hexa.as_bytes()
        .chunks(2)
        .map(|paire| {
            let texte = std::str::from_utf8(paire).expect("de l'ASCII");
            u8::from_str_radix(texte, 16).expect("de l'hexadécimal")
        })
        .collect()
}

/// Le `RDATA` d'un `TLSA` : trois octets, puis la donnée.
pub(crate) fn rdata(usage: u8, selecteur: u8, appariement: u8, donnee: &[u8]) -> std::vec::Vec<u8> {
    let mut octets = std::vec![usage, selecteur, appariement];
    octets.extend_from_slice(donnee);
    octets
}

/// **CE QU'UNE AUTRE IMPLÉMENTATION CALCULE, ON LE CALCULE AUSSI.**
///
/// C'est l'essai qui ancre tout le reste : si l'empreinte de la clef ne
/// s'accordait pas avec celle d'`openssl`, chaque `3 1 1` du monde serait refusé
/// et l'on ne le saurait qu'en production.
#[test]
fn les_empreintes_s_accordent_avec_openssl() {
    let clef = rdata(3, 1, 1, &octets(FEUILLE_CLEF_SHA256));
    assert!(Tlsa::parse(&clef).expect("bien formé").matches(FEUILLE));

    let certificat = rdata(3, 0, 1, &octets(FEUILLE_CERT_SHA256));
    assert!(
        Tlsa::parse(&certificat)
            .expect("bien formé")
            .matches(FEUILLE)
    );

    let autorite = rdata(2, 1, 1, &octets(AUTORITE_CLEF_SHA256));
    assert!(
        Tlsa::parse(&autorite)
            .expect("bien formé")
            .matches(AUTORITE)
    );

    // ET CHACUNE NE DÉSIGNE QUE LE SIEN.
    assert!(!Tlsa::parse(&clef).expect("bien formé").matches(AUTORITE));
    assert!(!Tlsa::parse(&autorite).expect("bien formé").matches(FEUILLE));
}

/// **LE SÉLECTEUR CHANGE CE QU'ON COMPARE**, et confondre les deux ferait
/// refuser tous les `3 1 1` — c'est-à-dire la quasi-totalité de ce qui est
/// publié.
#[test]
fn le_selecteur_decide_de_ce_qui_est_hache() {
    let sur_la_clef = rdata(3, 1, 1, &octets(FEUILLE_CLEF_SHA256));
    let sur_le_certificat = rdata(3, 0, 1, &octets(FEUILLE_CERT_SHA256));
    // L'empreinte du certificat ne satisfait pas un enregistrement sur la clef.
    let croise = rdata(3, 1, 1, &octets(FEUILLE_CERT_SHA256));
    assert!(!Tlsa::parse(&croise).expect("bien formé").matches(FEUILLE));
    // Ni l'inverse.
    let croise = rdata(3, 0, 1, &octets(FEUILLE_CLEF_SHA256));
    assert!(!Tlsa::parse(&croise).expect("bien formé").matches(FEUILLE));
    // Les deux bons, eux, passent.
    assert!(
        Tlsa::parse(&sur_la_clef)
            .expect("bien formé")
            .matches(FEUILLE)
    );
    assert!(
        Tlsa::parse(&sur_le_certificat)
            .expect("bien formé")
            .matches(FEUILLE)
    );
}

#[test]
fn un_enregistrement_se_decode_en_trois_champs() {
    let octets = rdata(3, 1, 1, &Sha256::digest(FEUILLE));
    let record = Tlsa::parse(&octets).expect("bien formé");
    assert_eq!(record.usage(), Usage::EndEntity);
    assert_eq!(record.selector(), Selector::PublicKey);
    assert_eq!(record.matching(), Matching::Sha256);
    assert_eq!(record.data().len(), 32);
    assert!(record.usable());
    assert_eq!(record.requirement(), Some(Match::LeafOnly));
}

#[test]
fn les_quatre_appariements_se_calculent_ou_se_refusent() {
    // `3 0 0` : le certificat entier, tel quel.
    let exact = rdata(3, 0, 0, FEUILLE);
    let record = Tlsa::parse(&exact).expect("bien formé");
    assert_eq!(record.matching(), Matching::Exact);
    assert!(record.matches(FEUILLE));
    assert!(!record.matches(AUTORITE));

    // `3 1 2` : SHA-512 de la clef.
    let clef = crate::subject_public_key_info(FEUILLE).expect("une clef");
    let sha512 = rdata(3, 1, 2, &Sha512::digest(clef));
    let record = Tlsa::parse(&sha512).expect("bien formé");
    assert_eq!(record.matching(), Matching::Sha512);
    assert!(record.matches(FEUILLE));
    assert!(!record.matches(AUTORITE));

    // `3 1 9` : un algorithme qu'on ne sait pas calculer.
    let inconnu = rdata(3, 1, 9, &[0xab; 32]);
    let record = Tlsa::parse(&inconnu).expect("bien formé");
    assert_eq!(record.matching(), Matching::Unusable(9));
    assert!(!record.usable());
    assert_eq!(record.requirement(), None);
}

/// **`PKIX-TA(0)` ET `PKIX-EE(1)` NE S'APPLIQUENT PAS À SMTP.**
///
/// §3.1.3 de RFC 7672. Ils demanderaient une validation WebPKI contre un nom qui
/// vient du DNS — ce que DANE existe précisément pour ne plus avoir à faire.
#[test]
fn les_usages_pkix_sont_inutilisables_pour_smtp() {
    for usage in [0_u8, 1, 7] {
        let octets = rdata(usage, 1, 1, &octets(FEUILLE_CLEF_SHA256));
        let record = Tlsa::parse(&octets).expect("bien formé");
        assert_eq!(record.usage(), Usage::Unusable(usage));
        assert!(!record.usable(), "l'usage {usage} aurait dû être écarté");
        assert_eq!(record.requirement(), None);
        // **ET IL NE CORRESPOND À RIEN**, surtout pas à tout : rendre `true`
        // ferait d'un usage inconnu un laissez-passer — alors même que son
        // empreinte est ici la bonne.
        assert!(!record.matches(FEUILLE));
    }
}

/// **UNE EMPREINTE DE LA MAUVAISE LONGUEUR N'EST PAS UNE EMPREINTE.**
///
/// La comparer à moitié serait pire que de l'ignorer : un `3 1 1` de quatre
/// octets serait satisfait par un certificat sur seize millions.
#[test]
fn une_empreinte_de_la_mauvaise_longueur_est_inutilisable() {
    for (appariement, longueur) in [
        (1_u8, 31_usize),
        (1, 33),
        (2, 63),
        (2, 65),
        (1, 64),
        (2, 32),
    ] {
        let octets = rdata(3, 1, appariement, &std::vec![0xab; longueur]);
        let record = Tlsa::parse(&octets).expect("bien formé");
        assert!(
            !record.usable(),
            "appariement {appariement} sur {longueur} octets"
        );
        assert!(!record.matches(FEUILLE));
    }
    // Les deux bonnes longueurs, elles, passent.
    for (appariement, longueur) in [(1_u8, 32_usize), (2, 64)] {
        let octets = rdata(3, 1, appariement, &std::vec![0xab; longueur]);
        assert!(Tlsa::parse(&octets).expect("bien formé").usable());
    }
}

#[test]
fn un_selecteur_inconnu_est_inutilisable() {
    let octets = rdata(3, 5, 1, &octets(FEUILLE_CLEF_SHA256));
    let record = Tlsa::parse(&octets).expect("bien formé");
    assert_eq!(record.selector(), Selector::Unusable(5));
    assert!(!record.usable());
    assert!(!record.matches(FEUILLE));
}

/// **UN CERTIFICAT DONT ON NE SAIT PAS TIRER LA CLEF NE SATISFAIT RIEN.**
///
/// Se rabattre sur le certificat entier ferait comparer une empreinte de clef à
/// autre chose qu'une clef.
#[test]
fn un_certificat_illisible_ne_satisfait_aucun_selecteur_de_clef() {
    let pas_un_certificat = b"ceci n'est pas du DER";
    let sur_la_clef = rdata(3, 1, 1, &Sha256::digest(pas_un_certificat));
    assert!(
        !Tlsa::parse(&sur_la_clef)
            .expect("bien formé")
            .matches(pas_un_certificat)
    );
    // Alors qu'un enregistrement sur le CERTIFICAT, lui, n'a rien à extraire.
    let sur_le_certificat = rdata(3, 0, 1, &Sha256::digest(pas_un_certificat));
    assert!(
        Tlsa::parse(&sur_le_certificat)
            .expect("bien formé")
            .matches(pas_un_certificat)
    );
}

/// **L'AUTORITÉ ET L'ENTITÉ FINALE NE SE VÉRIFIENT PAS PAREIL.**
#[test]
fn l_autorite_demande_autre_chose_que_l_entite_finale() {
    let ancre = rdata(2, 1, 1, &octets(AUTORITE_CLEF_SHA256));
    let record = Tlsa::parse(&ancre).expect("bien formé");
    assert_eq!(record.usage(), Usage::TrustAnchor);
    assert_eq!(record.requirement(), Some(Match::Anchor));
    assert!(record.matches(AUTORITE));

    let feuille = rdata(3, 1, 1, &octets(FEUILLE_CLEF_SHA256));
    let record = Tlsa::parse(&feuille).expect("bien formé");
    assert_eq!(record.requirement(), Some(Match::LeafOnly));
}

#[test]
fn ce_qui_n_est_pas_un_enregistrement_est_refuse() {
    // Moins de quatre octets : il manque au moins la donnée.
    for court in [&b""[..], b"\x03", b"\x03\x01", b"\x03\x01\x01"] {
        assert_eq!(Tlsa::parse(court), None, "{court:?}");
    }
    // Quatre octets, dont un de donnée : c'est le plus petit qui existe.
    assert!(Tlsa::parse(b"\x03\x01\x00\xff").is_some());
}

#[test]
fn les_codes_se_rendent_tels_qu_ils_arrivent() {
    assert_eq!(Usage::TrustAnchor.code(), 2);
    assert_eq!(Usage::EndEntity.code(), 3);
    assert_eq!(Usage::Unusable(0).code(), 0);
    assert_eq!(Selector::Certificate.code(), 0);
    assert_eq!(Selector::PublicKey.code(), 1);
    assert_eq!(Selector::Unusable(9).code(), 9);
    assert_eq!(Matching::Exact.code(), 0);
    assert_eq!(Matching::Sha256.code(), 1);
    assert_eq!(Matching::Sha512.code(), 2);
    assert_eq!(Matching::Unusable(4).code(), 4);
}

#[test]
fn les_types_se_copient_et_se_deboguent() {
    let feuille = rdata(3, 1, 1, &octets(FEUILLE_CLEF_SHA256));
    let record = Tlsa::parse(&feuille).expect("bien formé");
    let copie = record;
    assert_eq!(copie, record);
    assert!(!std::format!("{record:?}").is_empty());
    assert!(!std::format!("{:?}", Match::Anchor).is_empty());
    assert_ne!(Match::Anchor, Match::LeafOnly);
    assert_ne!(Usage::EndEntity, Usage::TrustAnchor);
    assert_ne!(Selector::Certificate, Selector::PublicKey);
    assert_ne!(Matching::Sha256, Matching::Sha512);
    let ancre = rdata(2, 1, 1, &octets(AUTORITE_CLEF_SHA256));
    assert_ne!(Tlsa::parse(&ancre).expect("bien formé"), record);
}
