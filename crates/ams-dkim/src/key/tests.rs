//! Ce qu'un enregistrement de clé publique doit tenir.

use super::{KeyType, PublicKeyRecord};
use crate::Error;
use crate::signature::Algorithm;

fn lire(valeur: &[u8]) -> Result<PublicKeyRecord<'_>, Error> {
    PublicKeyRecord::parse(valeur)
}

#[test]
fn un_enregistrement_ordinaire_se_lit() {
    let cle = lire(b"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQ==").expect("lisible");
    assert_eq!(cle.key_type, KeyType::Rsa);
    assert_eq!(cle.key, b"MIGfMA0GCSqGSIb3DQ==");
    assert_eq!(cle.hashes, None);
    assert!(!cle.testing);
    assert!(!cle.strict_identity);
}

#[test]
fn le_type_par_defaut_est_rsa() {
    // C'est le défaut de la RFC : un enregistrement sans `k=` publie une clé
    // RSA, et en déduire autre chose ferait échouer la vérification.
    let cle = lire(b"v=DKIM1; p=AAAA").expect("lisible");
    assert_eq!(cle.key_type, KeyType::Rsa);
    assert_eq!(KeyType::default(), KeyType::Rsa);
}

#[test]
fn la_version_est_facultative_mais_verifiee() {
    // Absente, c'est licite — bien des enregistrements ne l'écrivent pas.
    assert!(lire(b"p=AAAA").is_ok());
    // Présente et autre : un format qu'on ne connaît pas ne se lit pas
    // « au mieux ».
    assert_eq!(lire(b"v=DKIM2; p=AAAA"), Err(Error::NotDkimKey));
    // La casse ne compte pas.
    assert!(lire(b"v=dkim1; p=AAAA").is_ok());
}

#[test]
fn une_cle_vide_est_une_revocation() {
    // §3.6.1 : ce n'est pas une faute de forme, c'est une déclaration. Le
    // détenteur du domaine dit que cette clé ne doit plus rien signer, et la
    // traiter comme un enregistrement illisible reviendrait à l'ignorer.
    assert_eq!(lire(b"v=DKIM1; p="), Err(Error::RevokedKey));
    assert_eq!(lire(b"v=DKIM1; k=rsa; p=; t=y"), Err(Error::RevokedKey));
}

#[test]
fn une_cle_absente_n_est_pas_une_cle() {
    assert_eq!(lire(b"v=DKIM1; k=rsa"), Err(Error::MissingTag("p")));
}

#[test]
fn les_deux_types_de_cle_se_lisent_sans_casse() {
    assert_eq!(
        lire(b"k=ED25519; p=AAAA").expect("lisible").key_type,
        KeyType::Ed25519
    );
    assert_eq!(KeyType::parse(b"dsa"), Err(Error::UnsupportedKeyType));
    // Et la faute remonte depuis l'enregistrement entier, pas seulement de
    // l'analyseur du type.
    assert_eq!(
        lire(b"v=DKIM1; k=dsa; p=AAAA"),
        Err(Error::UnsupportedKeyType)
    );
}

#[test]
fn un_service_qui_n_est_pas_le_courrier_est_refuse() {
    // S'en servir pour du courrier serait employer une clé hors de l'usage que
    // son détenteur a déclaré.
    assert!(lire(b"p=AAAA; s=email").is_ok());
    assert!(lire(b"p=AAAA; s=*").is_ok());
    assert!(lire(b"p=AAAA; s=tlsa:email").is_ok());
    assert!(lire(b"p=AAAA; s= EMAIL ").is_ok());
    assert_eq!(lire(b"p=AAAA; s=tlsa"), Err(Error::NotForEmail));
    // Absent, le défaut est `*` : tous les services.
    assert!(lire(b"p=AAAA").is_ok());
}

#[test]
fn les_drapeaux_se_lisent() {
    let essai = lire(b"p=AAAA; t=y").expect("lisible");
    assert!(essai.testing);
    assert!(!essai.strict_identity);

    let stricte = lire(b"p=AAAA; t=s").expect("lisible");
    assert!(!stricte.testing);
    assert!(stricte.strict_identity);

    let deux = lire(b"p=AAAA; t=y:s").expect("lisible");
    assert!(deux.testing);
    assert!(deux.strict_identity);

    // Les blancs autour des deux-points ne comptent pas, ni la casse.
    let espaces = lire(b"p=AAAA; t= Y : S ").expect("lisible");
    assert!(espaces.testing && espaces.strict_identity);

    // Un drapeau inconnu s'ignore, comme le veut §3.6.1.
    let inconnu = lire(b"p=AAAA; t=z").expect("lisible");
    assert!(!inconnu.testing && !inconnu.strict_identity);
}

#[test]
fn la_liste_des_condensats_restreint_ce_que_la_cle_couvre() {
    // Absente, elle les accepte tous. Présente, elle décide — et passer outre
    // reviendrait à décider à la place du détenteur du domaine.
    let sans = lire(b"p=AAAA").expect("lisible");
    assert!(sans.accepts(Algorithm::RsaSha256));

    let avec = lire(b"p=AAAA; h=sha256").expect("lisible");
    assert!(avec.accepts(Algorithm::RsaSha256));

    let autre = lire(b"p=AAAA; h=sha1").expect("lisible");
    assert!(!autre.accepts(Algorithm::RsaSha256));

    let liste = lire(b"p=AAAA; h=sha1 : SHA256").expect("lisible");
    assert!(liste.accepts(Algorithm::Ed25519Sha256));
    assert_eq!(liste.hashes, Some(&b"sha1 : SHA256"[..]));
}

#[test]
fn le_type_de_cle_doit_aller_avec_l_algorithme() {
    // Une clé RSA ne vérifie pas une signature Ed25519, et l'essayer quand même
    // ne rendrait pas « faux » mais « illisible » — ce qui se confond trop
    // facilement avec une panne.
    let rsa = lire(b"k=rsa; p=AAAA").expect("lisible");
    assert!(rsa.matches(Algorithm::RsaSha256));
    assert!(!rsa.matches(Algorithm::Ed25519Sha256));

    let ed = lire(b"k=ed25519; p=AAAA").expect("lisible");
    assert!(ed.matches(Algorithm::Ed25519Sha256));
    assert!(!ed.matches(Algorithm::RsaSha256));
}

#[test]
fn une_etiquette_en_double_est_refusee() {
    for doublon in ["v=DKIM1", "k=rsa", "p=AAAA", "h=sha256", "s=email", "t=y"] {
        let valeur = std::format!("v=DKIM1; p=AAAA; {doublon}; {doublon}");
        assert_eq!(
            lire(valeur.as_bytes()),
            Err(Error::DuplicateTag),
            "{doublon}"
        );
    }
}

#[test]
fn une_note_et_les_etiquettes_inconnues_s_ignorent() {
    let cle = lire(b"v=DKIM1; p=AAAA; n=pour l'administrateur; futur=demain").expect("lisible");
    assert_eq!(cle.key, b"AAAA");
}

#[test]
fn la_cle_se_rend_sans_ses_blancs() {
    // Un `p=` réel est plié : les blancs n'en font pas partie.
    let cle = lire(b"v=DKIM1; p=MIGf\r\n MA0G").expect("lisible");
    let mut tampon = [0_u8; 32];
    assert_eq!(cle.key_base64(&mut tampon).expect("tient"), b"MIGfMA0G");
    let mut minuscule = [0_u8; 4];
    assert_eq!(cle.key_base64(&mut minuscule), Err(Error::BufferTooSmall));
}

#[test]
fn une_liste_mal_formee_remonte_telle_quelle() {
    assert_eq!(lire(b"v=DKIM1;;p=AAAA"), Err(Error::MalformedTagList));
    assert_eq!(lire(b"1=x"), Err(Error::MalformedTagName));
}

#[test]
fn les_types_se_deboguent_et_se_comparent() {
    let cle = lire(b"p=AAAA").expect("lisible");
    let copie = cle;
    assert_eq!(copie, cle);
    assert!(!std::format!("{cle:?}").is_empty());
    assert!(!std::format!("{:?}", KeyType::Ed25519).is_empty());
    assert_ne!(KeyType::Rsa, KeyType::Ed25519);
}
