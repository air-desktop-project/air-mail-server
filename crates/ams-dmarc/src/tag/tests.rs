//! Ce que la grammaire des listes DMARC doit tenir.

use super::{Tag, Tags};
use crate::Error;

fn lire(enregistrement: &[u8]) -> Result<std::vec::Vec<Tag<'_>>, Error> {
    Tags::new(enregistrement).collect()
}

fn couple<'a>(nom: &'a str, valeur: &'a str) -> Tag<'a> {
    Tag {
        name: nom.as_bytes(),
        value: valeur.as_bytes(),
    }
}

#[test]
fn un_enregistrement_ordinaire_se_lit() {
    let lues = lire(b"v=DMARC1; p=reject; pct=100").expect("lisible");
    assert_eq!(
        lues,
        [
            couple("v", "DMARC1"),
            couple("p", "reject"),
            couple("pct", "100")
        ]
    );
}

#[test]
fn le_point_virgule_final_est_permis() {
    // Bien des enregistrements réels l'écrivent, et le refuser ferait échouer
    // des politiques par ailleurs correctes.
    assert_eq!(
        lire(b"v=DMARC1; p=none;").expect("lisible"),
        [couple("v", "DMARC1"), couple("p", "none")]
    );
    assert_eq!(
        lire(b"v=DMARC1; p=none;  ").expect("lisible"),
        [couple("v", "DMARC1"), couple("p", "none")]
    );
}

#[test]
fn une_etiquette_vide_au_milieu_est_une_faute() {
    assert_eq!(lire(b"v=DMARC1;; p=none"), Err(Error::MalformedTagList));
    assert_eq!(lire(b"; v=DMARC1"), Err(Error::MalformedTagList));
}

#[test]
fn les_blancs_ne_comptent_pas() {
    let lues = lire(b"  v = DMARC1 ;\tp\t=\tnone\t").expect("lisible");
    assert_eq!(lues, [couple("v", "DMARC1"), couple("p", "none")]);
}

#[test]
fn une_liste_de_rapports_porte_des_uri() {
    // `rua=` transporte des `mailto:` séparés par des virgules — ni DKIM ni SPF
    // n'ont rien de tel, et c'est une des raisons pour lesquelles cette
    // grammaire est la sienne.
    let lues = lire(b"v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.net!10m")
        .expect("lisible");
    assert_eq!(
        lues[2],
        couple("rua", "mailto:a@example.com,mailto:b@example.net!10m")
    );
}

#[test]
fn une_valeur_peut_etre_vide() {
    assert_eq!(
        lire(b"v=DMARC1; p=none; rua=").expect("lisible")[2],
        couple("rua", "")
    );
}

#[test]
fn un_nom_d_etiquette_commence_par_une_lettre() {
    assert_eq!(lire(b"1=x"), Err(Error::MalformedTagName));
    assert_eq!(lire(b"=x"), Err(Error::MalformedTagName));
    assert_eq!(lire(b"a-b=x"), Err(Error::MalformedTagName));
    assert_eq!(lire(b"a_1=x").expect("lisible"), [couple("a_1", "x")]);
}

#[test]
fn une_etiquette_sans_signe_egal_est_une_faute() {
    assert_eq!(lire(b"v=DMARC1; oups"), Err(Error::MalformedTagList));
}

#[test]
fn un_octet_de_controle_n_est_pas_une_valeur() {
    for mechant in [&b"v=\x01"[..], b"v=\x7f", b"v=DMARC1\r\np=none"] {
        assert_eq!(
            lire(mechant),
            Err(Error::MalformedTagValue),
            "{}",
            std::string::String::from_utf8_lossy(mechant)
        );
    }
}

#[test]
fn une_liste_vide_ne_porte_aucune_etiquette() {
    assert!(lire(b"").expect("lisible").is_empty());
    assert!(lire(b"   ").expect("lisible").is_empty());
    assert!(lire(b";").expect("lisible").is_empty());
}

#[test]
fn les_types_se_deboguent_et_se_comparent() {
    let lecture = Tags::new(b"v=DMARC1");
    assert!(!std::format!("{lecture:?}").is_empty());
    let tag = couple("v", "DMARC1");
    assert!(!std::format!("{tag:?}").is_empty());
    assert_eq!(tag, couple("v", "DMARC1"));
    assert_ne!(tag, couple("v", "DMARC2"));
    let copie = tag;
    assert_eq!(copie.name, tag.name);
}
