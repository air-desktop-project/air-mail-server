//! Ce que la grammaire des listes `tag=valeur` doit tenir.

use super::{Tag, Tags, elaguer, sans_blancs};
use crate::Error;

/// Lit une liste entière, ou rend la première faute.
fn lire(liste: &[u8]) -> Result<std::vec::Vec<Tag<'_>>, Error> {
    Tags::new(liste).collect()
}

fn couple<'a>(nom: &'a str, valeur: &'a str) -> Tag<'a> {
    Tag {
        name: nom.as_bytes(),
        value: valeur.as_bytes(),
    }
}

#[test]
fn une_liste_ordinaire_se_lit() {
    let lues = lire(b"v=1; a=rsa-sha256; d=example.com").expect("lisible");
    assert_eq!(
        lues,
        [
            couple("v", "1"),
            couple("a", "rsa-sha256"),
            couple("d", "example.com")
        ]
    );
}

#[test]
fn le_point_virgule_final_est_permis() {
    // `tag-list = tag-spec *( ";" tag-spec ) [ ";" ]` : le dernier est optionnel,
    // et bien des signataires l'écrivent.
    assert_eq!(lire(b"v=1;").expect("lisible"), [couple("v", "1")]);
    assert_eq!(
        lire(b"v=1; a=rsa-sha256;  ").expect("lisible"),
        [couple("v", "1"), couple("a", "rsa-sha256")]
    );
}

#[test]
fn une_etiquette_vide_au_milieu_est_une_faute() {
    // On ne devine pas ce que son auteur voulait écrire.
    assert_eq!(lire(b"v=1;; a=rsa-sha256"), Err(Error::MalformedTagList));
    assert_eq!(lire(b"; v=1"), Err(Error::MalformedTagList));
}

#[test]
fn une_liste_vide_ne_porte_aucune_etiquette() {
    assert!(lire(b"").expect("lisible").is_empty());
    assert!(lire(b"   ").expect("lisible").is_empty());
    assert!(lire(b";").expect("lisible").is_empty());
}

#[test]
fn les_blancs_autour_du_signe_egal_ne_comptent_pas() {
    // `tag-spec = [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]`.
    let lues = lire(b"  v = 1 ;\r\n\ta\t=\trsa-sha256\r\n ").expect("lisible");
    assert_eq!(lues, [couple("v", "1"), couple("a", "rsa-sha256")]);
}

#[test]
fn les_blancs_internes_restent_dans_la_valeur() {
    // La grammaire les admet entre deux morceaux, et c'est à chaque étiquette de
    // dire ce qu'elle en fait : `b=` les ignore, `z=` les garde.
    let lues = lire(b"h=from :\r\n to : subject").expect("lisible");
    assert_eq!(lues, [couple("h", "from :\r\n to : subject")]);
}

#[test]
fn une_valeur_peut_etre_vide() {
    // `tag-value = [ tval *(...) ]` : la valeur vide est permise, et elle DIT
    // quelque chose — un `p=` vide révoque la clé.
    assert_eq!(lire(b"p=").expect("lisible"), [couple("p", "")]);
    assert_eq!(
        lire(b"v=DKIM1; p=;").expect("lisible"),
        [couple("v", "DKIM1"), couple("p", "")]
    );
}

#[test]
fn un_nom_d_etiquette_commence_par_une_lettre() {
    // `tag-name = ALPHA *ALNUMPUNC`.
    assert_eq!(lire(b"1=x"), Err(Error::MalformedTagName));
    assert_eq!(lire(b"_x=y"), Err(Error::MalformedTagName));
    assert_eq!(lire(b"=x"), Err(Error::MalformedTagName));
    assert_eq!(lire(b"a-b=x"), Err(Error::MalformedTagName));
    // Chiffres et souligné sont permis ENSUITE.
    assert_eq!(lire(b"a_1=x").expect("lisible"), [couple("a_1", "x")]);
}

#[test]
fn une_etiquette_sans_signe_egal_est_une_faute() {
    assert_eq!(lire(b"v=1; oups"), Err(Error::MalformedTagList));
}

#[test]
fn le_signe_egal_est_un_octet_de_valeur_recevable() {
    // C'EST L'ERRATUM 3192. L'ABNF exclut `=` de `VALCHAR`, son commentaire ne
    // l'exclut pas — et un `b=` en base64 finit par des `=` de remplissage.
    // Sous la première lecture, AUCUNE signature ne se lirait.
    let lues = lire(b"b=bXVzdA==").expect("lisible");
    assert_eq!(lues, [couple("b", "bXVzdA==")]);
}

#[test]
fn un_octet_hors_de_l_imprimable_est_refuse() {
    for mechant in [&b"v=\x01"[..], b"v=\x7f", b"v=\xe9"] {
        assert_eq!(
            lire(mechant),
            Err(Error::MalformedTagValue),
            "{}",
            std::string::String::from_utf8_lossy(mechant)
        );
    }
}

#[test]
fn elaguer_retire_les_quatre_blancs_et_rien_d_autre() {
    assert_eq!(elaguer(b" \t\r\nx\r\n\t "), b"x");
    assert_eq!(elaguer(b""), b"");
    assert_eq!(elaguer(b" \t "), b"");
    assert_eq!(elaguer(b"x"), b"x");
}

#[test]
fn sans_blancs_recolle_ce_que_le_pliage_a_coupe() {
    // Le base64 d'un `b=` peut être plié n'importe où : les blancs n'en font pas
    // partie, et les garder ferait échouer le décodage.
    let mut sortie = [0_u8; 32];
    assert_eq!(
        sans_blancs(b"bXVz\r\n dA==", &mut sortie).expect("tient"),
        b"bXVzdA=="
    );
    assert_eq!(sans_blancs(b"", &mut sortie).expect("tient"), b"");
}

#[test]
fn sans_blancs_refuse_plutot_que_de_tronquer() {
    // Une valeur tronquée se décoderait en AUTRE CHOSE, et cette autre chose
    // serait comparée à un condensat.
    let mut minuscule = [0_u8; 3];
    assert_eq!(
        sans_blancs(b"abcd", &mut minuscule),
        Err(Error::BufferTooSmall)
    );
    // Juste la place : rien n'est refusé pour rien.
    let mut juste = [0_u8; 4];
    assert_eq!(sans_blancs(b"a b c d", &mut juste).expect("tient"), b"abcd");
}

#[test]
fn les_types_se_deboguent_et_se_comparent() {
    let lecture = Tags::new(b"v=1");
    assert!(!std::format!("{lecture:?}").is_empty());
    let tag = couple("v", "1");
    assert!(!std::format!("{tag:?}").is_empty());
    assert_eq!(tag, couple("v", "1"));
    assert_ne!(tag, couple("v", "2"));
    let copie = tag;
    assert_eq!(copie.name, tag.name);
}
