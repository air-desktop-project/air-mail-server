//! Ce qu'un champ d'identifiants rend.

use super::message_ids;

fn ids(valeur: &[u8]) -> std::vec::Vec<&[u8]> {
    message_ids(valeur).collect()
}

#[test]
fn les_identifiants_se_rendent_sans_chevrons() {
    assert_eq!(ids(b" <a@b.test>"), [&b"a@b.test"[..]]);
    assert_eq!(
        ids(b"<un@x.test>\r\n <deux@x.test> <trois@x.test>"),
        [&b"un@x.test"[..], b"deux@x.test", b"trois@x.test"]
    );
    // Collés, sans blanc entre eux : §3.6.4 l'admet.
    assert_eq!(ids(b"<un@x><deux@x>"), [&b"un@x"[..], b"deux@x"]);
}

#[test]
fn ce_qui_n_est_pas_un_identifiant_est_saute() {
    assert!(ids(b"").is_empty());
    assert!(ids(b"votre message du 3 mars").is_empty());
    // Vide, avec un blanc, ou hors de l'ASCII imprimable.
    assert_eq!(ids(b"<> <a b@x> <\xc3\xa9@x> <ok@x>"), [&b"ok@x"[..]]);
    // Un chevron que rien ne ferme arrête tout.
    assert_eq!(ids(b"<ok@x> <perdu@x"), [&b"ok@x"[..]]);
    // Le texte autour ne compte pas.
    assert_eq!(ids(b"Jean <jean@x> (commentaire)"), [&b"jean@x"[..]]);
}
