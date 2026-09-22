// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce banc joue un VRAI CLIENT SCRAM contre ce module.
//!
//! Une implémentation éprouvée contre elle-même ne prouve que sa cohérence. Ici
//! le client calcule sa preuve par le chemin de `ams-sasl` — celui que le
//! vecteur de RFC 7677 valide —, et le serveur la vérifie par le sien.

use std::path::PathBuf;

use super::{Verificateurs, nombre};

const CLEF: [u8; 32] = [7; 32];

/// Monte un magasin jetable avec un compte, et rend le répertoire.
fn atelier(nom: &str, login: &str, mot_de_passe: &[u8]) -> (PathBuf, Verificateurs) {
    let repertoire = std::env::temp_dir().join(format!(
        "ams-scram-srv-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&repertoire);
    std::fs::create_dir_all(&repertoire).expect("répertoire");
    let chemin_clef = repertoire.join("scram.key");
    std::fs::write(&chemin_clef, CLEF).expect("clé");
    let chemin = repertoire.join("scram.bin");

    let v = ams_auth::scram_deriver(mot_de_passe, login, [3; 16], 4_096, [9; 12], &CLEF)
        .expect("dérivation");
    std::fs::write(&chemin, ams_config::encode_scram(&[v]).expect("encodage")).expect("magasin");
    let charge = Verificateurs::charger(&chemin_clef, chemin).expect("chargement");
    (repertoire, charge)
}

/// Le client : il calcule sa preuve comme un vrai client le ferait.
fn preuve_du_client(
    mot_de_passe: &[u8],
    bare: &[u8],
    server_first: &[u8],
    client_final_sans_preuve: &[u8],
    sel: &[u8],
    iterations: u32,
) -> [u8; 32] {
    let mut message = Vec::new();
    message.extend_from_slice(bare);
    message.push(b',');
    message.extend_from_slice(server_first);
    message.push(b',');
    message.extend_from_slice(client_final_sans_preuve);
    let salted = ams_sasl::derive_salted_password(mot_de_passe, sel, iterations);
    let ck = ams_sasl::client_key(&salted);
    ams_sasl::client_proof(&ck, &ams_sasl::stored_key(&ck), &message)
}

#[test]
fn un_vrai_client_ouvre_sa_session() {
    let (repertoire, serveur) = atelier("ouvre", "jean", b"ouvre-toi");

    // ── Le `server-first` ────────────────────────────────────────────────────
    let mut premier = [0_u8; 256];
    let ecrits = serveur
        .server_first(b"jean", b"nonceclient", b"noncesrv", &mut premier)
        .expect("server-first");
    let server_first = premier.get(..ecrits).expect("longueur");
    let texte = String::from_utf8_lossy(server_first).into_owned();
    assert!(texte.starts_with("r=nonceclientnoncesrv,s="), "{texte}");
    assert!(texte.ends_with(",i=4096"), "{texte}");

    // ── Le client conclut ────────────────────────────────────────────────────
    let bare = b"n=jean,r=nonceclient";
    let sans_preuve = b"c=biws,r=nonceclientnoncesrv";
    let preuve = preuve_du_client(
        b"ouvre-toi",
        bare,
        server_first,
        sans_preuve,
        &[3; 16],
        4_096,
    );

    let mut auth_message = Vec::new();
    auth_message.extend_from_slice(bare);
    auth_message.push(b',');
    auth_message.extend_from_slice(server_first);
    auth_message.push(b',');
    auth_message.extend_from_slice(sans_preuve);

    let mut final_serveur = [0_u8; 256];
    let longueur = serveur
        .server_final(b"jean", &auth_message, &preuve, &mut final_serveur)
        .expect("la preuve doit être acceptée");
    let dit = String::from_utf8_lossy(final_serveur.get(..longueur).expect("l")).into_owned();
    assert!(dit.starts_with("v="), "{dit}");

    let _ = std::fs::remove_dir_all(&repertoire);
}

#[test]
fn un_mauvais_mot_de_passe_ne_passe_pas() {
    let (repertoire, serveur) = atelier("faux", "jean", b"ouvre-toi");
    let mut premier = [0_u8; 256];
    let ecrits = serveur
        .server_first(b"jean", b"nc", b"ns", &mut premier)
        .expect("server-first");
    let server_first = premier.get(..ecrits).expect("longueur");
    let bare = b"n=jean,r=nc";
    let sans_preuve = b"c=biws,r=ncns";
    // Le client se trompe de mot de passe.
    let preuve = preuve_du_client(
        b"pas-le-bon",
        bare,
        server_first,
        sans_preuve,
        &[3; 16],
        4_096,
    );
    let mut auth_message = Vec::new();
    auth_message.extend_from_slice(bare);
    auth_message.push(b',');
    auth_message.extend_from_slice(server_first);
    auth_message.push(b',');
    auth_message.extend_from_slice(sans_preuve);
    let mut sortie = [0_u8; 256];
    assert!(
        serveur
            .server_final(b"jean", &auth_message, &preuve, &mut sortie)
            .is_none(),
        "un mauvais mot de passe a été accepté"
    );
    let _ = std::fs::remove_dir_all(&repertoire);
}

#[test]
fn un_compte_inconnu_repond_comme_un_autre_puis_refuse() {
    // **C'EST §7 DE RFC 5802**, et c'est ce qui empêche d'énumérer le magasin.
    let (repertoire, serveur) = atelier("inconnu", "jean", b"ouvre-toi");
    let mut un = [0_u8; 256];
    let a = serveur
        .server_first(b"fantome", b"nc", b"ns", &mut un)
        .expect("un compte inconnu répond quand même");
    let premier = String::from_utf8_lossy(un.get(..a).expect("l")).into_owned();
    // Mêmes itérations que les vrais comptes : le nombre ne doit pas trahir.
    assert!(
        premier.ends_with(&std::format!(",i={}", ams_auth::SCRAM_ITERATIONS)),
        "{premier}"
    );

    // **ET LE SEL EST STABLE** : un sel neuf à chaque essai se distinguerait
    // d'un vrai compte en deux tentatives.
    let mut deux = [0_u8; 256];
    let b = serveur
        .server_first(b"fantome", b"nc", b"ns", &mut deux)
        .expect("server-first");
    assert_eq!(
        un.get(..a),
        deux.get(..b),
        "deux essais sur un compte inconnu n'ont pas rendu la même chose"
    );

    // La preuve, elle, échoue — quelle qu'elle soit.
    let mut sortie = [0_u8; 256];
    assert!(
        serveur
            .server_final(b"fantome", b"peu importe", &[0; 32], &mut sortie)
            .is_none()
    );
    let _ = std::fs::remove_dir_all(&repertoire);
}

#[test]
fn un_magasin_absent_n_empeche_pas_de_demarrer() {
    // Un serveur qui vient d'ouvrir SCRAM n'a pas encore de vérificateur.
    let repertoire = std::env::temp_dir().join(std::format!(
        "ams-scram-vide-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&repertoire).expect("répertoire");
    let chemin_clef = repertoire.join("scram.key");
    std::fs::write(&chemin_clef, CLEF).expect("clé");
    let charge =
        Verificateurs::charger(&chemin_clef, repertoire.join("absent.bin")).expect("chargement");
    assert_eq!(charge.combien(), 0);
    let _ = std::fs::remove_dir_all(&repertoire);
}

#[test]
fn une_clef_de_mauvaise_taille_est_refusee() {
    let repertoire = std::env::temp_dir().join(std::format!(
        "ams-scram-clef-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&repertoire).expect("répertoire");
    let chemin_clef = repertoire.join("scram.key");
    std::fs::write(&chemin_clef, [1_u8; 31]).expect("clé courte");
    let erreur = Verificateurs::charger(&chemin_clef, repertoire.join("x.bin"))
        .expect_err("une clé de 31 octets doit être refusée");
    assert!(erreur.contains("31 octet"), "{erreur}");
    // Et une clé absente aussi.
    let erreur = Verificateurs::charger(&repertoire.join("nulle-part"), repertoire.join("x.bin"))
        .expect_err("une clé absente doit être refusée");
    assert!(erreur.contains("clé SCRAM"), "{erreur}");
    let _ = std::fs::remove_dir_all(&repertoire);
}

#[test]
fn le_magasin_se_relit_a_chaud() {
    let (repertoire, serveur) = atelier("relire", "jean", b"ouvre-toi");
    assert_eq!(serveur.combien(), 1);
    // On ajoute un compte dans le fichier, et on relit.
    let un = ams_auth::scram_deriver(b"ouvre-toi", "jean", [3; 16], 4_096, [9; 12], &CLEF)
        .expect("dérivation");
    let deux = ams_auth::scram_deriver(b"autre", "contact", [4; 16], 4_096, [8; 12], &CLEF)
        .expect("dérivation");
    std::fs::write(
        repertoire.join("scram.bin"),
        ams_config::encode_scram(&[un, deux]).expect("encodage"),
    )
    .expect("magasin");
    assert_eq!(serveur.relire().expect("relecture"), 2);
    assert_eq!(serveur.combien(), 2);

    // **UN FICHIER REFUSÉ NE FERME PAS LA PORTE** : l'ancien magasin reste.
    std::fs::write(repertoire.join("scram.bin"), b"ceci n'est pas du capnp").expect("abîmé");
    assert!(serveur.relire().is_err());
    assert_eq!(serveur.combien(), 2, "l'ancien magasin a été perdu");
    let _ = std::fs::remove_dir_all(&repertoire);
}

#[test]
fn le_nombre_s_ecrit_sans_allocation() {
    let mut place = [0_u8; 10];
    assert_eq!(nombre(0, &mut place), b"0");
    assert_eq!(nombre(1, &mut place), b"1");
    assert_eq!(nombre(4_096, &mut place), b"4096");
    assert_eq!(nombre(32_768, &mut place), b"32768");
    assert_eq!(nombre(u32::MAX, &mut place), b"4294967295");
}

#[test]
fn une_sortie_trop_courte_est_dite_et_non_debordee() {
    let (repertoire, serveur) = atelier("courte", "jean", b"ouvre-toi");
    let mut minuscule = [0_u8; 4];
    assert!(
        serveur
            .server_first(b"jean", b"nc", b"ns", &mut minuscule)
            .is_none(),
        "un tampon de quatre octets a été accepté"
    );
    let _ = std::fs::remove_dir_all(&repertoire);
}
