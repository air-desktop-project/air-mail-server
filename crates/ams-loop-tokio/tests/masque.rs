//! Le masque de création, éprouvé par son EFFET et non par ce qu'il rend.
//!
//! # Pourquoi un essai d'intégration, et non un essai unitaire
//!
//! `umask` est un état du PROCESSUS. Le poser depuis un essai unitaire le
//! poserait pour tous les autres essais du même binaire, qui tournent en
//! parallèle : l'un d'eux verrait ses fichiers naître autrement qu'il ne l'a
//! écrit, et l'apprendrait un jour où l'on chercherait ailleurs. Un fichier
//! d'essais d'intégration est un binaire à lui seul ; ce qu'on y change n'en
//! sort pas.
//!
//! # Ce qui est établi
//!
//! Que le masque posé change ce que le SYSTÈME DE FICHIERS reçoit. Vérifier la
//! valeur rendue par l'appel ne dirait que ce que `umask` a répondu, jamais ce
//! qu'un `File::create` en fait — or c'est cela, et cela seul, qui décide si le
//! courrier de quelqu'un est lisible par son voisin.

use std::os::unix::fs::PermissionsExt as _;

fn mode(chemin: &std::path::Path) -> u32 {
    std::fs::metadata(chemin).expect("lu").permissions().mode() & 0o777
}

#[test]
fn ce_qui_nait_apres_le_masque_n_est_lisible_que_par_nous() {
    let coin = std::env::temp_dir().join(format!("ams-masque-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&coin);

    // ON PART DU MASQUE PERMISSIF QUE DONNENT SYSTEMD ET LES SHELLS, pour que
    // l'essai éprouve le resserrement et non l'état de la machine qui le fait
    // tourner.
    //
    // SAFETY : voir `restreindre_le_masque`. Ce binaire d'essai ne contient
    // qu'un seul essai, donc aucun autre fil n'observe ce changement.
    unsafe { libc::umask(0o022) };
    std::fs::create_dir_all(&coin).expect("répertoire d'essai");

    let temoin = coin.join("avant");
    std::fs::write(&temoin, b"x").expect("écrit");
    assert_eq!(
        mode(&temoin),
        0o644,
        "sans masque serré, un fichier naît lisible par toute la machine"
    );

    let ancien = ams_loop_tokio::restreindre_le_masque();
    assert_eq!(ancien, 0o022, "l'ancien masque est rendu tel quel");
    assert!(
        ams_loop_tokio::masque_trop_large(ancien),
        "et il est reconnu pour ce qu'il est"
    );

    // C'EST ICI QUE TOUT SE JOUE : le même appel, après, donne autre chose.
    let apres = coin.join("apres");
    std::fs::write(&apres, b"x").expect("écrit");
    assert_eq!(
        mode(&apres),
        0o600,
        "après le masque, un fichier naît fermé"
    );

    // ET LES RÉPERTOIRES AUSSI. Sans le bit `x` pour les autres, aucun chemin ne
    // les traverse : c'est la protection qui décide pour une boîte, quels que
    // soient les modes des messages qu'elle contient.
    let dossier = coin.join("boite");
    std::fs::create_dir(&dossier).expect("créé");
    assert_eq!(
        mode(&dossier),
        0o700,
        "un répertoire créé après le masque ne se traverse pas"
    );

    let _ = std::fs::remove_dir_all(&coin);
}
