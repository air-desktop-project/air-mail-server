//! Le refus de s'exécuter en superutilisateur (C10).

use crate::Error;

/// Ce numéro d'utilisateur est-il celui du superutilisateur ?
///
/// Séparé de l'appel système pour que la **décision** soit éprouvable sans être
/// `root` : c'est elle qui porte la règle, l'appel ne fait que la renseigner.
#[must_use]
pub fn is_root(effective_uid: u32) -> bool {
    effective_uid == 0
}

/// Refuse de continuer si le processus est superutilisateur.
///
/// # Pourquoi il n'y a pas d'abandon de privilèges ici
///
/// C10 interdit d'exécuter le serveur avec les privilèges du superutilisateur —
/// **jamais**, pas même le temps de se lier à un port. Les ports privilégiés
/// (25, 465, 587, 110, 995, 143, 993, 80, 443) s'atteignent par une règle de
/// redirection du pare-feu, posée par l'administrateur hors du serveur.
///
/// Il n'existe donc **aucun** code de `setuid`, de `capabilities`, ni de
/// séparation de privilèges dans cette crate. Ce n'est pas un manque : c'est ce
/// que la contrainte achète. Le chemin le plus sûr est celui qui n'existe pas, et
/// on ne se trompe pas dans un abandon de privilèges qu'on n'écrit pas.
///
/// # Errors
///
/// [`Error::RunningAsRoot`].
pub fn refuse_root() -> Result<(), Error> {
    // SAFETY : `geteuid` ne prend aucun argument, ne touche à aucune mémoire, ne
    // peut pas échouer, et est déclaré sans effet de bord observable par POSIX.
    // L'appeler n'a aucune précondition.
    let effective_uid = unsafe { libc::geteuid() };
    if is_root(effective_uid) {
        return Err(Error::RunningAsRoot);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_root, refuse_root};
    use crate::Error;

    #[test]
    fn seul_zero_est_le_superutilisateur() {
        assert!(is_root(0));
        assert!(!is_root(1));
        assert!(!is_root(1000));
        assert!(!is_root(u32::MAX));
    }

    #[test]
    fn le_refus_laisse_passer_un_utilisateur_ordinaire() {
        // Ce test suppose que la suite ne tourne pas en `root` — ce qui est
        // précisément ce que le projet exige de son environnement.
        match refuse_root() {
            Ok(()) => {}
            Err(Error::RunningAsRoot) => {
                panic!("les tests tournent en root, ce que C10 proscrit")
            }
            Err(autre) => panic!("erreur inattendue : {autre}"),
        }
    }
}
