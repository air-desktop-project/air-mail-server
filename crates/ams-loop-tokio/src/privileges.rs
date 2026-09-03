//! La posture que ce processus adopte avant de toucher à quoi que ce soit : le
//! refus de s'exécuter en superutilisateur (C10), et le masque de création.

use crate::Error;

/// Le masque posé : **rien pour le groupe, rien pour les autres**.
///
/// Ce n'est pas un durcissement facultatif. Tout ce que ce serveur écrit est soit
/// un secret, soit le courrier de quelqu'un.
const MASQUE: u32 = 0o077;

/// Restreint le masque de création de ce processus, et rend l'ANCIEN.
///
/// # Ce que cela répare
///
/// Le mode de création n'était posé qu'aux endroits où quelqu'un y avait pensé :
/// le magasin des comptes, le cache MTA-STS, la file de réémission. Partout
/// ailleurs, `File::create` et `create_dir_all` prenaient le défaut — c'est-à-
/// dire `0666` et `0777` moins le masque HÉRITÉ. Avec le `0022` que systemd
/// donne par défaut, cela fait :
///
///   - **chaque message livré en `0644`**, et les répertoires `new/`, `cur/` et
///     `tmp/` de chaque boîte en `0755` ;
///   - l'index d'une boîte, les abonnements IMAP, la configuration écrite par
///     l'outil d'administration ;
///   - les rapports DMARC agrégés, et **les rapports d'ÉCHEC**, qui portent les
///     en-têtes du courrier d'autrui (RFC 6591).
///
/// Sur une machine à plusieurs comptes Unix, n'importe quel utilisateur local
/// lisait donc le courrier de tout le monde. Rien dans ce dépôt ne posait de
/// masque, et il n'y a ni unité systemd ni documentation d'installation qui
/// aurait pu le faire à sa place.
///
/// # POURQUOI LE MASQUE, ET NON UN MODE À CHAQUE APPEL
///
/// Parce que la seconde solution est celle qui a échoué. La règle était écrite à
/// quatre endroits et oubliée à dix ; l'écrire aux dix restants la laisserait
/// s'oublier au onzième. Le masque est une propriété du PROCESSUS : il couvre ce
/// que ce code écrit aujourd'hui, et ce qu'il écrira sans y penser demain.
///
/// # CE QU'IL NE FAIT PAS
///
/// Il ne touche PAS aux fichiers déjà là. Une installation existante garde ses
/// permissions, et c'est pourquoi l'appelant les vérifie et le dit.
///
/// Il ne remplace pas non plus un mode explicite là où l'on veut être sûr :
/// `0600` posé à l'ouverture reste juste, et vaut même si quelqu'un desserre le
/// masque plus tard. Les deux se cumulent — le masque est un plancher, pas une
/// dispense.
pub fn restreindre_le_masque() -> u32 {
    // SAFETY : `umask` ne prend qu'un entier, ne touche à aucune mémoire de ce
    // processus, ne peut pas échouer, et rend toujours l'ancien masque. POSIX ne
    // lui reconnaît aucune précondition. Elle n'est pas sûre entre fils —
    // l'ancien masque est un état global — et c'est pourquoi elle est appelée
    // une seule fois, au tout début, avant qu'aucun fil ne soit créé.
    // `mode_t` EST DÉJÀ UN `u32` ICI : ce serveur est Linux seulement (C10), et
    // convertir masquerait le jour où ce ne serait plus vrai.
    unsafe { libc::umask(MASQUE) }
}

/// Ce masque laissait-il lire à quelqu'un d'autre que nous ?
///
/// Séparé de l'appel système pour la raison qui vaut déjà pour [`is_root`] : la
/// **décision** doit s'éprouver sans dépendre de l'état du processus qui la
/// pose.
#[must_use]
pub fn masque_trop_large(masque: u32) -> bool {
    masque & 0o077 != 0o077
}

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

    /// **UN MASQUE QUI NE BLOQUE PAS TOUT NE BLOQUE RIEN QUI COMPTE.**
    ///
    /// `0022` — celui que donnent systemd et la plupart des shells — laisse le
    /// bit de LECTURE au groupe et aux autres : c'est lui qui rendait chaque
    /// message livré lisible par toute la machine. Seul un masque qui porte les
    /// six bits `go` est assez serré.
    #[test]
    fn seul_un_masque_qui_porte_les_six_bits_est_assez_serre() {
        assert!(
            super::masque_trop_large(0o000),
            "aucun masque : tout est ouvert"
        );
        assert!(super::masque_trop_large(0o022), "le défaut de systemd");
        assert!(super::masque_trop_large(0o007), "le groupe lit encore");
        assert!(super::masque_trop_large(0o070), "les autres lisent encore");
        assert!(!super::masque_trop_large(0o077), "celui qu'on pose");
        // Plus serré encore reste assez serré : on ne reproche pas à un
        // exploitant d'avoir fermé davantage.
        assert!(!super::masque_trop_large(0o177));
        assert!(!super::masque_trop_large(0o777));
    }

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
