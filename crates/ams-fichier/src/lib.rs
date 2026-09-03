//! Poser un fichier : **atomique pour qui le lit, durable pour la machine**.
//!
//! # Pourquoi cette crate existe
//!
//! Cette décision était prise CINQ FOIS dans ce dépôt, de cinq façons
//! différentes : l'index d'une boîte, le magasin des comptes, le cache MTA-STS,
//! la liste des abonnements IMAP, et les deux fichiers de `air-mail-admin`.
//! Trois des cinq étaient incomplètes, et la plus exposée — l'outil dont c'est
//! le métier d'écrire les comptes et la configuration — ne la prenait pas du
//! tout : il tronquait le fichier SUR PLACE.
//!
//! Ce que cela coûtait : `account add` relit tous les comptes, en ajoute un, et
//! réécrit le tout. Une interruption au mauvais moment — coupure, disque plein,
//! `SIGTERM` — laissait un magasin tronqué. Au démarrage suivant, le serveur ne
//! le relisait plus, et TOUS les comptes étaient perdus, pas seulement celui
//! qu'on ajoutait.
//!
//! Ce n'est la discipline ni du Maildir, ni des comptes, ni de tokio. C'est
//! celle de poser des octets. Lui donner un nom est ce qui empêche de la
//! réinventer une sixième fois, et de l'oublier une quatrième.
//!
//! # Les quatre gestes, et ce que chacun empêche
//!
//! 1. **Un temporaire dans le MÊME répertoire.** `rename` n'est atomique qu'au
//!    sein d'un système de fichiers, et deux répertoires peuvent être sur deux
//!    montages.
//! 2. **`0600` dès l'ouverture.** Un fichier créé en `0644` puis resserré est
//!    lisible par tout le monde pendant l'intervalle — court, mais réel. Et
//!    poser le mode sur un fichier DÉJÀ LÀ ne fait rien du tout : c'est
//!    l'erreur qui laissait un magasin de comptes en `0644` pendant que son
//!    code affirmait `0600`.
//! 3. **`sync_all` sur le fichier, AVANT le renommage.** Sans lui, une coupure
//!    laisserait le nom désigner un fichier vide.
//! 4. **`sync_all` sur le répertoire, APRÈS.** Un répertoire non synchronisé
//!    peut perdre l'entrée qu'on vient d'y écrire.
//!
//! Ôter l'un des quatre laisse une fenêtre ; les quatre ensemble n'en laissent
//! aucune. C'est pourquoi ils ne se choisissent pas à la carte.
//!
//! # `0600`, ET PAS DE RÉGLAGE
//!
//! Tout ce que ce serveur écrit est soit un secret — le scellement des jetons,
//! les empreintes des mots de passe —, soit l'état de la boîte de quelqu'un.
//! Aucun de ces fichiers n'a de raison d'être lisible par les autres comptes de
//! la machine. Un paramètre ferait exister un appel en `0644`, et c'est
//! précisément ce qu'on ne veut pas pouvoir écrire.
//!
//! Le masque du processus dit déjà la même chose. Les deux se cumulent, et ce
//! n'est pas une redondance inutile : le masque couvre ce qu'on écrit sans y
//! penser, le mode explicite tient même si quelqu'un desserre le masque.
//!
//! # LA SEULE ÉCRITURE QUI N'EMPRUNTE PAS CE CHEMIN
//!
//! L'index d'une boîte garde son temporaire dans le `tmp/` du Maildir, et ce
//! n'est pas un oubli. Les sous-dossiers d'une boîte sont des répertoires
//! `.Nom` à la racine, à la façon de Maildir++ : un temporaire nommé
//! `.index.1234.0.tmp` y ressemblerait, le temps d'un renommage, à un dossier
//! nommé `index.1234.0.tmp` — qu'un `LIST` IMAP concurrent pourrait montrer.
//! `tmp/` est le répertoire que Maildir définit pour exactement cela.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Distingue deux poses simultanées du MÊME processus.
///
/// Le numéro de processus ne suffit pas : deux fils qui posent le même chemin
/// choisiraient le même temporaire, et le premier `rename` emporterait le
/// travail du second à moitié écrit.
static SUITE: AtomicU64 = AtomicU64::new(0);

/// Le répertoire qui contient `chemin`.
///
/// # Un chemin nu n'a pas un parent VIDE, il a le répertoire courant
///
/// `Path::new("cache.bin").parent()` rend `Some("")`, et ouvrir `""` échoue.
/// C'est ce qui cassait la pose du cache MTA-STS dès que son chemin était
/// relatif : le renommage réussissait, puis la synchronisation du répertoire
/// rendait une erreur, et l'appelant croyait n'avoir rien posé.
///
/// Séparé de [`poser`] pour que la **décision** s'éprouve sans changer le
/// répertoire courant du processus — qui est global, alors que les essais
/// tournent en parallèle.
#[must_use]
pub fn repertoire_de(chemin: &Path) -> &Path {
    chemin
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Écrit `octets` à `chemin`, en `0600`, atomiquement et durablement.
///
/// Qui lit `chemin` pendant l'appel voit l'ANCIEN contenu en entier, ou le
/// nouveau en entier, jamais un mélange des deux. Après le retour, le contenu
/// survit à une coupure d'alimentation.
///
/// # Errors
///
/// Rend l'erreur du système, et **retire le temporaire** avant de la rendre :
/// un provisoire abandonné serait un fichier de plus, au nom que personne ne
/// lit et au contenu que personne ne relit.
///
/// Rend [`io::ErrorKind::InvalidInput`] si `chemin` ne nomme aucun fichier —
/// `/`, `.` ou `..`. Inventer un nom dans ce cas écrirait ailleurs que là où
/// l'appelant a demandé.
pub fn poser(chemin: &Path, octets: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let Some(nom) = chemin.file_name() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{}` ne nomme aucun fichier", chemin.display()),
        ));
    };
    let repertoire = repertoire_de(chemin);
    let provisoire = repertoire.join(format!(
        ".{}.{}.{}.tmp",
        nom.to_string_lossy(),
        std::process::id(),
        SUITE.fetch_add(1, Ordering::Relaxed)
    ));

    let ecrire = || -> io::Result<()> {
        let mut fichier = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&provisoire)?;
        fichier.write_all(octets)?;
        fichier.sync_all()?;
        drop(fichier);
        std::fs::rename(&provisoire, chemin)?;
        std::fs::File::open(repertoire)?.sync_all()
    };

    ecrire().inspect_err(|_| {
        let _ = std::fs::remove_file(&provisoire);
    })
}

#[cfg(test)]
mod tests {
    use super::{poser, repertoire_de};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Un répertoire à soi, effacé à la sortie.
    struct Ephemere(PathBuf);

    impl Ephemere {
        fn nouveau() -> Self {
            static RANG: AtomicU32 = AtomicU32::new(0);
            let chemin = std::env::temp_dir().join(format!(
                "ams-fichier-{}-{}",
                std::process::id(),
                RANG.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&chemin);
            std::fs::create_dir_all(&chemin).expect("répertoire d'essai");
            Self(chemin)
        }

        fn join(&self, nom: &str) -> PathBuf {
            self.0.join(nom)
        }
    }

    impl Drop for Ephemere {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode(chemin: &Path) -> u32 {
        std::fs::metadata(chemin)
            .expect("posé")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn ce_qu_on_pose_est_ce_qu_on_relit() {
        let coin = Ephemere::nouveau();
        let cible = coin.join("comptes.bin");
        poser(&cible, b"premier").expect("posé");
        assert_eq!(std::fs::read(&cible).expect("relu"), b"premier");
        // ET LE REMPLACEMENT REMPLACE TOUT : un contenu plus court ne doit pas
        // laisser la queue de l'ancien derrière lui.
        poser(&cible, b"deux").expect("posé");
        assert_eq!(std::fs::read(&cible).expect("relu"), b"deux");
    }

    /// **C'EST L'UN DES DEUX DÉFAUTS QUE CETTE CRATE FERME.**
    ///
    /// `OpenOptions::mode` ne s'applique qu'à la CRÉATION. Le magasin des
    /// comptes s'ouvrait donc en place avec `.mode(0o600)`, et un fichier déjà
    /// là en `0644` y restait — pendant que sa documentation affirmait `0600`.
    /// En passant par un temporaire, le fichier qui survit est toujours le neuf.
    #[test]
    fn un_fichier_deja_ouvert_a_tous_se_referme() {
        let coin = Ephemere::nouveau();
        let cible = coin.join("comptes.bin");
        std::fs::write(&cible, b"ancien").expect("écrit");
        std::fs::set_permissions(&cible, std::fs::Permissions::from_mode(0o644)).expect("0644");
        assert_eq!(mode(&cible), 0o644, "l'essai part bien d'un fichier ouvert");
        poser(&cible, b"neuf").expect("posé");
        assert_eq!(
            mode(&cible),
            0o600,
            "le fichier posé n'est lisible que par nous"
        );
    }

    #[test]
    fn un_fichier_neuf_nait_en_0600() {
        let coin = Ephemere::nouveau();
        let cible = coin.join("configuration.bin");
        poser(&cible, b"x").expect("posé");
        assert_eq!(mode(&cible), 0o600);
    }

    /// **AUCUN PROVISOIRE NE RESTE**, ni après un succès, ni après un échec.
    #[test]
    fn le_provisoire_ne_survit_a_rien() {
        let coin = Ephemere::nouveau();
        poser(&coin.join("a"), b"x").expect("posé");
        let restes: Vec<String> = std::fs::read_dir(&coin.0)
            .expect("lu")
            .filter_map(Result::ok)
            .map(|entree| entree.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(restes, vec![String::from("a")], "un provisoire traîne");

        // ÉCHEC : on pose SUR un répertoire non vide, que `rename` ne peut pas
        // remplacer. Le temporaire, lui, a bien été écrit avant l'échec.
        let occupe = coin.join("plein");
        std::fs::create_dir(&occupe).expect("créé");
        std::fs::write(occupe.join("dedans"), b"y").expect("écrit");
        poser(&occupe, b"x").expect_err("un répertoire non vide ne se remplace pas");
        let traînards = std::fs::read_dir(&coin.0)
            .expect("lu")
            .filter_map(Result::ok)
            .filter(|entree| entree.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(traînards, 0, "le provisoire d'un échec traîne");
    }

    #[test]
    fn un_chemin_nu_designe_le_repertoire_courant() {
        assert_eq!(repertoire_de(Path::new("cache.bin")), Path::new("."));
        assert_eq!(repertoire_de(Path::new("./cache.bin")), Path::new("."));
        assert_eq!(
            repertoire_de(Path::new("/etc/ams/cache.bin")),
            Path::new("/etc/ams")
        );
    }

    /// **CE QUI NE NOMME AUCUN FICHIER SE REFUSE**, plutôt que d'inventer un nom
    /// et d'écrire ailleurs que là où l'appelant a demandé.
    #[test]
    fn un_chemin_qui_ne_nomme_aucun_fichier_est_refuse() {
        for muet in ["/", "..", "."] {
            let erreur = poser(Path::new(muet), b"x").expect_err("refusé");
            assert_eq!(erreur.kind(), std::io::ErrorKind::InvalidInput, "{muet}");
        }
    }
}
