//! Une boîte prise pour une session de relève : verrou, instantané, effacement.

use std::fs::{self, File};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use ams_index::{MessageName, Uid};

use crate::{Error, Maildir};

/// Le nom du fichier de verrou, dans la racine de la boîte.
///
/// Comme l'index, il vit dans la racine et non dans `cur/`, `new/` ou `tmp/` :
/// ces trois-là ne contiennent que des messages.
const NOM_VERROU: &str = "ams-pop3.lock";

/// Un message, tel qu'une session de relève le voit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Où il vit.
    pub path: PathBuf,
    /// Son UID Maildir — l'identifiant durable que POP3 appelle `UIDL`.
    pub uid: Uid,
    /// Sa taille en octets.
    pub size: u64,
    /// Vit-il encore dans `new/` ?
    ///
    /// # C'EST CE QUE MAILDIR APPELLE « RÉCENT », ET RIEN D'AUTRE
    ///
    /// Un message naît dans `new/` et passe dans `cur/` à la PREMIÈRE écriture
    /// de drapeau — poser `\Seen` le déplace, parce que le nom du fichier porte
    /// les drapeaux et que Maildir veut les porteurs dans `cur/`. Le compte
    /// décroît donc à mesure qu'on lit la boîte, ce qui est exactement ce qu'un
    /// client IMAP4rev1 attend de `RECENT`.
    ///
    /// **Ce n'est pas tout à fait le `\Recent` de RFC 3501 §2.3.2**, qui parle
    /// de la PREMIÈRE SESSION à voir le message. Le suivre demanderait un état
    /// par session, écrit sur le disque, et §2.3.2 admet lui-même qu'on ne
    /// puisse pas le déterminer. Ce que ce serveur rapporte est vrai, dit ce
    /// qu'il dit, et ne prétend pas davantage.
    pub recent: bool,
}

/// Une boîte **verrouillée**, avec la liste de ses messages.
///
/// # Le verrou est un `flock`, et pas un fichier témoin
///
/// La RFC 1939 §3 veut un accès exclusif pendant toute la session. Un fichier
/// témoin le donnerait aussi — mais il survivrait à un arrêt brutal, et il
/// faudrait alors décider au bout de combien de temps un verrou devient
/// « périmé ». Personne ne décide bien cela. `flock` est relâché par le noyau à
/// la mort du processus : il n'y a pas de verrou périmé, donc pas de règle à se
/// tromper.
///
/// Le verrou tient tant que cette structure vit, et le fichier reste en place :
/// l'effacer à la fin ouvrirait une course où deux sessions verrouillent deux
/// fichiers différents portant le même nom.
///
/// # L'instantané est pris UNE FOIS
///
/// RFC 1939 §3 : le nombre de messages ne change plus jusqu'au `QUIT`. Les
/// numéros POP3 sont donc les rangs dans cette liste — `1` désigne le même
/// message du début à la fin.
#[derive(Debug)]
pub struct LockedMailbox {
    racine: PathBuf,
    messages: Vec<Message>,
    /// Le fichier verrouillé. **Il n'est jamais lu** : c'est sa seule
    /// existence, et le `flock` qui le tient, qui comptent.
    _verrou: File,
}

impl LockedMailbox {
    /// Verrouille une boîte et relève ce qu'elle contient.
    ///
    /// Rend `Ok(None)` si une autre session la tient déjà : ce n'est pas une
    /// panne, c'est la situation que la RFC prévoit, et l'appelant répondra
    /// `-ERR` plutôt que de mourir.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] si la boîte ne peut être ni ouverte ni lue.
    pub fn open(boite: &Maildir) -> Result<Option<Self>, Error> {
        let racine = boite.root().to_path_buf();
        let chemin = racine.join(NOM_VERROU);
        let fichier = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&chemin)?;

        // SAFETY: `flock` reçoit un descripteur valide, emprunté à `fichier`
        // qui vit plus longtemps que l'appel.
        let pris = unsafe { libc::flock(fichier.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if pris != 0 {
            let cause = std::io::Error::last_os_error();
            // `EWOULDBLOCK` : une autre session tient la boîte. Tout le reste
            // est une vraie panne, et la taire ferait passer un disque en
            // lecture seule pour une boîte occupée.
            if cause.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            return Err(Error::Io(cause));
        }

        let messages = relever(&racine)?;
        Ok(Some(Self {
            racine,
            messages,
            _verrou: fichier,
        }))
    }

    /// Les messages, dans l'ordre de leurs numéros POP3.
    #[must_use]
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// La racine de la boîte.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.racine
    }

    /// Efface les messages dont le rang (à partir de zéro) est marqué.
    ///
    /// # Ce qui est fait, et ce qui ne l'est pas
    ///
    /// Les fichiers sont **retirés**, pas déplacés dans une corbeille : POP3 ne
    /// connaît pas de corbeille, et en inventer une ferait grossir une boîte que
    /// l'utilisateur croit avoir vidée.
    ///
    /// Un effacement qui échoue **n'arrête pas les autres** : la RFC 1939 §6 dit
    /// que le serveur DOIT tenter d'effacer, et s'arrêter au premier échec
    /// laisserait la boîte à moitié dans l'état demandé sans que personne ne
    /// sache lequel. Le nombre d'échecs est rendu.
    #[must_use]
    pub fn expunge(&self, marques: &[bool]) -> usize {
        let mut echecs = 0_usize;
        for (message, marque) in self.messages.iter().zip(marques) {
            if !marque {
                continue;
            }
            if fs::remove_file(&message.path).is_err() {
                echecs = echecs.saturating_add(1);
            }
        }
        echecs
    }
}

/// Une boîte **lue sans verrou**, avec la liste de ses messages.
///
/// # Pourquoi un lecteur ne verrouille pas
///
/// Maildir est fait pour être lu sans verrou : un message est un fichier qui ne
/// change plus une fois déposé, et une livraison ne fait qu'en ajouter un. C'est
/// la propriété qui a donné son nom au format, et s'en priver coûterait cher :
/// une session IMAP dure des heures, et un verrou exclusif tenu pendant ces
/// heures interdirait toute relève POP3 de la même boîte. On aurait échangé une
/// course qui n'existe pas contre une indisponibilité qui, elle, existe.
///
/// # Ce qu'on accepte en échange
///
/// Qu'un message s'efface pendant la session — une relève POP3 concurrente le
/// peut. Le lecteur en garde alors le nom sans le fichier, et sa lecture rend
/// zéro octet. **C'est déjà le cas qu'il faut tenir de toute façon** : entre le
/// moment où l'on annonce la taille d'un message et celui où on l'écrit, rien
/// n'empêchait sa disparition, verrou ou pas.
///
/// # L'instantané est pris UNE FOIS
///
/// Comme pour [`LockedMailbox`], et pour la même raison : les numéros de séquence
/// d'IMAP sont les rangs dans cette liste, et ils ne bougent pas de la session.
pub struct MailboxView {
    /// La racine de la boîte.
    racine: PathBuf,
    /// L'instantané.
    messages: Vec<Message>,
}

impl MailboxView {
    /// Relève ce que la boîte contient, sans rien verrouiller.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] si la boîte ne peut être lue.
    pub fn open(boite: &Maildir) -> Result<Self, Error> {
        let racine = boite.root().to_path_buf();
        let messages = relever(&racine)?;
        Ok(Self { racine, messages })
    }

    /// Les messages, dans l'ordre de leurs rangs.
    #[must_use]
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// La racine de la boîte.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.racine
    }

    /// Retire le message de rang `index` de l'instantané.
    ///
    /// **Ne touche pas au disque** : c'est l'appelant qui a effacé le fichier,
    /// et qui vient dire que l'instantané ne doit plus le compter. Les rangs qui
    /// suivaient descendent d'un cran, ce qu'IMAP appelle renuméroter (§7.5.1) —
    /// et ce que POP3 interdit pendant une session, raison de plus pour que
    /// cette opération ne vive pas sur [`LockedMailbox`].
    ///
    /// Un rang hors de portée ne fait rien : il n'y a pas de message à oublier.
    pub fn forget(&mut self, index: usize) {
        if index < self.messages.len() {
            self.messages.remove(index);
        }
    }
}

/// Relève les messages d'une boîte, `new/` puis `cur/`, triés par UID.
///
/// # L'ordre est celui des UID, et il ne doit dépendre de rien d'autre
///
/// Ni de l'ordre de lecture du répertoire — qui n'est pas garanti — ni de la
/// date de modification. Les numéros POP3 sont les rangs dans cette liste, et
/// un client qui revient doit retrouver `1` sur le même message.
fn relever(racine: &Path) -> Result<Vec<Message>, Error> {
    let mut messages = Vec::new();
    for sous in ["new", "cur"] {
        let repertoire = racine.join(sous);
        for entree in fs::read_dir(&repertoire)? {
            let entree = entree?;
            let nom = entree.file_name();
            let Ok(lu) = MessageName::parse(nom.as_bytes()) else {
                // Un nom que la grammaire refuse n'est pas un message : le
                // compter en ferait un, et `RETR` rendrait n'importe quoi.
                continue;
            };
            let Some(uid) = lu.uid() else {
                // Sans UID, le message n'a pas d'identifiant durable à donner à
                // `UIDL`. `Maildir::open` les adopte au démarrage ; celui-ci est
                // arrivé entre-temps, et sera relevé à la session suivante.
                continue;
            };
            let chemin = entree.path();
            // La taille du NOM si elle y est, sinon celle du fichier. Le nom la
            // porte depuis que nous composons les noms ; un message adopté d'un
            // autre outil peut ne pas l'avoir.
            let size = match lu.size() {
                Some(taille) => taille,
                None => entree.metadata()?.len(),
            };
            messages.push(Message {
                path: chemin,
                uid,
                size,
                // LA VÉRITÉ VIENT DU RÉPERTOIRE QU'ON PARCOURT, et non d'une
                // relecture du chemin : c'est la même donnée, mais celle-ci ne
                // peut pas se tromper de séparateur ni d'encodage.
                recent: sous == "new",
            });
        }
    }
    messages.sort_by_key(|message| message.uid.value());
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::{LockedMailbox, NOM_VERROU};
    use crate::Maildir;
    use ams_index::UidValidity;
    use std::path::PathBuf;

    const VALIDITE: UidValidity = UidValidity::MIN;

    /// Un répertoire temporaire qui se nettoie tout seul.
    struct Ephemere(PathBuf);

    impl Drop for Ephemere {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ephemere(nom: &str) -> Ephemere {
        let chemin = std::env::temp_dir().join(format!(
            "ams-store-{nom}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&chemin);
        std::fs::create_dir_all(&chemin).expect("répertoire temporaire");
        Ephemere(chemin)
    }

    /// Une boîte avec `combien` messages remis.
    fn boite(temporaire: &Ephemere, combien: usize) -> Maildir {
        let boite = Maildir::open(&temporaire.0, b"mail.example.com", VALIDITE).expect("ouvrable");
        for rang in 0..combien {
            let mut arrivee = boite.deliver().expect("remise");
            arrivee
                .write(format!("message {rang}\r\n").as_bytes())
                .expect("écriture");
            arrivee.commit().expect("validation");
        }
        boite
    }

    #[test]
    fn l_instantane_est_trie_par_uid_et_porte_les_tailles() {
        let temporaire = ephemere("instantane");
        let boite = boite(&temporaire, 3);
        let verrouillee = LockedMailbox::open(&boite)
            .expect("verrouillable")
            .expect("libre");
        let uids: Vec<u32> = verrouillee
            .messages()
            .iter()
            .map(|message| message.uid.value())
            .collect();
        let mut tries = uids.clone();
        tries.sort_unstable();
        assert_eq!(uids, tries, "l'ordre doit être celui des UID");
        assert_eq!(verrouillee.messages().len(), 3);
        for message in verrouillee.messages() {
            // « message 0\r\n » : onze octets, et la taille vient du NOM
            // (`,S=`) — pas d'un `stat` par message.
            assert_eq!(message.size, 11);
        }
        assert_eq!(verrouillee.root(), boite.root());
    }

    #[test]
    fn une_seconde_session_ne_verrouille_pas_la_meme_boite() {
        // RFC 1939 §3 : accès exclusif. Deux sessions qui effacent en même temps
        // se marcheraient dessus, et le second `QUIT` porterait sur des numéros
        // qui ne désignent plus rien.
        let temporaire = ephemere("verrou");
        let boite = boite(&temporaire, 1);
        let premiere = LockedMailbox::open(&boite)
            .expect("verrouillable")
            .expect("libre");
        assert!(
            LockedMailbox::open(&boite)
                .expect("interrogeable")
                .is_none(),
            "la boîte devait être occupée"
        );
        // Le verrou est relâché avec la structure, pas avec le fichier : celui-ci
        // RESTE, et l'effacer ouvrirait une course entre deux sessions
        // verrouillant deux fichiers différents du même nom.
        drop(premiere);
        assert!(temporaire.0.join(NOM_VERROU).is_file());
        assert!(
            LockedMailbox::open(&boite)
                .expect("verrouillable")
                .is_some(),
            "le verrou devait être relâché"
        );
    }

    #[test]
    fn expunge_efface_ce_qui_est_marque_et_rien_d_autre() {
        let temporaire = ephemere("expunge");
        let boite = boite(&temporaire, 3);
        let verrouillee = LockedMailbox::open(&boite)
            .expect("verrouillable")
            .expect("libre");
        let restant = verrouillee.messages()[1].path.clone();
        assert_eq!(verrouillee.expunge(&[true, false, true]), 0);
        assert!(restant.is_file());

        // Et la session suivante ne voit plus que celui-là.
        drop(verrouillee);
        let apres = LockedMailbox::open(&boite)
            .expect("verrouillable")
            .expect("libre");
        assert_eq!(apres.messages().len(), 1);
        assert_eq!(apres.messages()[0].path, restant);
    }

    #[test]
    fn un_effacement_qui_echoue_n_arrete_pas_les_autres() {
        // RFC 1939 §6 : le serveur DOIT tenter. S'arrêter au premier échec
        // laisserait la boîte à moitié dans l'état demandé, sans que personne ne
        // sache laquelle.
        let temporaire = ephemere("echec");
        let boite = boite(&temporaire, 2);
        let verrouillee = LockedMailbox::open(&boite)
            .expect("verrouillable")
            .expect("libre");
        // On efface le premier À LA MAIN : son effacement échouera.
        std::fs::remove_file(&verrouillee.messages()[0].path).expect("effacement");
        assert_eq!(verrouillee.expunge(&[true, true]), 1);
        assert!(!verrouillee.messages()[1].path.exists());
    }

    #[test]
    fn les_noms_illisibles_et_les_messages_sans_uid_sont_ignores() {
        // Un nom que la grammaire refuse n'est pas un message : le compter en
        // ferait un, et `RETR` rendrait n'importe quoi.
        let temporaire = ephemere("intrus");
        let boite = boite(&temporaire, 1);
        std::fs::write(temporaire.0.join("new").join("pas:un:nom"), b"x").expect("intrus");
        let verrouillee = LockedMailbox::open(&boite)
            .expect("verrouillable")
            .expect("libre");
        assert_eq!(verrouillee.messages().len(), 1);
    }

    #[test]
    fn une_marque_de_plus_que_de_messages_ne_deborde_pas() {
        // `zip` s'arrête au plus court : un appelant qui se tromperait de
        // longueur n'efface rien de plus.
        let temporaire = ephemere("marques");
        let boite = boite(&temporaire, 1);
        let verrouillee = LockedMailbox::open(&boite)
            .expect("verrouillable")
            .expect("libre");
        assert_eq!(verrouillee.expunge(&[false, true, true]), 0);
        assert!(verrouillee.messages()[0].path.is_file());
    }
}
