//! Une boîte Maildir : `tmp/`, `new/`, `cur/`.

use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ams_index::{Flags, MailboxSummary, MessageName, Uid, compose, summarise};

use crate::Error;

/// La longueur maximale d'un nom composé : la partie unique, plus les champs.
const NOM_MAX: usize = 512;

/// Un compteur PROCESSUS, pour que deux messages de la même seconde ne se
/// disputent pas un nom.
static COMPTEUR: AtomicU64 = AtomicU64::new(0);

/// Une boîte Maildir.
///
/// # Pourquoi Maildir, et ce que cela achète
///
/// Un fichier par message, et l'arrivée par `rename()` de `tmp/` vers `new/`.
/// `rename()` est **atomique** sur POSIX : un lecteur voit le message entier ou
/// ne le voit pas. Il n'y a donc aucun verrou à prendre, donc aucun à oublier de
/// relâcher — c'est la propriété qui fait choisir ce format (C13).
pub struct Maildir {
    racine: PathBuf,
    hote: Vec<u8>,
    prochain_uid: AtomicU32,
}

impl Maildir {
    /// Ouvre — ou crée — une boîte, et adopte ce qu'elle contient déjà.
    ///
    /// `hote` entre dans les noms de fichiers pour qu'ils restent uniques entre
    /// machines. Il vient de l'appelant plutôt que d'un appel système : c'est une
    /// valeur de configuration, et le serveur en connaît déjà une.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] si les répertoires ne peuvent être créés ou lus.
    pub fn open(racine: impl Into<PathBuf>, hote: &[u8]) -> Result<Self, Error> {
        let racine = racine.into();
        for sous in ["tmp", "new", "cur"] {
            fs::create_dir_all(racine.join(sous))?;
        }
        let boite = Self {
            racine,
            // Un `/` ou un `:` dans le nom d'hôte casserait le nom de fichier ;
            // Maildir prescrit de les remplacer plutôt que de refuser.
            hote: hote
                .iter()
                .map(|&octet| match octet {
                    b'/' => b'\x02',
                    b':' => b'\x01',
                    autre => autre,
                })
                .collect(),
            prochain_uid: AtomicU32::new(1),
        };
        let resume = boite.scan()?;
        boite
            .prochain_uid
            .store(resume.next_uid.value(), Ordering::Relaxed);
        boite.adopter()?;
        Ok(boite)
    }

    /// Le résumé de la boîte, relu depuis les fichiers.
    ///
    /// C'est **la** reconstruction : rien n'est cru sur parole, tout est relu.
    ///
    /// # Errors
    ///
    /// [`Error::Io`].
    pub fn summary(&self) -> Result<MailboxSummary, Error> {
        self.scan()
    }

    /// Ouvre la remise d'un message.
    ///
    /// # Errors
    ///
    /// [`Error::UidExhausted`], [`Error::Io`] ou [`Error::Name`].
    pub fn deliver(&self) -> Result<Incoming, Error> {
        let uid = self.reserver_uid()?;
        let unique = self.nom_unique();
        let chemin = self.racine.join("tmp").join(nom_de_fichier(&unique));
        let fichier = File::create(&chemin)?;
        Ok(Incoming {
            // La remise POSSÈDE son chemin plutôt que d'emprunter la boîte : une
            // tâche qui la porte doit pouvoir vivre seule, et un emprunt la
            // clouerait à la pile qui l'a créée.
            racine: self.racine.clone(),
            fichier: Some(fichier),
            chemin,
            unique,
            uid,
            ecrits: 0,
        })
    }

    /// Le chemin de la boîte.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.racine
    }

    /// Réserve le prochain UID.
    fn reserver_uid(&self) -> Result<Uid, Error> {
        loop {
            let courant = self.prochain_uid.load(Ordering::Relaxed);
            let Some(uid) = Uid::new(courant) else {
                return Err(Error::UidExhausted);
            };
            let Some(suivant) = uid.next() else {
                return Err(Error::UidExhausted);
            };
            if self
                .prochain_uid
                .compare_exchange_weak(
                    courant,
                    suivant.value(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Ok(uid);
            }
        }
    }

    /// Une partie unique : la seconde, un compteur, et l'hôte.
    fn nom_unique(&self) -> Vec<u8> {
        let secondes = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |depuis| depuis.as_secs());
        let compte = COMPTEUR.fetch_add(1, Ordering::Relaxed);
        let mut unique = Vec::with_capacity(64);
        unique.extend_from_slice(secondes.to_string().as_bytes());
        unique.extend_from_slice(b".M");
        unique.extend_from_slice(compte.to_string().as_bytes());
        unique.extend_from_slice(b"P");
        unique.extend_from_slice(std::process::id().to_string().as_bytes());
        unique.push(b'.');
        unique.extend_from_slice(&self.hote);
        unique
    }

    /// Relit `new/` et `cur/`, et replie ce qu'ils portent.
    fn scan(&self) -> Result<MailboxSummary, Error> {
        let mut noms: Vec<Vec<u8>> = Vec::new();
        for sous in ["new", "cur"] {
            for entree in fs::read_dir(self.racine.join(sous))? {
                noms.push(entree?.file_name().as_bytes().to_vec());
            }
        }
        Ok(summarise(noms.iter().map(Vec::as_slice)))
    }

    /// Donne un UID aux messages qui n'en ont pas.
    ///
    /// # Pourquoi c'est nécessaire, et pas seulement soigné
    ///
    /// Un message sans `,U=` n'a **aucun UID stable** : au prochain parcours, on
    /// devrait le lui inventer, et il changerait. Or un UID qui change force à
    /// incrémenter l'`UIDVALIDITY`, ce qui fait retélécharger la boîte entière à
    /// tous les clients. Adopter à l'ouverture ferme cette porte une fois.
    ///
    /// Un `rename` qui échoue parce que la source a disparu n'est **pas** une
    /// erreur : un autre serveur sur la même boîte vient de l'adopter, et Maildir
    /// est fait pour cela.
    fn adopter(&self) -> Result<(), Error> {
        for sous in ["new", "cur"] {
            let repertoire = self.racine.join(sous);
            let mut a_adopter: Vec<Vec<u8>> = Vec::new();
            for entree in fs::read_dir(&repertoire)? {
                let nom = entree?.file_name().as_bytes().to_vec();
                if MessageName::parse(&nom).is_ok_and(|lu| lu.uid().is_none()) {
                    a_adopter.push(nom);
                }
            }
            for ancien in a_adopter {
                let lu = MessageName::parse(&ancien)?;
                let uid = self.reserver_uid()?;
                let taille = fs::metadata(repertoire.join(nom_de_fichier(&ancien)))
                    .map_or(0, |donnees| donnees.len());
                let mut tampon = [0_u8; NOM_MAX];
                let flags = lu.has_info().then(|| lu.flags());
                let ecrits = compose(&mut tampon, lu.unique(), uid, taille, flags)?;
                let nouveau = repertoire.join(nom_de_fichier(&tampon[..ecrits]));
                let _ = fs::rename(repertoire.join(nom_de_fichier(&ancien)), nouveau);
            }
        }
        Ok(())
    }
}

/// Un message en cours de remise.
///
/// Tant qu'il n'est pas validé, il vit dans `tmp/` et **personne ne le voit**.
pub struct Incoming {
    racine: PathBuf,
    fichier: Option<File>,
    chemin: PathBuf,
    unique: Vec<u8>,
    uid: Uid,
    ecrits: u64,
}

impl Incoming {
    /// L'UID que ce message portera.
    #[must_use]
    pub fn uid(&self) -> Uid {
        self.uid
    }

    /// Ajoute des octets au message.
    ///
    /// # Errors
    ///
    /// [`Error::Io`].
    pub fn write(&mut self, morceau: &[u8]) -> Result<(), Error> {
        if let Some(fichier) = self.fichier.as_mut() {
            fichier.write_all(morceau)?;
            self.ecrits = self
                .ecrits
                .saturating_add(u64::try_from(morceau.len()).unwrap_or(u64::MAX));
        }
        Ok(())
    }

    /// Valide le message : il apparaît dans `new/`, et il y est **durable**.
    ///
    /// # Deux synchronisations, et la seconde est celle qu'on oublie
    ///
    /// 1. Le **fichier**, avant le `rename` : sans elle, le nom existerait sans
    ///    son contenu.
    /// 2. Le **répertoire**, après le `rename` : sans elle, le contenu existerait
    ///    sans son nom. Un `rename` n'est durable que lorsque le répertoire qui le
    ///    porte l'est, et c'est la moitié qu'on oublie.
    ///
    /// Un serveur qui répond `250` doit avoir pris la responsabilité du message
    /// (RFC 5321 §6.1). Sans ces deux appels, il ne l'a pas prise : il l'a
    /// promise.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] ou [`Error::Name`].
    pub fn commit(mut self) -> Result<Uid, Error> {
        let Some(fichier) = self.fichier.take() else {
            return Ok(self.uid);
        };
        fichier.sync_all()?;
        drop(fichier);

        let mut tampon = [0_u8; NOM_MAX];
        // `None` : un message qui arrive n'a pas de drapeaux, et Maildir veut
        // qu'il n'ait pas non plus d'information de drapeaux.
        let ecrits = compose(&mut tampon, &self.unique, self.uid, self.ecrits, None)?;
        let destination = self
            .racine
            .join("new")
            .join(nom_de_fichier(&tampon[..ecrits]));
        fs::rename(&self.chemin, &destination)?;

        File::open(self.racine.join("new"))?.sync_all()?;
        Ok(self.uid)
    }

    /// Abandonne le message : rien n'en subsiste.
    pub fn abort(mut self) {
        drop(self.fichier.take());
        let _ = fs::remove_file(&self.chemin);
    }
}

impl Drop for Incoming {
    /// Un message qu'on laisse tomber ne laisse pas de fichier derrière lui.
    ///
    /// Sans cela, une tâche qui panique en pleine remise emplirait `tmp/` de
    /// moitiés de messages que personne ne réclamerait jamais.
    fn drop(&mut self) {
        if self.fichier.take().is_some() {
            let _ = fs::remove_file(&self.chemin);
        }
    }
}

/// Un nom de fichier, depuis des octets.
fn nom_de_fichier(octets: &[u8]) -> &Path {
    Path::new(std::ffi::OsStr::from_bytes(octets))
}

/// Les drapeaux d'un message déjà classé.
///
/// Exposé pour que l'appelant n'ait pas à refaire l'analyse du nom.
///
/// # Errors
///
/// [`Error::Name`] si le nom est irrecevable.
pub fn flags_of(nom: &[u8]) -> Result<Flags, Error> {
    Ok(MessageName::parse(nom)?.flags())
}

#[cfg(test)]
mod tests {
    use super::{Maildir, flags_of};
    use crate::Error;
    use ams_index::{Flags, MessageName, Uid};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Un répertoire temporaire qui se nettoie tout seul.
    struct Ephemere(PathBuf);

    impl Ephemere {
        fn nouveau() -> Self {
            static RANG: AtomicU32 = AtomicU32::new(0);
            let chemin = std::env::temp_dir().join(format!(
                "ams-store-{}-{}",
                std::process::id(),
                RANG.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&chemin);
            Self(chemin)
        }
    }

    impl Drop for Ephemere {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn boite(temporaire: &Ephemere) -> Maildir {
        Maildir::open(&temporaire.0, b"mail.example.com").expect("ouvrable")
    }

    /// Les noms présents dans un sous-répertoire.
    fn noms(boite: &Maildir, sous: &str) -> Vec<Vec<u8>> {
        use std::os::unix::ffi::OsStrExt as _;
        let mut trouves: Vec<Vec<u8>> = fs::read_dir(boite.root().join(sous))
            .expect("lisible")
            .map(|entree| entree.expect("entrée").file_name().as_bytes().to_vec())
            .collect();
        trouves.sort_unstable();
        trouves
    }

    #[test]
    fn une_boite_neuve_a_ses_trois_repertoires() {
        let temporaire = Ephemere::nouveau();
        let boite = boite(&temporaire);
        for sous in ["tmp", "new", "cur"] {
            assert!(boite.root().join(sous).is_dir(), "{sous} manque");
        }
        let resume = boite.summary().expect("résumable");
        assert_eq!(resume.next_uid, Uid::FIRST);
        assert_eq!(resume.numbered, 0);
    }

    #[test]
    fn un_message_remis_porte_son_uid_dans_son_nom() {
        // C'EST CE QUI REND L'INDEX RECONSTRUCTIBLE (C13).
        let temporaire = Ephemere::nouveau();
        let boite = boite(&temporaire);

        let mut arrivee = boite.deliver().expect("remise ouverte");
        arrivee.write(b"From: moi\r\n\r\n").expect("écriture");
        arrivee.write(b"bonjour\r\n").expect("écriture");
        let uid = arrivee.commit().expect("validation");
        assert_eq!(uid, Uid::FIRST);

        let dans_new = noms(&boite, "new");
        assert_eq!(dans_new.len(), 1);
        let lu = MessageName::parse(&dans_new[0]).expect("relisible");
        assert_eq!(lu.uid(), Some(Uid::FIRST));
        assert_eq!(lu.size(), Some(22));
        // Un message qui arrive n'a PAS d'information de drapeaux.
        assert!(!lu.has_info());
        assert_eq!(flags_of(&dans_new[0]).expect("relisible"), Flags::NONE);

        // Le contenu est intact, et `tmp/` est vide.
        use std::os::unix::ffi::OsStrExt as _;
        let contenu = fs::read(
            boite
                .root()
                .join("new")
                .join(std::ffi::OsStr::from_bytes(&dans_new[0])),
        )
        .expect("lisible");
        assert_eq!(contenu, b"From: moi\r\n\r\nbonjour\r\n");
        assert!(noms(&boite, "tmp").is_empty());
    }

    #[test]
    fn un_message_abandonne_ne_laisse_rien() {
        let temporaire = Ephemere::nouveau();
        let boite = boite(&temporaire);
        let mut arrivee = boite.deliver().expect("remise ouverte");
        arrivee.write(b"a moitie").expect("écriture");
        arrivee.abort();
        assert!(noms(&boite, "tmp").is_empty(), "`tmp/` n'a pas été nettoyé");
        assert!(noms(&boite, "new").is_empty());
    }

    #[test]
    fn un_message_laisse_tomber_ne_laisse_rien_non_plus() {
        // Une tâche qui panique en pleine remise emplirait `tmp/` de moitiés de
        // messages que personne ne réclamerait.
        let temporaire = Ephemere::nouveau();
        let boite = boite(&temporaire);
        {
            let mut arrivee = boite.deliver().expect("remise ouverte");
            arrivee.write(b"jamais valide").expect("écriture");
        }
        assert!(noms(&boite, "tmp").is_empty());
    }

    #[test]
    fn les_uid_se_suivent_et_survivent_a_une_reouverture() {
        let temporaire = Ephemere::nouveau();
        {
            let boite = boite(&temporaire);
            for attendu in 1..=3_u32 {
                let arrivee = boite.deliver().expect("remise ouverte");
                assert_eq!(arrivee.commit().expect("validation").value(), attendu);
            }
        }
        // La boîte rouverte reprend où elle en était : les UID sont RELUS depuis
        // les noms, pas retenus quelque part.
        let boite = boite(&temporaire);
        assert_eq!(boite.summary().expect("résumable").next_uid.value(), 4);
        let arrivee = boite.deliver().expect("remise ouverte");
        assert_eq!(arrivee.commit().expect("validation").value(), 4);
    }

    #[test]
    fn un_message_depose_par_un_autre_outil_est_adopte() {
        // Un message sans `,U=` n'a aucun UID stable : le lui inventer à chaque
        // parcours forcerait à changer l'`UIDVALIDITY`, donc à faire
        // retélécharger la boîte entière à tous les clients.
        let temporaire = Ephemere::nouveau();
        {
            let boite = boite(&temporaire);
            fs::write(boite.root().join("new").join("1724832000.M9.autre"), b"abc").expect("dépôt");
            fs::write(
                boite.root().join("cur").join("1724832001.M9.autre:2,S"),
                b"defg",
            )
            .expect("dépôt");
        }
        let boite = boite(&temporaire);

        let dans_new = noms(&boite, "new");
        let lu = MessageName::parse(&dans_new[0]).expect("relisible");
        assert!(lu.uid().is_some(), "le message n'a pas été adopté");
        assert_eq!(lu.size(), Some(3));
        assert!(!lu.has_info());

        let dans_cur = noms(&boite, "cur");
        let lu = MessageName::parse(&dans_cur[0]).expect("relisible");
        assert!(lu.uid().is_some());
        assert_eq!(lu.size(), Some(4));
        // L'adoption N'EFFACE PAS les drapeaux : ils étaient l'état du message.
        assert!(lu.flags().contains(Flags::SEEN));

        assert_eq!(boite.summary().expect("résumable").unnumbered, 0);
    }

    #[test]
    fn un_hote_qui_casserait_un_nom_est_transpose() {
        // Maildir prescrit de remplacer `/` et `:` plutôt que de refuser.
        let temporaire = Ephemere::nouveau();
        let boite = Maildir::open(&temporaire.0, b"ho/te:bizarre").expect("ouvrable");
        let arrivee = boite.deliver().expect("remise ouverte");
        arrivee.commit().expect("validation");
        let dans_new = noms(&boite, "new");
        assert!(MessageName::parse(&dans_new[0]).is_ok());
    }

    #[test]
    fn deux_remises_de_la_meme_seconde_ne_se_disputent_pas_un_nom() {
        let temporaire = Ephemere::nouveau();
        let boite = boite(&temporaire);
        let une = boite.deliver().expect("remise ouverte");
        let autre = boite.deliver().expect("remise ouverte");
        une.commit().expect("validation");
        autre.commit().expect("validation");
        assert_eq!(noms(&boite, "new").len(), 2);
    }

    #[test]
    fn une_erreur_s_affiche_et_dit_quelque_chose() {
        let erreur = Error::UidExhausted;
        assert!(format!("{erreur}").len() > 20);
        assert!(!format!("{erreur:?}").is_empty());
        let nom = Error::Name(ams_index::NameError::Empty);
        assert!(format!("{nom}").len() > 10);
        let io = Error::from(std::io::Error::other("essai"));
        assert!(format!("{io}").len() > 10);
        assert!(std::error::Error::source(&io).is_some());
        assert!(std::error::Error::source(&erreur).is_none());
    }
}
