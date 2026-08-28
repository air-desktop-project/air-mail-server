//! Une boîte Maildir : `tmp/`, `new/`, `cur/`.

use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ams_index::{
    Flags, MailboxState, MailboxSummary, MessageName, Uid, UidValidity, compose, reconcile,
    reserved_watermark, summarise,
};

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
    /// L'`UIDVALIDITY`, décidée à l'ouverture et fixe ensuite.
    uid_validity: UidValidity,
    /// Jusqu'où l'index écrit sur le disque couvre les UID déjà servis.
    ///
    /// Au-delà, il faut le réécrire AVANT de servir l'UID : c'est ce qui rend le
    /// filigrane vrai même après un arrêt brutal.
    reserve: Mutex<Uid>,
}

/// Une `UIDVALIDITY` tirée de l'horloge.
///
/// # Pourquoi l'horloge, et pourquoi elle suffit
///
/// La RFC 9051 §2.3.1.1 demande une valeur qui **ne redescend jamais** pour une
/// même boîte. Les secondes écoulées depuis l'époque tiennent cette promesse
/// tant que l'horloge de la machine avance, et elles ne sont pas coordonnées
/// entre boîtes — ce que la RFC n'exige pas.
///
/// Elle n'est employée que lorsqu'il n'y a **pas** d'index à relire : une boîte
/// qui en a un garde la sienne pour toujours.
///
/// La saturation à `1` est là pour deux cas également invraisemblables et
/// également silencieux : une horloge d'avant 1970, et le débordement de 2106.
/// Rendre zéro serait rendre une valeur que la RFC interdit.
#[must_use]
pub fn fresh_uid_validity() -> UidValidity {
    let secondes = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |ecoule| ecoule.as_secs());
    UidValidity::new(u32::try_from(secondes).unwrap_or(u32::MAX)).unwrap_or(
        // `new(1)` ne peut pas rendre `None` ; l'écrire ainsi évite une branche
        // qu'aucun test ne pourrait atteindre.
        UidValidity::new(1).unwrap_or(UidValidity::MIN),
    )
}

/// Le nom du fichier d'index, dans la racine de la boîte.
///
/// Il n'est ni dans `cur/`, ni dans `new/`, ni dans `tmp/` : ces trois-là ne
/// contiennent que des messages, et y déposer autre chose ferait compter l'index
/// comme un courrier illisible par tout outil Maildir — le nôtre compris.
const NOM_INDEX: &str = "ams-index.bin";

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
    pub fn open(
        racine: impl Into<PathBuf>,
        hote: &[u8],
        validite: UidValidity,
    ) -> Result<Self, Error> {
        let racine = racine.into();
        for sous in ["tmp", "new", "cur"] {
            fs::create_dir_all(racine.join(sous))?;
        }
        let mut boite = Self {
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
            uid_validity: validite,
            reserve: Mutex::new(Uid::FIRST),
        };

        // LES FICHIERS D'ABORD, L'INDEX ENSUITE. Le parcours dit ce qui EST ;
        // l'index dit seulement ce qui A ÉTÉ. Confronter les deux dans cet ordre
        // rend impossible qu'un index périmé fasse oublier un message présent.
        let resume = boite.scan()?;
        let ecrit = boite.lire_index();
        let vu = reconcile(ecrit, &resume, validite);

        boite.uid_validity = vu.state.uid_validity;
        boite
            .prochain_uid
            .store(vu.state.uid_next.value(), Ordering::Relaxed);
        boite.adopter()?;

        // On réserve dès l'ouverture, ce qui réécrit l'index : une boîte ouverte
        // puis abandonnée sans remise laisse tout de même un index valide.
        boite.etendre_la_reserve(vu.state.uid_next)?;
        Ok(boite)
    }

    /// L'`UIDVALIDITY` de cette boîte (RFC 9051 §2.3.1.1).
    #[must_use]
    pub const fn uid_validity(&self) -> UidValidity {
        self.uid_validity
    }

    /// Relit l'index, ou rend `None` s'il n'y en a pas d'utilisable.
    ///
    /// # Un index illisible est un index ABSENT, pas une panne
    ///
    /// Fichier manquant, octet retourné, message tronqué : les trois mènent au
    /// même endroit — on reconstruit, et l'`UIDVALIDITY` change. Refuser
    /// d'ouvrir la boîte transformerait un octet retourné en indisponibilité,
    /// alors que tous les messages sont là et que leurs UID le sont aussi.
    fn lire_index(&self) -> Option<MailboxState> {
        let octets = fs::read(self.racine.join(NOM_INDEX)).ok()?;
        ams_config::decode_index(&octets).ok()
    }

    /// Écrit l'index, atomiquement et durablement.
    ///
    /// Même discipline qu'un message : écrire ailleurs, `fsync`, renommer,
    /// `fsync` du répertoire. Le second est celui qu'on oublie — sans lui, le
    /// renommage peut ne pas survivre à une coupure, et l'index reviendrait à sa
    /// valeur d'avant.
    fn ecrire_index(&self, etat: MailboxState) -> Result<(), Error> {
        let octets = ams_config::encode_index(&etat).map_err(|_| Error::IndexUnwritable)?;
        let provisoire = self.racine.join("tmp").join(NOM_INDEX);
        {
            let mut fichier = File::create(&provisoire)?;
            fichier.write_all(&octets)?;
            fichier.sync_all()?;
        }
        fs::rename(&provisoire, self.racine.join(NOM_INDEX))?;
        File::open(&self.racine)?.sync_all()?;
        Ok(())
    }

    /// Porte le filigrane écrit au-delà de `atteint`, s'il ne l'est pas déjà.
    fn etendre_la_reserve(&self, atteint: Uid) -> Result<(), Error> {
        let mut reserve = self
            .reserve
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Un autre fil a pu étendre pendant qu'on attendait le verrou : on
        // relit sous le verrou plutôt que de réécrire pour rien.
        if atteint < *reserve {
            return Ok(());
        }
        let filigrane = reserved_watermark(atteint);
        self.ecrire_index(MailboxState {
            uid_validity: self.uid_validity,
            uid_next: filigrane,
        })?;
        *reserve = filigrane;
        Ok(())
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
        // AVANT de servir l'UID, et non après : un arrêt entre les deux doit
        // laisser un filigrane qui COUVRE ce qu'on s'apprête à donner. L'ordre
        // inverse rendrait le même UID deux fois.
        self.etendre_la_reserve(uid)?;
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

    /// Le prochain UID que cette boîte servira.
    ///
    /// **Ce n'est pas toujours « le plus grand des noms, plus un »** : après une
    /// réouverture, il repart du filigrane écrit, donc plus loin. Voir
    /// [`ams_index::UID_RESERVATION`] pour ce que ce saut achète.
    ///
    /// [`MailboxSummary::next_uid`], lui, dit ce que les FICHIERS portent. Les
    /// deux répondent à deux questions différentes, et les confondre ferait
    /// annoncer à un opérateur un numéro qui ne sera pas servi.
    #[must_use]
    pub fn next_uid(&self) -> Uid {
        Uid::new(self.prochain_uid.load(Ordering::Relaxed)).unwrap_or(Uid::FIRST)
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
    use ams_index::{Flags, MessageName, Uid, UidValidity};
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

    /// Une validité FIXE : ces tests parlent des fichiers, pas de l'horloge.
    const VALIDITE: UidValidity = UidValidity::MIN;

    fn boite(temporaire: &Ephemere) -> Maildir {
        Maildir::open(&temporaire.0, b"mail.example.com", VALIDITE).expect("ouvrable")
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
        // Ce que les FICHIERS portent : trois messages, donc le suivant serait
        // le quatrième.
        let boite = boite(&temporaire);
        assert_eq!(boite.summary().expect("résumable").next_uid.value(), 4);

        // Ce que la boîte SERVIRA : le filigrane réservé, c'est-à-dire plus
        // loin. LE TROU EST VOULU. Reprendre à quatre demanderait d'avoir écrit
        // l'index à chaque remise ; sauter jusqu'à 255 numéros ne coûte rien à
        // personne (RFC 9051 §2.3.1.1), là où réattribuer un numéro déjà servi
        // montrerait à un client un message pour un autre.
        let prochain = boite.next_uid().value();
        assert!(
            prochain > 3,
            "le filigrane doit couvrir ce qui a déjà été servi"
        );
        let arrivee = boite.deliver().expect("remise ouverte");
        assert_eq!(arrivee.commit().expect("validation").value(), prochain);
    }

    #[test]
    fn l_uidvalidity_survit_a_une_reouverture() {
        // C'EST TOUTE LA RAISON D'ÊTRE DE L'INDEX. Si elle changeait à chaque
        // ouverture, tous les clients resynchroniseraient la boîte entière à
        // chaque redémarrage du serveur.
        let temporaire = Ephemere::nouveau();
        let validite = {
            let boite = Maildir::open(&temporaire.0, b"h", VALIDITE).expect("ouvrable");
            boite.deliver().expect("remise").commit().expect("validée");
            boite.uid_validity()
        };
        // On rouvre avec une AUTRE validité candidate : elle doit être ignorée,
        // puisque l'index en porte déjà une.
        let autre = UidValidity::new(999_999).expect("non nulle");
        let boite = Maildir::open(&temporaire.0, b"h", autre).expect("ouvrable");
        assert_eq!(boite.uid_validity(), validite);
        assert_ne!(boite.uid_validity(), autre);
    }

    #[test]
    fn un_index_perdu_fait_changer_l_uidvalidity_et_ne_perd_aucun_uid() {
        // L'index effacé — sauvegarde partielle, disque changé, curieux. Les
        // messages sont là, leurs UID sont dans leurs noms : rien n'est perdu.
        // Ce qui est perdu, c'est le filigrane, donc la promesse de ne pas
        // réattribuer. L'`UIDVALIDITY` change pour le DIRE aux clients.
        let temporaire = Ephemere::nouveau();
        {
            let boite = Maildir::open(&temporaire.0, b"h", VALIDITE).expect("ouvrable");
            for _ in 0..3 {
                boite.deliver().expect("remise").commit().expect("validée");
            }
        }
        fs::remove_file(temporaire.0.join("ams-index.bin")).expect("index effacé");

        let autre = UidValidity::new(999_999).expect("non nulle");
        let boite = Maildir::open(&temporaire.0, b"h", autre).expect("ouvrable");
        assert_eq!(boite.uid_validity(), autre, "l'UIDVALIDITY devait changer");
        // Les trois messages sont toujours là, avec leurs UID.
        let resume = boite.summary().expect("résumable");
        assert_eq!(resume.numbered, 3);
        assert_eq!(resume.next_uid.value(), 4);
    }

    #[test]
    fn un_index_illisible_vaut_un_index_absent() {
        // Un octet retourné ne doit pas rendre une boîte inouvrable : tous les
        // messages sont là, et leurs UID aussi. On reconstruit, et
        // l'`UIDVALIDITY` change — ce qui est exactement ce qu'un index absent
        // provoque.
        let temporaire = Ephemere::nouveau();
        {
            let boite = Maildir::open(&temporaire.0, b"h", VALIDITE).expect("ouvrable");
            boite.deliver().expect("remise").commit().expect("validée");
        }
        fs::write(
            temporaire.0.join("ams-index.bin"),
            b"ceci n'est pas un index",
        )
        .expect("écriture");

        let autre = UidValidity::new(999_999).expect("non nulle");
        let boite = Maildir::open(&temporaire.0, b"h", autre).expect("ouvrable");
        assert_eq!(boite.uid_validity(), autre);
        // Et l'index a été RÉÉCRIT : la prochaine ouverture n'aura plus à
        // changer quoi que ce soit.
        let encore = Maildir::open(&temporaire.0, b"h", VALIDITE).expect("ouvrable");
        assert_eq!(encore.uid_validity(), autre);
    }

    #[test]
    fn l_index_n_est_pas_compte_comme_un_message() {
        // Il vit dans la RACINE, pas dans `cur/` ni `new/`. S'il y était, tout
        // outil Maildir le compterait comme un courrier illisible — le nôtre le
        // premier.
        let temporaire = Ephemere::nouveau();
        let boite = Maildir::open(&temporaire.0, b"h", VALIDITE).expect("ouvrable");
        assert!(temporaire.0.join("ams-index.bin").is_file());
        let resume = boite.summary().expect("résumable");
        assert_eq!(resume.unreadable, 0);
        assert_eq!(resume.numbered, 0);
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
        let boite = Maildir::open(&temporaire.0, b"ho/te:bizarre", VALIDITE).expect("ouvrable");
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
