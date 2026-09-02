//! Le fil entre la boucle et les boîtes.

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStringExt as _;
use std::sync::Arc;

use ams_loop_tokio::{Delivery, DeliveryFailure, Spool};
use ams_store::{Incoming, Maildir};

/// Les boîtes du serveur, une par compte, partagées par toutes les connexions.
///
/// # ELLE EST MODIFIABLE, PARCE QUE LES COMPTES LE SONT
///
/// Un compte créé par l'administration n'a pas de boîte : la carte était lue une
/// fois au démarrage, et un compte neuf aurait pu s'authentifier sans jamais rien
/// recevoir. Un demi-compte est pire qu'un refus, parce que rien ne le dit.
///
/// # UN `Arc<Maildir>` SORT, PAS UNE RÉFÉRENCE
///
/// Chaque lecture clone le pointeur et relâche le verrou. Rendre une référence
/// obligerait à tenir le verrou aussi longtemps qu'on s'en sert — c'est-à-dire
/// pendant une session IMAP entière, pendant laquelle aucun compte ne pourrait
/// être créé.
#[derive(Default)]
pub struct Boites {
    /// Une boîte par compte, par son nom.
    carte: std::sync::RwLock<BTreeMap<String, Arc<Maildir>>>,
    /// Les DOSSIERS déjà ouverts, par compte et par nom.
    ///
    /// # CE N'EST PAS QU'UNE ÉCONOMIE, MÊME SI C'EN EST UNE
    ///
    /// Ouvrir un Maildir relit son index, adopte les messages sans UID et
    /// réécrit l'index : le refaire à chaque `LIST` ou chaque `SELECT` coûterait
    /// un parcours de répertoire par commande. Le registre ne grandit que d'une
    /// entrée par dossier RÉELLEMENT ouvrable — un client ne peut donc pas le
    /// faire enfler en nommant des boîtes au hasard.
    ///
    /// # UN SEUL `Maildir` PAR RÉPERTOIRE, DANS TOUT LE PROCESSUS
    ///
    /// Et c'est surtout une CORRECTION, non une optimisation. Chaque
    /// `Maildir` numérote ce qu'il remet à partir d'un compteur qui lui est
    /// propre ; deux instances ouvertes sur le même répertoire serviraient le
    /// même UID à deux messages différents, et un client IMAP qui a mis l'un en
    /// cache montrerait l'autre.
    ///
    /// La boîte de réception l'évitait déjà, en n'existant qu'ici. Les dossiers
    /// vivaient dans le service IMAP — jusqu'à ce que la quarantaine DMARC ait,
    /// elle aussi, besoin d'en ouvrir un.
    dossiers: std::sync::RwLock<BTreeMap<(String, String), Arc<Maildir>>>,
}

impl Boites {
    /// La carte telle qu'elle est au démarrage.
    #[must_use]
    pub fn new(carte: BTreeMap<String, Arc<Maildir>>) -> Self {
        Self {
            carte: std::sync::RwLock::new(carte),
            dossiers: std::sync::RwLock::new(BTreeMap::new()),
        }
    }

    /// La boîte de ce compte, s'il en a une.
    #[must_use]
    pub fn get(&self, nom: &str) -> Option<Arc<Maildir>> {
        self.lire().get(nom).map(Arc::clone)
    }

    /// Ajoute cette boîte à la carte, ou remplace celle qui portait ce nom.
    pub fn poser(&self, nom: String, boite: Arc<Maildir>) {
        self.ecrire().insert(nom, boite);
    }

    /// Retire la boîte de ce compte de la carte.
    ///
    /// **LE RÉPERTOIRE RESTE SUR LE DISQUE**, et c'est délibéré : voir
    /// `ApiMaildir::supprimer_un_compte`.
    pub fn retirer(&self, nom: &str) {
        self.ecrire().remove(nom);
    }

    /// Le dossier de ce compte, ouvert par `faire` s'il ne l'est pas déjà.
    ///
    /// **`faire` est appelée SOUS LE VERROU**, et c'est délibéré : deux
    /// connexions qui ouvrent le même dossier en même temps en construiraient
    /// deux instances, et c'est exactement ce que ce registre existe pour
    /// empêcher. Elle rend `None` quand le dossier n'est pas ouvrable, et rien
    /// n'est alors retenu.
    pub fn dossier_ou(
        &self,
        compte: &str,
        nom: &str,
        faire: impl FnOnce() -> Option<Arc<Maildir>>,
    ) -> Option<Arc<Maildir>> {
        let clef = (compte.to_owned(), nom.to_owned());
        let mut ouverts = self.ecrire_dossiers();
        if let Some(deja) = ouverts.get(&clef) {
            return Some(Arc::clone(deja));
        }
        let boite = faire()?;
        ouverts.insert(clef, Arc::clone(&boite));
        Some(boite)
    }

    /// Oublie les dossiers ouverts que `garder` ne retient pas.
    ///
    /// Le prédicat reçoit le compte et le nom du dossier.
    pub fn oublier_les_dossiers(&self, mut garder: impl FnMut(&str, &str) -> bool) {
        self.ecrire_dossiers()
            .retain(|(compte, nom), _| garder(compte, nom));
    }

    /// Le verrou d'écriture des dossiers, empoisonnement compris.
    fn ecrire_dossiers(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, BTreeMap<(String, String), Arc<Maildir>>> {
        self.dossiers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Le verrou de lecture, empoisonnement compris.
    fn lire(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, Arc<Maildir>>> {
        self.carte
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Le verrou d'écriture, empoisonnement compris.
    fn ecrire(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<String, Arc<Maildir>>> {
        self.carte
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Remet un message dans **les boîtes de ses destinataires**.
///
/// # Pourquoi cette pièce vit dans le binaire
///
/// `ams-store` n'implémente pas [`Delivery`] : le trait appartient à la boucle,
/// et l'implémenter dans un écrivain de fichiers l'aurait fait dépendre de tokio.
/// L'adaptation appartient donc à qui connaît les deux — c'est-à-dire ici.
///
/// # Un message, plusieurs boîtes : ON ÉCRIT N FOIS
///
/// Un `RCPT` par destinataire, un seul `DATA`. Le message est donc écrit dans
/// chaque boîte, en parallèle, morceau par morceau.
///
/// **Un lien matériel serait moins cher** — un seul contenu sur le disque au
/// lieu de N — et c'est ce que font les serveurs qui optimisent. Il suppose en
/// revanche que toutes les boîtes vivent sur le même système de fichiers, ce que
/// rien ici ne garantit ni ne vérifie ; et il fait partager une inode entre des
/// comptes qui n'ont, par ailleurs, rien à partager. Le choix est fait dans ce
/// sens, il coûte de la place, et il est écrit ici plutôt que découvert.
///
/// # `block_in_place`, et pourquoi il n'est appelé QUE sur `finish`
///
/// Valider un message fait deux `fsync` par boîte — le fichier, puis le
/// répertoire — et un `fsync` peut prendre le temps d'une écriture disque.
/// L'appeler dans une tâche asynchrone bloquerait l'ordonnanceur ;
/// `block_in_place` sort le fil courant du bassin le temps de l'attente.
///
/// `append`, lui, ne fait qu'écrire dans le cache de pages : l'y envelopper
/// coûterait un déménagement de fil par morceau de message, pour rien.
///
/// **Cela exige l'ordonnanceur multi-fils** : `block_in_place` panique sur le
/// mono-fil. Le binaire le choisit, et c'est pour cela qu'il le choisit.
///
/// # ET CE QUI N'EST PAS D'ICI VA DANS LA FILE
///
/// Depuis que l'émission existe, une adresse qu'aucun compte ne déclare peut
/// avoir été acceptée au `RCPT` — mais seulement pour une session AUTHENTIFIÉE,
/// et seulement si l'exploitant a demandé l'émission (voir
/// `BoitesConnues::qui_relaie`). Elle arrive donc ici sans boîte, et c'est le
/// signe qu'il faut la mettre en file plutôt que de la refuser.
///
/// **Cette remise ne redécide RIEN de tout cela.** Elle ne sait pas si la
/// session était authentifiée, et elle n'a pas à le savoir : sans file
/// configurée, une adresse sans boîte est refusée, et c'est tout ce qu'elle a
/// besoin de vérifier. Deux endroits qui décideraient d'ouvrir un relais
/// finiraient par ne plus dire la même chose.
pub struct MaildirDelivery {
    boites: Arc<Boites>,
    comptes: Arc<crate::comptes::Comptes>,
    /// Les remises ouvertes, chacune avec le COMPTE dont elle est la boîte.
    ///
    /// Le nom du compte y est retenu parce que la quarantaine en a besoin
    /// APRÈS coup : le verdict tombe une fois le corps lu, et il faut alors
    /// savoir chez qui ouvrir le dossier.
    arrivees: Vec<(String, Incoming)>,
    /// La file, quand l'émission est ouverte.
    file: Option<Spool>,
    /// Le `MAIL FROM:` de cette transaction — voir [`Delivery::begin`].
    retour: Option<String>,
    /// Les destinataires qui ne sont pas d'ici.
    sortants: Vec<String>,
    /// Le message, RASSEMBLÉ, et seulement s'il y a un sortant.
    ///
    /// **On ne rassemble rien pour une remise purement locale** : une boîte
    /// s'écrit au fil de l'eau, et garder le message en mémoire ferait payer à
    /// chaque courrier reçu le prix d'une émission qui n'a pas lieu.
    corps: Vec<u8>,
    /// Ce qu'un message peut peser, pour que `corps` ne croisse pas sans fin.
    corps_max: usize,
    /// Combien d'octets réserver en tête pour l'en-tête de trace.
    ///
    /// Zéro : on n'en écrit pas, et rien n'est réservé.
    trace: usize,
    /// Le dossier où mettre de côté ce que `p=quarantine` vise.
    ///
    /// **Aucun : la quarantaine n'existe pas**, et le message va dans la boîte
    /// de réception comme n'importe quel autre.
    quarantaine: Option<String>,
    /// Ce message-ci doit-il être mis de côté ?
    ///
    /// Remis à faux par [`Delivery::begin`] : un second message sur la même
    /// connexion n'hérite pas du verdict du premier.
    ecarte: bool,
}

impl MaildirDelivery {
    /// Ouvre une remise vers ce jeu de boîtes. **Elle n'émet pas.**
    #[must_use]
    pub fn new(boites: Arc<Boites>, comptes: Arc<crate::comptes::Comptes>) -> Self {
        Self {
            boites,
            comptes,
            arrivees: Vec::new(),
            file: None,
            retour: None,
            sortants: Vec::new(),
            corps: Vec::new(),
            corps_max: 0,
            trace: 0,
            quarantaine: None,
            ecarte: false,
        }
    }

    /// Lui donne un dossier où mettre de côté ce que DMARC met en quarantaine.
    ///
    /// **C'est la seule façon d'ouvrir la quarantaine**, et elle se voit : sans
    /// cet appel, un `p=quarantine` est remis dans la boîte de réception, et le
    /// rapport agrégé le dit.
    #[must_use]
    pub fn avec_quarantaine(mut self, dossier: String) -> Self {
        self.quarantaine = Some(dossier);
        self
    }

    /// Lui donne de quoi mettre en file ce qui n'est pas d'ici.
    ///
    /// **C'est la seule façon d'ouvrir l'émission de ce côté**, et elle se voit :
    /// une remise se construit sans file, et l'appelant doit écrire une ligne
    /// pour la lui donner.
    #[must_use]
    pub fn avec_file(mut self, file: Spool, corps_max: usize) -> Self {
        self.file = Some(file);
        self.corps_max = corps_max;
        self
    }

    /// L'heure, en secondes depuis l'époque.
    fn maintenant() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |depuis| depuis.as_secs())
    }
}

impl Delivery for MaildirDelivery {
    fn begin(&mut self, return_path: Option<&[u8]>) {
        // Une nouvelle transaction n'hérite RIEN de la précédente : ni son
        // chemin de retour, ni ses sortants, ni son corps. Sans cela, un second
        // message émis sur la même connexion partirait à qui l'avait précédé.
        self.retour = return_path.map(|octets| String::from_utf8_lossy(octets).into_owned());
        self.sortants.clear();
        self.corps.clear();
        self.ecarte = false;
    }

    fn reserve_trace(&mut self, combien: usize) {
        self.trace = combien;
    }

    fn quarantine(&mut self) -> bool {
        // **ON REND CE QU'ON PEUT FAIRE, ET NON CE QU'ON NOUS DEMANDE.** Sans
        // dossier configuré, le message est remis dans la boîte de réception,
        // et le rapport agrégé doit dire `none`.
        self.ecarte = self.quarantaine.is_some();
        self.ecarte
    }

    fn trace(&mut self, entete: &[u8]) {
        for (_, arrivee) in &mut self.arrivees {
            // **UN EN-TÊTE QU'ON NE SAIT PAS POSER NE FAIT PAS ÉCHOUER LA
            // REMISE.** Le message arrive alors avec une place réservée remplie
            // d'espaces plutôt qu'avec un en-tête ; c'est laid, et c'est bien
            // moins grave que de perdre le message.
            let _ = arrivee.set_prologue(entete);
        }
    }

    fn add_recipient(&mut self, address: &[u8]) -> Result<(), DeliveryFailure> {
        // **UN INSTANTANÉ PAR DESTINATAIRE** : ce qu'un administrateur change
        // pendant une transaction sera vu par la suivante, et non au milieu de
        // celle-ci.
        let comptes = self.comptes.vue();
        let Some(compte) = ams_auth::route(&comptes, address) else {
            return self.mettre_en_file(address);
        };
        let boite = self
            .boites
            .get(&compte.login)
            .ok_or(DeliveryFailure::Temporary)?;
        // Un `deliver` qui échoue — plus d'UID, disque plein — est TEMPORAIRE :
        // lui répondre « définitivement non » ferait jeter au pair un message
        // qui pourrait passer dans une heure.
        let mut arrivee = boite.deliver().map_err(|_| DeliveryFailure::Temporary)?;
        if self.trace > 0 {
            arrivee
                .reserve_prologue(self.trace)
                .map_err(|_| DeliveryFailure::Temporary)?;
        }
        self.arrivees.push((compte.login.clone(), arrivee));
        Ok(())
    }

    fn append(&mut self, chunk: &[u8]) -> Result<(), DeliveryFailure> {
        for (_, arrivee) in &mut self.arrivees {
            arrivee
                .write(chunk)
                .map_err(|_| DeliveryFailure::Temporary)?;
        }
        if !self.sortants.is_empty() {
            // LA BORNE EST CELLE DU MESSAGE, et elle est vérifiée ici aussi
            // plutôt que supposée : la session la tient déjà, mais un tampon qui
            // croît en mémoire au rythme d'un pair est exactement ce que C3
            // interdit de laisser sans garde.
            if self.corps.len().saturating_add(chunk.len()) > self.corps_max {
                return Err(DeliveryFailure::Permanent);
            }
            self.corps.extend_from_slice(chunk);
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), DeliveryFailure> {
        // AUCUN DESTINATAIRE, AUCUNE REMISE. La session n'accepte pas de `DATA`
        // sans `RCPT`, et accepter un message qui ne va nulle part reviendrait à
        // répondre `250` pour une boîte qui n'existe pas.
        if self.arrivees.is_empty() && self.sortants.is_empty() {
            return Err(DeliveryFailure::Temporary);
        }
        let arrivees = core::mem::take(&mut self.arrivees);
        // **LES BOÎTES D'ABORD, LA FILE ENSUITE**, et l'ordre n'est pas
        // indifférent. Si le second échoue après le premier, le pair réessaie et
        // le message arrive deux fois quelque part : dans cet ordre, ce
        // « quelque part » est une boîte d'ici. L'ordre inverse ferait partir un
        // doublon chez un tiers, que personne ne peut plus rattraper.
        let ecarte = self.ecarte;
        tokio::task::block_in_place(|| {
            for (compte, arrivee) in arrivees {
                // TOUT OU RIEN N'EST PAS TENABLE ICI : les `rename` sont
                // atomiques un par un, pas ensemble. Un échec au milieu laisse
                // les premiers remis, et le pair réessaiera — il recevra alors
                // le message en double dans ces boîtes-là. C'est le compromis
                // que fait tout serveur sans file d'attente, et le doublon est
                // moins grave que la perte.
                let ecrit = match ecarte
                    .then(|| self.dossier_de_quarantaine(&compte))
                    .flatten()
                {
                    // **LE DOSSIER ADOPTE LE MESSAGE, IL NE LE RECOPIE PAS** :
                    // le fichier est déjà écrit dans le `tmp/` de la boîte de
                    // réception, et un `rename` suffit à le nommer ailleurs.
                    Some(dossier) => dossier.adopt(arrivee),
                    None => arrivee.commit(),
                };
                ecrit
                    .map(|_uid| ())
                    .map_err(|_| DeliveryFailure::Temporary)?;
            }
            Ok(())
        })?;
        self.deposer_les_sortants()
    }

    fn abort(&mut self) {
        for (_, arrivee) in core::mem::take(&mut self.arrivees) {
            arrivee.abort();
        }
        // RIEN N'EST ENCORE EN FILE : le dépôt n'a lieu qu'au `finish`. Il n'y a
        // donc qu'à oublier ce qu'on avait rassemblé.
        self.sortants.clear();
        self.corps.clear();
    }
}

impl MaildirDelivery {
    /// Le dossier de quarantaine de ce compte, ouvert ou créé.
    ///
    /// # C'EST ICI QUE LE DOSSIER NAÎT
    ///
    /// `Maildir::open` crée l'arborescence qu'on lui nomme : le dossier existe
    /// donc à la première remise qui en a besoin, et pas avant. Un dossier vide
    /// créé au démarrage dans chaque compte annoncerait à tous une protection
    /// dont la plupart n'auront jamais l'usage.
    ///
    /// **Il passe par le registre du serveur** : un `Maildir` par répertoire
    /// dans tout le processus, IMAP compris — voir [`Boites::dossier_ou`].
    ///
    /// Rend `None` si le dossier ne s'ouvre pas ; le message va alors dans la
    /// boîte de réception, ce qui est la seule chose à faire de mieux que de le
    /// perdre.
    fn dossier_de_quarantaine(&self, compte: &str) -> Option<Arc<Maildir>> {
        let nom = self.quarantaine.as_ref()?;
        let arrivee = self.boites.get(compte)?;
        let racine = arrivee.root().to_path_buf();
        self.boites.dossier_ou(compte, nom, || {
            // La transcription est celle de Maildir++, la même qu'IMAP :
            // `Courrier/Junk` devient `.Courrier.Junk` à la racine du compte.
            let mut repertoire = std::vec::Vec::with_capacity(nom.len().saturating_add(1));
            repertoire.push(b'.');
            for octet in nom.bytes() {
                repertoire.push(if octet == b'/' { b'.' } else { octet });
            }
            let chemin = racine.join(std::ffi::OsString::from_vec(repertoire));
            Some(Arc::new(
                Maildir::open(chemin, arrivee.host(), ams_store::fresh_uid_validity()).ok()?,
            ))
        })
    }

    /// Retient une adresse qui n'est pas d'ici, pour la file.
    fn mettre_en_file(&mut self, address: &[u8]) -> Result<(), DeliveryFailure> {
        // **SANS FILE, UNE ADRESSE SANS BOÎTE EST UN REFUS**, et il est
        // TEMPORAIRE : la politique l'avait acceptée, donc le magasin a changé
        // sous nos pieds, et le pair a le droit de réessayer.
        let Some(_) = self.file.as_ref() else {
            return Err(DeliveryFailure::Temporary);
        };
        // **SANS CHEMIN DE RETOUR, ON NE MET RIEN EN FILE.** Un `MAIL FROM:<>`
        // ne désigne personne à qui rendre compte d'un échec, et §6.1 de
        // RFC 5321 interdit qu'une notification en engendre une autre. C'est
        // DÉFINITIF : aucune reprise ne donnera un expéditeur à ce message.
        if self.retour.is_none() {
            return Err(DeliveryFailure::Permanent);
        }
        self.sortants
            .push(String::from_utf8_lossy(address).into_owned());
        Ok(())
    }

    /// Dépose en file ce qui n'était pas d'ici.
    fn deposer_les_sortants(&mut self) -> Result<(), DeliveryFailure> {
        if self.sortants.is_empty() {
            return Ok(());
        }
        // Les deux `else` sont structurels : `mettre_en_file` a déjà refusé une
        // transaction qui n'aurait ni file ni chemin de retour, et rien ne peut
        // remplir `sortants` sans passer par elle.
        let (Some(file), Some(retour)) = (self.file.as_ref(), self.retour.as_ref()) else {
            return Err(DeliveryFailure::Permanent);
        };
        let sortants = core::mem::take(&mut self.sortants);
        let corps = core::mem::take(&mut self.corps);
        tokio::task::block_in_place(|| file.deposer(retour, &sortants, &corps, Self::maintenant()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Boites, MaildirDelivery};
    use ams_auth::Account;
    use ams_loop_tokio::Delivery as _;
    use ams_store::Maildir;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    /// Un répertoire qui s'efface quand le test finit.
    struct Ephemere(PathBuf);

    impl Ephemere {
        fn nouveau() -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |depuis| depuis.as_nanos());
            let chemin = std::env::temp_dir().join(format!(
                "ams-remise-{unique}-{:?}",
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&chemin).expect("créable");
            Self(chemin)
        }
    }

    impl Drop for Ephemere {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Un compte `marie`, sa boîte, et la remise qui les sert.
    fn remise(racine: &Path) -> (Arc<Boites>, MaildirDelivery) {
        let boite = Maildir::open(
            racine.join("marie"),
            b"mail.example.com",
            ams_store::fresh_uid_validity(),
        )
        .expect("ouvrable");
        let mut carte = BTreeMap::new();
        carte.insert(String::from("marie"), Arc::new(boite));
        let boites = Arc::new(Boites::new(carte));
        let comptes = Arc::new(crate::comptes::Comptes::new(
            racine.join("comptes.bin"),
            vec![Account {
                login: String::from("marie"),
                hash: String::new(),
                addresses: vec![String::from("marie@example.com")],
            }],
        ));
        let remise = MaildirDelivery::new(Arc::clone(&boites), comptes);
        (boites, remise)
    }

    /// Les noms de fichiers d'un sous-répertoire, triés.
    fn contenu(chemin: &Path) -> Vec<String> {
        let mut trouves: Vec<String> = std::fs::read_dir(chemin)
            .map(|entrees| {
                entrees
                    .filter_map(Result::ok)
                    .map(|entree| entree.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        trouves.sort();
        trouves
    }

    /// Remet un message, en disant si DMARC le met en quarantaine.
    fn remettre(remise: &mut MaildirDelivery, ecarter: bool) -> bool {
        remise.begin(Some(b"joe@example.net"));
        remise
            .add_recipient(b"marie@example.com")
            .expect("destinataire");
        remise
            .append(b"From: joe\r\n\r\nbonjour\r\n")
            .expect("corps");
        let ecarte = ecarter && remise.quarantine();
        remise.finish().expect("remis");
        ecarte
    }

    /// **SANS DOSSIER, LA QUARANTAINE N'EXISTE PAS — ET LA REMISE LE DIT.**
    ///
    /// C'est ce que le rapport agrégé écrira : `none`, parce que c'est ce qui a
    /// été fait.
    #[tokio::test(flavor = "multi_thread")]
    async fn sans_dossier_un_message_ecarte_va_dans_la_boite_de_reception() {
        let temporaire = Ephemere::nouveau();
        let (_boites, mut remise) = remise(&temporaire.0);

        assert!(
            !remettre(&mut remise, true),
            "rien n'est mis de côté sans dossier"
        );
        assert_eq!(contenu(&temporaire.0.join("marie").join("new")).len(), 1);
        assert!(!temporaire.0.join("marie").join(".Junk").exists());
    }

    /// **AVEC UN DOSSIER, LE MESSAGE Y VA — ET IL EST CRÉÉ À LA PREMIÈRE
    /// REMISE.**
    #[tokio::test(flavor = "multi_thread")]
    async fn un_message_ecarte_va_dans_le_dossier_nomme() {
        let temporaire = Ephemere::nouveau();
        let (_boites, remise) = remise(&temporaire.0);
        let mut remise = remise.avec_quarantaine(String::from("Junk"));

        assert!(remettre(&mut remise, true), "mis de côté, et il le dit");
        let compte = temporaire.0.join("marie");
        assert!(
            contenu(&compte.join("new")).is_empty(),
            "rien dans la boîte de réception"
        );
        assert!(
            contenu(&compte.join("tmp")).is_empty(),
            "rien n'est resté en attente"
        );
        let ecartes = contenu(&compte.join(".Junk").join("new"));
        assert_eq!(ecartes.len(), 1, "le message est dans le dossier");
        let lu =
            std::fs::read(compte.join(".Junk").join("new").join(&ecartes[0])).expect("lisible");
        assert_eq!(lu, b"From: joe\r\n\r\nbonjour\r\n");

        // ET LE MESSAGE SUIVANT N'HÉRITE PAS DU VERDICT DU PRÉCÉDENT.
        assert!(!remettre(&mut remise, false));
        assert_eq!(contenu(&compte.join("new")).len(), 1);
        assert_eq!(contenu(&compte.join(".Junk").join("new")).len(), 1);
    }

    /// **UN SEUL `Maildir` PAR RÉPERTOIRE**, remise et IMAP confondus : deux
    /// instances serviraient le même UID à deux messages différents.
    #[tokio::test(flavor = "multi_thread")]
    async fn le_dossier_de_quarantaine_est_celui_du_registre() {
        let temporaire = Ephemere::nouveau();
        let (boites, remise) = remise(&temporaire.0);
        let mut remise = remise.avec_quarantaine(String::from("Junk"));

        assert!(remettre(&mut remise, true));
        let depuis_le_registre = boites
            .dossier_ou("marie", "Junk", || panic!("il est déjà ouvert"))
            .expect("ouvert");
        // Le second message y prend l'UID suivant, et non le même.
        assert_ne!(
            depuis_le_registre.next_uid(),
            ams_index::Uid::FIRST,
            "le registre rend l'instance qui a déjà remis"
        );
    }
}
