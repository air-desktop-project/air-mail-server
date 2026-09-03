//! Le fil entre la boucle et les boîtes.

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStringExt as _;
use std::sync::Arc;

use ams_loop_tokio::{Delivery, DeliveryFailure, DkimSigner, Spool};
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
    /// `ApiMaildir::retirer_un_compte`.
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
/// Ce qu'un destinataire sortant a demandé du sort de son message (RFC 3461).
///
/// Une structure nommée plutôt qu'un quadruplet : trois booléens de suite se
/// permutent sans que rien ne le dise, et celui qui compte le plus fait TAIRE
/// un rapport.
#[derive(Debug, Clone)]
struct Demande {
    never: bool,
    on_success: bool,
    on_delay: bool,
    original: String,
}

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
    /// Le compte qui s'est authentifié — voir [`Delivery::submitter`].
    ///
    /// **`None` INTERDIT D'ÉMETTRE AU NOM DE QUI QUE CE SOIT.** Une transaction
    /// anonyme ne met rien en file de toute façon ; ce champ dit, pour celles
    /// qui le font, quelle adresse le déposant a le droit d'affirmer.
    compte: Option<String>,
    /// De quoi signer ce qui sort (RFC 6376), quand une clé est nommée.
    dkim: Option<DkimSigner>,
    /// Les domaines dont on tient la zone, donc ceux pour lesquels on peut
    /// signer. **Signer ailleurs produirait une signature qui échoue partout.**
    domaines: Arc<Vec<String>>,
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
    /// L'identifiant d'enveloppe du déposant (RFC 3461 §4.4).
    envid: String,
    /// Ce que chaque destinataire SORTANT a demandé (§4.1, §4.2).
    ///
    /// Un par entrée de `sortants`, dans le même ordre : c'est ce qui suit le
    /// message dans la file.
    /// Ce que chaque sortant a demandé : silence, succès, retard, origine.
    rapports: Vec<Demande>,
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
            compte: None,
            dkim: None,
            domaines: Arc::new(Vec::new()),
            corps: Vec::new(),
            corps_max: 0,
            trace: 0,
            quarantaine: None,
            envid: String::new(),
            rapports: Vec::new(),
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
    /// Le signataire DKIM et les domaines pour lesquels il vaut.
    ///
    /// # SANS CET APPEL, RIEN N'EST SIGNÉ
    ///
    /// C'est le défaut qui ne ment pas : un serveur qu'on n'a pas doté d'une clé
    /// ne doit pas produire de signature, et surtout pas une signature que
    /// personne ne pourrait vérifier.
    pub fn avec_dkim(mut self, signataire: DkimSigner) -> Self {
        self.dkim = Some(signataire);
        self
    }

    /// Les domaines dont ce serveur tient la zone.
    ///
    /// # ILS NE SERVENT PAS QU'À SIGNER
    ///
    /// Ils disent aussi pour qui l'on peut fabriquer un `Message-ID:` (RFC 6409
    /// §8.3) : un identifiant d'un domaine qu'on ne tient pas ne serait unique
    /// que par chance. Les lier au signataire ferait dépendre la complétion de
    /// la présence d'une clé, ce qui n'a aucune raison d'être.
    #[must_use]
    pub fn avec_domaines(mut self, domaines: Arc<Vec<String>>) -> Self {
        self.domaines = domaines;
        self
    }

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
        // **L'IDENTITÉ AUSSI REPART DE RIEN**, et la boucle la repose juste
        // après si le pair est authentifié. La garder ferait émettre le message
        // suivant au nom du compte du précédent — sur la même connexion, un
        // `AUTH` puis un `RSET` suffiraient.
        self.compte = None;
        self.sortants.clear();
        self.corps.clear();
        self.envid.clear();
        self.rapports.clear();
        self.ecarte = false;
    }

    fn submitter(&mut self, login: &[u8]) {
        self.compte = Some(String::from_utf8_lossy(login).into_owned());
    }

    fn reserve_trace(&mut self, combien: usize) {
        self.trace = combien;
    }

    fn envelope_id(&mut self, id: &[u8]) {
        self.envid = String::from_utf8_lossy(id).into_owned();
    }

    fn recipient_report(&mut self, never: bool, on_success: bool, on_delay: bool, original: &[u8]) {
        // **SEULS LES SORTANTS EN ONT L'USAGE.** Un destinataire d'ici est remis
        // tout de suite, et son sort est dit au pair par le code de retour du
        // `DATA` — il n'y a pas de rapport à composer pour cela.
        if self.sortants.len() != self.rapports.len().saturating_add(1) {
            return;
        }
        self.rapports.push(Demande {
            never,
            on_success,
            on_delay,
            original: String::from_utf8_lossy(original).into_owned(),
        });
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

    /// **LE `Return-Path:` NE SUIT PAS CE QU'ON RELAIE** (RFC 5321 §4.4).
    ///
    /// Il n'appartient qu'à la remise finale. L'écrire dans le tampon sortant
    /// ferait porter au saut suivant un en-tête de notre main, au-dessus duquel
    /// il posera le sien à la remise : le message arriverait avec deux, et le
    /// nôtre serait le périmé des deux.
    fn append_final(&mut self, chunk: &[u8]) -> Result<(), DeliveryFailure> {
        for (_, arrivee) in &mut self.arrivees {
            arrivee
                .write(chunk)
                .map_err(|_| DeliveryFailure::Temporary)?;
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

    /// Le déposant a-t-il le droit d'écrire au nom de ce `From:` ?
    ///
    /// # POURQUOI CETTE RÈGLE EXISTE, ET POURQUOI ELLE EST NOUVELLE
    ///
    /// Rien ne la vérifiait sur ce chemin — la porte HTTP, elle, refusait déjà.
    /// Tant que rien n'était signé, une usurpation partait nue. Depuis que ce
    /// serveur signe ce qu'il émet, elle partirait **avec notre signature**, et
    /// passerait DMARC chez le destinataire : nous authentifierions un
    /// hameçonnage interne.
    ///
    /// Un compte authentifié comme `marie` ne peut donc écrire `From:` qu'avec
    /// une adresse qui lui route — ses alias compris, que `ams_auth::route`
    /// résout.
    ///
    /// # `None` REFUSE, ET C'EST VOULU
    ///
    /// Sans compte retenu, sans `From:` lisible, ou avec une adresse qui ne
    /// route vers personne : on ne sait pas au nom de qui ce message part, et
    /// l'émettre reviendrait à signer une identité qu'on n'a pas vérifiée.
    /// # UN MESSAGE PORTE DEUX IDENTITÉS, ET LES DEUX DOIVENT ÊTRE LES SIENNES
    ///
    /// Le `From:` dit qui a ÉCRIT ; le chemin de retour de l'enveloppe dit à qui
    /// l'échec REVIENDRA. Seul le premier était vérifié.
    ///
    /// Un compte pouvait donc déposer `MAIL FROM:<victime@ailleurs.test>` avec
    /// un `From:` parfaitement légitime. Deux conséquences, toutes deux
    /// silencieuses :
    ///
    ///   - **son rebond se perdait.** La file dépose les rapports dans une
    ///     boîte — jamais sur le réseau —, et cette adresse-là ne route vers
    ///     personne : `deliver` rend `false`, le rapport est compté perdu, et le
    ///     déposant n'apprend jamais que son message a échoué.
    ///   - **son courrier échouait en SPF** chez tous ses destinataires, le
    ///     domaine de l'enveloppe n'autorisant pas notre adresse. DMARC passait
    ///     encore par DKIM ; la réputation, elle, s'abîmait.
    ///
    /// La file s'appuyait par écrit sur ce qui n'était pas vérifié : « le chemin
    /// de retour est TOUJOURS l'une de ses adresses ». C'est vrai désormais,
    /// parce que c'est contrôlé ici — et non parce qu'on le déduit.
    ///
    /// # LE CHEMIN DE RETOUR ARRIVE EN ARGUMENT
    ///
    /// L'appelant vient de l'extraire, et une transaction sans chemin de retour
    /// n'atteint jamais ce point : le relire depuis `self` créerait une branche
    /// `None` que nul essai ne pourrait éprouver. C'est le même choix que
    /// `submitter` dans `accepts_recipient`.
    fn ecrit_bien_en_son_nom(&self, message: &ams_mime::Message<'_>, retour: &str) -> bool {
        let Some(compte) = self.compte.as_deref() else {
            return false;
        };
        let Some(champ) = message.fields().find(|champ| champ.name_is(b"from")) else {
            return false;
        };
        let Some(adresse) = ams_mime::bare_address(champ.raw_value()) else {
            return false;
        };
        // **LA MÊME LECTURE QUE LA PORTE HTTP**, et la même fonction de routage :
        // deux règles à deux endroits finissent par ne plus dire la même chose.
        let sien = |adresse: &[u8]| {
            ams_auth::route(&self.comptes.vue(), adresse).is_some_and(|vu| vu.login == compte)
        };
        sien(adresse) && sien(retour.as_bytes())
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

    /// Complète ce qu'un serveur de SOUMISSION doit compléter (RFC 6409 §8).
    ///
    /// # CE N'EST PAS LE TRAVAIL D'UN RELAIS
    ///
    /// §6.4 de RFC 5321 déconseille à un relais de toucher aux en-têtes d'un
    /// message qui n'est pas le sien. Cette fonction ne s'applique qu'au tampon
    /// SORTANT — et rien n'y entre qui ne soit une soumission, puisqu'un
    /// destinataire d'ailleurs n'est accepté que d'un pair authentifié.
    ///
    /// # LES CHAMPS VONT À LA FIN DU BLOC D'EN-TÊTE
    ///
    /// `Date:` et `Message-ID:` appartiennent à l'AUTEUR, pas au saut. Les poser
    /// en tête mettrait deux champs qui ne sont pas de la trace au-dessus de
    /// notre `Received:`, que §4.4 veut « at the beginning of the message
    /// content ».
    ///
    /// # UN MESSAGE QU'ON NE SAIT PAS LIRE PART TEL QUEL
    ///
    /// La même règle que pour la signature : le refuser serait une punition
    /// qu'on infligerait au déposant, et un message malformé qu'on fait suivre
    /// reste un message que quelqu'un attend.
    fn completer(&self, corps: Vec<u8>) -> Vec<u8> {
        let bornes = ams_mime::Limits::DEFAULT;
        let Ok(message) = ams_mime::Message::parse(&corps, &bornes) else {
            return corps;
        };
        let manquants = ams_mime::missing_submission_fields(&message);
        if manquants.rien() {
            return corps;
        }
        // **LE DOMAINE DE DROITE EST CELUI DU `From:`** : un `Message-ID` d'un
        // domaine qu'on ne tient pas ne serait unique que par chance, et c'est
        // l'unicité qui fait tout l'intérêt du champ (§3.6.4 de RFC 5322).
        let Some(domaine) = self.domaine_de_l_auteur(&message) else {
            return corps;
        };
        let unique = Self::unique();
        let mut place = [0_u8; ams_mime::SUBMISSION_FIELDS_MAX];
        let Ok(ecrits) = ams_mime::write_submission_fields(
            &mut place,
            manquants,
            Self::maintenant(),
            unique.as_bytes(),
            domaine.as_bytes(),
        ) else {
            return corps;
        };
        // `header_block` porte le CRLF du dernier champ et s'arrête AVANT la
        // ligne vide : la recomposition est sans ambiguïté.
        let mut complet =
            Vec::with_capacity(corps.len().saturating_add(ecrits.len()).saturating_add(2));
        complet.extend_from_slice(message.header_block());
        complet.extend_from_slice(ecrits);
        complet.extend_from_slice(b"\r\n");
        complet.extend_from_slice(message.body());
        complet
    }

    /// Le domaine du `From:`, s'il est l'un des nôtres.
    fn domaine_de_l_auteur(&self, message: &ams_mime::Message<'_>) -> Option<String> {
        let champ = message.fields().find(|champ| champ.name_is(b"from"))?;
        let adresse = ams_mime::bare_address(champ.raw_value())?;
        let adresse = core::str::from_utf8(adresse).ok()?;
        let (_, domaine) = adresse.rsplit_once('@')?;
        self.domaines
            .iter()
            .find(|notre| notre.eq_ignore_ascii_case(domaine))
            .cloned()
    }

    /// Une valeur qu'aucun autre message de ce serveur ne portera.
    ///
    /// # POURQUOI UN COMPTEUR DE PROCESSUS, ET NON D'INSTANCE
    ///
    /// Une remise se construit par TRANSACTION : un compteur porté par elle
    /// repartirait de zéro à chaque message, et deux messages de la même
    /// seconde partageraient leur identifiant. Le compteur vit donc aussi
    /// longtemps que le processus, et les nanosecondes le complètent pour que
    /// deux processus ne se rencontrent pas non plus.
    fn unique() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SUITE: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |depuis| u64::from(depuis.subsec_nanos()));
        let rang = SUITE.fetch_add(1, Ordering::Relaxed);
        format!(
            "{:x}-{:x}",
            nanos.rotate_left(24) ^ rang,
            Self::maintenant()
        )
    }

    /// Signe le message sortant (DKIM, RFC 6376), quand on peut le faire.
    ///
    /// # POURQUOI ICI, ET UNE SEULE FOIS
    ///
    /// La signature couvre le message tel qu'il partira ; le composer une fois
    /// au dépôt évite de le refaire à chaque tentative de remise — une
    /// exponentiation RSA par essai, sur un pair en panne, serait payée des
    /// dizaines de fois pour rien.
    ///
    /// # ON NE SIGNE QUE POUR UN DOMAINE QU'ON HÉBERGE
    ///
    /// `d=` vient du domaine du `From:`, et la clé publique se publie sous
    /// `<sélecteur>._domainkey.<domaine>`. Signer pour un domaine dont on ne
    /// tient pas la zone produirait une signature qui échoue PARTOUT — et un
    /// échec DKIM se voit dans les rapports DMARC du domaine usurpé. C'est pire
    /// que pas de signature du tout.
    ///
    /// # UN MESSAGE QU'ON NE SAIT PAS SIGNER PART QUAND MÊME
    ///
    /// La même règle que pour les rapports : le refuser serait une punition
    /// qu'on infligerait au déposant pour une faute qui n'est pas la sienne.
    fn signer(&self, corps: Vec<u8>) -> Vec<u8> {
        let (Some(signataire), Some(retour)) = (self.dkim.as_ref(), self.retour.as_ref()) else {
            return corps;
        };
        // **LE DOMAINE VIENT DU `From:`, PAS DU CHEMIN DE RETOUR** : c'est
        // l'auteur que DKIM authentifie, et c'est sur lui que DMARC alignera.
        let bornes = ams_mime::Limits::DEFAULT;
        let auteur = {
            let Ok(message) = ams_mime::Message::parse(&corps, &bornes) else {
                return corps;
            };
            let Some(champ) = message.fields().find(|champ| champ.name_is(b"from")) else {
                return corps;
            };
            // **LA MÊME LECTURE QU'À LA SOUMISSION HTTP**, et par la même
            // fonction : deux lectures d'un même champ finissent par ne plus
            // dire la même chose.
            let Some(adresse) = ams_mime::bare_address(champ.raw_value()) else {
                return corps;
            };
            String::from_utf8_lossy(adresse).into_owned()
        };
        let Some((_, domaine)) = auteur.rsplit_once('@') else {
            return corps;
        };
        if !self
            .domaines
            .iter()
            .any(|notre| notre.eq_ignore_ascii_case(domaine))
        {
            return corps;
        }
        let _ = retour;
        signataire.sign(corps, &auteur, Self::maintenant())
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
        let brut = core::mem::take(&mut self.corps);
        // **ON N'ÉMET PAS AU NOM DE QUELQU'UN D'AUTRE** (RFC 6409 §6.1). La
        // vérification vient AVANT la complétion et la signature : ce qu'on
        // refuse d'émettre n'a pas à être complété, et surtout pas à être signé.
        //
        // Le refus est DÉFINITIF : aucune reprise ne donnera au déposant le
        // droit d'écrire au nom d'un autre. Et il vaut pour le message entier —
        // il n'y a qu'un `From:` et qu'un chemin de retour, et ils sont faux ou
        // ils ne le sont pas.
        {
            let bornes = ams_mime::Limits::DEFAULT;
            let Ok(message) = ams_mime::Message::parse(&brut, &bornes) else {
                return Err(DeliveryFailure::Permanent);
            };
            if !self.ecrit_bien_en_son_nom(&message, retour) {
                return Err(DeliveryFailure::Permanent);
            }
        }
        // **COMPLÉTER PUIS SIGNER**, et pas l'inverse : la signature doit
        // couvrir ce qu'on ajoute. `h=` nomme `date` et `message-id` — les
        // signer absents laisserait un tiers les ajouter en route sans casser la
        // signature, ce qui est exactement ce que `h=` sert à empêcher.
        let brut = self.completer(brut);
        let corps = self.signer(brut);
        let rapports: Vec<ams_queue::Report<'_>> = self
            .rapports
            .iter()
            .map(|demande| ams_queue::Report {
                never: demande.never,
                on_success: demande.on_success,
                on_delay: demande.on_delay,
                // **UN MESSAGE QUI VIENT D'ARRIVER N'A PAS ENCORE TARDÉ** :
                // poser ce bit ici ferait taire l'avis de retard avant qu'il
                // n'ait eu lieu de partir.
                delay_sent: false,
                original: &demande.original,
            })
            .collect();
        let envid = self.envid.clone();
        tokio::task::block_in_place(|| {
            file.deposer(
                retour,
                &sortants,
                &rapports,
                &envid,
                &corps,
                Self::maintenant(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Boites, MaildirDelivery};
    use ams_auth::Account;
    use ams_loop_tokio::Delivery as _;
    use ams_loop_tokio::DeliveryFailure;
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

    // ── LES DEUX EN-TÊTES DE §4.4 NE VONT PAS AU MÊME ENDROIT ───────────────

    /// **LE `Return-Path:` NE SUIT PAS CE QU'ON RELAIE** (RFC 5321 §4.4).
    ///
    /// Il n'appartient qu'à la remise FINALE. Le laisser partir avec un message
    /// relayé ferait porter au saut suivant un en-tête de notre main, au-dessus
    /// duquel il posera le sien à la remise : le message arriverait avec deux, et
    /// le nôtre serait le périmé des deux.
    ///
    /// La trace `Received:`, elle, va aux DEUX : un relais doit poser la sienne.
    #[tokio::test(flavor = "multi_thread")]
    async fn le_chemin_de_retour_ne_part_pas_avec_ce_qu_on_relaie() {
        let temporaire = Ephemere::nouveau();
        let (_boites, mut remise) = remise(&temporaire.0);

        remise.begin(Some(b"marie@example.com"));
        remise
            .add_recipient(b"marie@example.com")
            .expect("une adresse d'ici");
        // Ce que la boucle écrit pour la remise finale, et pour tout le monde.
        remise
            .append_final(b"Return-Path: <marie@example.com>\r\n")
            .expect("en-tête final");
        remise
            .append(b"Received: from client ([192.0.2.1])\r\n")
            .expect("trace");
        remise
            .append(b"From: marie@example.com\r\n\r\nbonjour\r\n")
            .expect("corps");
        remise.finish().expect("remis");

        let boite = temporaire.0.join("marie").join("new");
        let noms = contenu(&boite);
        assert_eq!(noms.len(), 1, "{noms:?}");
        let ecrit = std::fs::read_to_string(boite.join(&noms[0])).expect("lisible");
        // **LA BOÎTE LOCALE LES A LES DEUX**, dans l'ordre de §4.4.
        assert!(
            ecrit.starts_with("Return-Path: <marie@example.com>\r\nReceived: from client "),
            "{ecrit:?}"
        );
    }

    /// **CE QU'ON RELAIE NE PORTE QUE LA TRACE.**
    ///
    /// Le tampon sortant est l'autre moitié de la propriété précédente : ce qui
    /// part vers le saut suivant ne doit pas porter notre `Return-Path:`.
    #[tokio::test(flavor = "multi_thread")]
    async fn ce_qu_on_relaie_ne_porte_que_la_trace() {
        let temporaire = Ephemere::nouveau();
        let (_boites, mut remise) = remise(&temporaire.0);

        remise.begin(Some(b"marie@example.com"));
        // On force un sortant sans file : `mettre_en_file` refuserait, alors on
        // écrit dans le tampon comme la boucle le fait, et l'on relit.
        remise
            .append_final(b"Return-Path: <marie@example.com>\r\n")
            .expect("en-tête final");
        remise
            .append(b"Received: from client ([192.0.2.1])\r\n")
            .expect("trace");
        // Sans destinataire sortant, le tampon reste vide : c'est `append` qui
        // décide, et c'est ce qu'on éprouve ici — l'en-tête final n'y va JAMAIS.
        assert!(remise.corps.is_empty());
    }

    // ── LA SIGNATURE DE CE QUI SORT (DKIM, RFC 6376) ────────────────────────

    /// Une clé Ed25519 d'épreuve, la même que celle d'`ams-loop-tokio`.
    const CLE_PRIVEE: &str = "-----BEGIN PRIVATE KEY-----\n\
         MC4CAQAwBQYDK2VwBCIEIPycWR71gsJjQjlyixhg1EFwd/RmkyoHfIBubnK3v8rE\n\
         -----END PRIVATE KEY-----\n";

    /// Un signataire d'épreuve, pour ces domaines.
    fn signataire(domaines: &[&str]) -> (ams_loop_tokio::DkimSigner, Arc<Vec<String>>) {
        let cle = ams_dkim::SigningKey::from_pem(CLE_PRIVEE.as_bytes()).expect("la clé se lit");
        (
            ams_loop_tokio::DkimSigner::new(String::from("epreuve"), Arc::new(cle)),
            Arc::new(domaines.iter().map(|nom| (*nom).to_string()).collect()),
        )
    }

    /// Met un message en file et rend ce qui y a été déposé.
    fn depose(remise: &mut MaildirDelivery, racine: &Path, de: &str) -> String {
        let entete = format!("From: {de}\r\nTo: ailleurs@autre.test\r\n\r\nbonjour\r\n");
        depose_tel_quel(remise, racine, de, &entete)
    }

    /// Dépose en dissociant l'ENVELOPPE de l'en-tête, et rend ce qu'il advient.
    ///
    /// Les autres bancs emploient la même adresse pour les deux, si bien
    /// qu'aucun n'éprouvait le cas où elles diffèrent — celui-là même que rien
    /// ne refusait.
    fn depose_avec_retour(
        remise: &mut MaildirDelivery,
        retour: &str,
        de: &str,
    ) -> Result<(), DeliveryFailure> {
        let message = format!("From: {de}\r\nTo: ailleurs@autre.test\r\n\r\nbonjour\r\n");
        remise.begin(Some(retour.as_bytes()));
        remise.submitter(b"marie");
        remise
            .add_recipient(b"ailleurs@autre.test")
            .expect("un sortant");
        remise.append(message.as_bytes()).expect("corps");
        remise.finish()
    }

    /// Le même, avec un message écrit à la main.
    fn depose_tel_quel(
        remise: &mut MaildirDelivery,
        racine: &Path,
        de: &str,
        message: &str,
    ) -> String {
        remise.begin(Some(de.as_bytes()));
        // **UNE SOUMISSION EST AUTHENTIFIÉE**, et c'est ce qui dit au nom de qui
        // elle écrit. Sans cela, la remise refuse — voir
        // `ecrit_bien_en_son_nom`.
        remise.submitter(b"marie");
        remise
            .add_recipient(b"ailleurs@autre.test")
            .expect("un sortant");
        remise.append(message.as_bytes()).expect("corps");
        remise.finish().expect("déposé");
        // Le message en file est le seul `.eml` du dossier.
        let file = racine.join("file");
        let nom = contenu(&file)
            .into_iter()
            .find(|nom| nom.ends_with(".eml"))
            .expect("un message en file");
        std::fs::read_to_string(file.join(nom)).expect("lisible")
    }

    /// Une remise dotée d'une file, pour éprouver ce qui SORT.
    fn remise_avec_file(racine: &Path) -> MaildirDelivery {
        remise_pour(racine, &["example.com"])
    }

    /// La même, pour les domaines qu'on lui nomme.
    fn remise_pour(racine: &Path, domaines: &[&str]) -> MaildirDelivery {
        std::fs::create_dir_all(racine.join("file")).expect("dossier");
        let (_boites, remise) = remise(racine);
        remise
            .avec_domaines(Arc::new(
                domaines.iter().map(|nom| (*nom).to_string()).collect(),
            ))
            .avec_file(
                ams_loop_tokio::Spool::new(
                    racine.join("file"),
                    ams_queue::Backoff::DEFAULT,
                    String::from("mail.example.com"),
                    String::from("postmaster@example.com"),
                ),
                1_048_576,
            )
    }

    /// **CE QUE NOS COMPTES ÉMETTENT EST SIGNÉ** (RFC 6376).
    ///
    /// Le serveur l'annonçait au démarrage — « ce qui est ÉMIS est signé » —
    /// alors que seuls les rapports l'étaient. L'exploitant publiait la clé,
    /// croyait son courrier signé, et ses utilisateurs échouaient en DMARC dès
    /// que SPF ne suffisait plus : un transfert, une liste de diffusion.
    #[tokio::test(flavor = "multi_thread")]
    async fn ce_que_nos_comptes_emettent_est_signe() {
        let temporaire = Ephemere::nouveau();
        let (signataire, domaines) = signataire(&["example.com"]);
        let mut remise = remise_avec_file(&temporaire.0)
            .avec_domaines(domaines)
            .avec_dkim(signataire);

        let ecrit = depose(&mut remise, &temporaire.0, "marie@example.com");
        // **EN TÊTE** : §3.5 veut que le champ précède ce qu'il couvre.
        assert!(ecrit.starts_with("DKIM-Signature: "), "{ecrit}");
        // `d=` vient du domaine du `From:` — c'est l'auteur que DKIM authentifie,
        // et c'est sur lui que DMARC alignera.
        assert!(ecrit.contains("d=example.com"), "{ecrit}");
        assert!(ecrit.contains("s=epreuve"), "{ecrit}");
        // Et le message suit, intact.
        assert!(ecrit.contains("From: marie@example.com\r\n"), "{ecrit}");
    }

    /// **UN MESSAGE PORTE DEUX IDENTITÉS, ET LES DEUX DOIVENT ÊTRE LES SIENNES.**
    ///
    /// Le `From:` était vérifié contre le compte authentifié ; le chemin de
    /// retour de l'enveloppe ne l'était pas. Un compte pouvait donc déposer
    /// `MAIL FROM:<victime@ailleurs.test>` avec un `From:` parfaitement
    /// légitime.
    ///
    /// Rien ne partait vers l'inconnu — la file DÉPOSE ses rapports dans une
    /// boîte, elle ne les émet jamais —, mais deux choses se perdaient en
    /// silence : le rebond, que cette adresse-là ne pouvait pas recevoir, et la
    /// conformité SPF du message chez tous ses destinataires.
    ///
    /// La file s'appuyait par écrit sur ce qui n'était pas vérifié : « le chemin
    /// de retour est TOUJOURS l'une de ses adresses ».
    #[tokio::test(flavor = "multi_thread")]
    async fn un_chemin_de_retour_etranger_est_refuse() {
        let temporaire = Ephemere::nouveau();
        let mut remise = remise_avec_file(&temporaire.0);

        let issue = depose_avec_retour(&mut remise, "victime@ailleurs.test", "marie@example.com");
        assert!(
            matches!(issue, Err(DeliveryFailure::Permanent)),
            "un chemin de retour qui n'est pas le sien doit être refusé : {issue:?}"
        );
        // ET RIEN N'EST PARTI : le refus précède la mise en file, comme il
        // précède la complétion et la signature.
        let file = temporaire.0.join("file");
        assert!(
            !contenu(&file).into_iter().any(|nom| nom.ends_with(".eml")),
            "un message refusé ne doit rien laisser en file"
        );
    }

    /// **ET LE SIEN PASSE**, sans quoi le refus précédent ne prouverait rien
    /// d'autre que l'existence d'un refus.
    #[tokio::test(flavor = "multi_thread")]
    async fn son_propre_chemin_de_retour_passe() {
        let temporaire = Ephemere::nouveau();
        let mut remise = remise_avec_file(&temporaire.0);

        depose_avec_retour(&mut remise, "marie@example.com", "marie@example.com")
            .expect("son propre chemin de retour doit passer");
        let file = temporaire.0.join("file");
        assert!(
            contenu(&file).into_iter().any(|nom| nom.ends_with(".eml")),
            "le message aurait dû être mis en file"
        );
    }

    /// **ON NE SIGNE PAS POUR UN DOMAINE DONT ON NE TIENT PAS LA ZONE.**
    ///
    /// La clé publique se publie sous `<sélecteur>._domainkey.<domaine>` : signer
    /// pour un domaine dont on ne tient pas la zone produirait une signature qui
    /// échoue PARTOUT — et un échec DKIM se voit dans les rapports DMARC du
    /// domaine usurpé. C'est pire que pas de signature du tout.
    ///
    /// # C'EST UNE SECONDE COUCHE, ET ELLE RESTE UTILE
    ///
    /// Depuis qu'un `From:` doit router vers le compte authentifié, et que le
    /// démarrage refuse un compte dont l'adresse sort des domaines annoncés, ce
    /// cas ne se présente plus en production. Il se présente ici, parce que le
    /// constructeur permet de ne nommer aucun domaine — et le jour où l'une des
    /// deux règles amont bougera, celle-ci tiendra encore.
    #[tokio::test(flavor = "multi_thread")]
    async fn on_ne_signe_pas_pour_un_domaine_qu_on_ne_tient_pas() {
        let temporaire = Ephemere::nouveau();
        let (signataire, _) = signataire(&["example.com"]);
        let mut remise = remise_pour(&temporaire.0, &[]).avec_dkim(signataire);

        let ecrit = depose(&mut remise, &temporaire.0, "marie@example.com");
        assert!(
            !ecrit.contains("DKIM-Signature"),
            "on a signé sans tenir la zone : {ecrit}"
        );
    }

    /// **SANS CLÉ, RIEN N'EST SIGNÉ** — et le message part quand même.
    ///
    /// Le refuser serait une punition qu'on infligerait au déposant pour une
    /// faute qui n'est pas la sienne.
    #[tokio::test(flavor = "multi_thread")]
    async fn sans_cle_le_message_part_sans_signature() {
        let temporaire = Ephemere::nouveau();
        let mut remise = remise_avec_file(&temporaire.0);

        let ecrit = depose(&mut remise, &temporaire.0, "marie@example.com");
        assert!(!ecrit.contains("DKIM-Signature"), "{ecrit}");
        assert!(ecrit.contains("From: marie@example.com\r\n"), "{ecrit}");
    }

    // ── LES DEVOIRS DE SOUMISSION (RFC 6409 §8) ─────────────────────────────

    /// **`Date:` EST L'UN DES DEUX SEULS CHAMPS OBLIGATOIRES** (§3.6 de
    /// RFC 5322), et §8.1 de RFC 6409 en fait le devoir du serveur de
    /// soumission.
    ///
    /// Un message qui sort sans est malformé : les filtres en aval le pénalisent
    /// lourdement, certains le refusent d'emblée — et le déposant ne saura
    /// jamais pourquoi son message n'arrive pas.
    #[tokio::test(flavor = "multi_thread")]
    async fn ce_qui_manque_a_une_soumission_est_complete() {
        let temporaire = Ephemere::nouveau();
        let mut remise = remise_avec_file(&temporaire.0);

        let ecrit = depose_tel_quel(
            &mut remise,
            &temporaire.0,
            "marie@example.com",
            "From: marie@example.com\r\nTo: ailleurs@autre.test\r\n\r\nbonjour\r\n",
        );
        assert!(ecrit.contains("\r\nDate: "), "{ecrit}");
        assert!(ecrit.contains("\r\nMessage-ID: <"), "{ecrit}");
        // **LE DOMAINE DE DROITE EST LE NÔTRE** : un identifiant d'un domaine
        // qu'on ne tient pas ne serait unique que par chance.
        assert!(ecrit.contains("@example.com>\r\n"), "{ecrit}");
        // **ET LES CHAMPS VONT À LA FIN DE L'EN-TÊTE**, pas au-dessus de la
        // trace : `Date:` et `Message-ID:` sont à l'auteur, pas au saut.
        let entete = ecrit.split("\r\n\r\n").next().expect("un en-tête");
        assert!(entete.starts_with("From: marie@example.com"), "{entete}");
        assert!(entete.contains("Date: "), "{entete}");
        // Le corps n'a pas bougé.
        assert!(ecrit.ends_with("\r\n\r\nbonjour\r\n"), "{ecrit}");
    }

    /// **CE QUI EST PRÉSENT N'EST PAS TOUCHÉ**, même écrit de travers.
    ///
    /// §8.1 ne demande que de combler une absence. Corriger une date douteuse
    /// serait décider à la place du déposant — la même faute que d'écrire un
    /// diagnostic à la place d'un pair.
    #[tokio::test(flavor = "multi_thread")]
    async fn ce_qui_est_present_n_est_pas_touche() {
        let temporaire = Ephemere::nouveau();
        let mut remise = remise_avec_file(&temporaire.0);

        let ecrit = depose_tel_quel(
            &mut remise,
            &temporaire.0,
            "marie@example.com",
            "From: marie@example.com\r\nDate: hier\r\nMessage-ID: <sien@example.com>\r\n\r\nbonjour\r\n",
        );
        assert!(ecrit.contains("Date: hier\r\n"), "{ecrit}");
        assert!(ecrit.contains("<sien@example.com>"), "{ecrit}");
        // Un seul de chaque : on n'en a pas ajouté par-dessus.
        assert_eq!(ecrit.matches("Date: ").count(), 1, "{ecrit}");
        assert_eq!(ecrit.matches("Message-ID: ").count(), 1, "{ecrit}");
    }

    /// **LA SIGNATURE COUVRE CE QU'ON A AJOUTÉ**, et c'est l'ordre qui le fait.
    ///
    /// `h=` nomme `date` et `message-id`. Signer AVANT de compléter laisserait un
    /// tiers les ajouter en route sans casser la signature — ce que `h=` sert
    /// précisément à empêcher.
    ///
    /// # CE QUE CET ESSAI PROUVE, ET CE QU'IL NE PROUVE PAS
    ///
    /// Il prouve que les deux ont lieu, et que la signature est posée par-dessus
    /// un message qui porte déjà les champs. **Il ne prouve PAS que la signature
    /// est valable sur eux** : seule une vérification cryptographique le dirait,
    /// et la clé publique Ed25519 qui correspond à celle-ci n'existe pas dans ces
    /// essais.
    ///
    /// L'ordre est donc tenu par CONSTRUCTION : un seul endroit enchaîne les
    /// deux, et il porte la raison. C'est écrit ici plutôt que laissé croire —
    /// un essai qui prétendrait prouver l'ordre par la position se tromperait,
    /// puisque la position est la même dans les deux ordres.
    #[tokio::test(flavor = "multi_thread")]
    async fn la_signature_est_posee_sur_un_message_deja_complete() {
        let temporaire = Ephemere::nouveau();
        let (signataire, domaines) = signataire(&["example.com"]);
        let mut remise = remise_avec_file(&temporaire.0)
            .avec_domaines(domaines)
            .avec_dkim(signataire);

        let ecrit = depose_tel_quel(
            &mut remise,
            &temporaire.0,
            "marie@example.com",
            "From: marie@example.com\r\nTo: ailleurs@autre.test\r\n\r\nbonjour\r\n",
        );
        assert!(ecrit.starts_with("DKIM-Signature: "), "{ecrit}");
        assert!(ecrit.contains("\r\nDate: "), "{ecrit}");
        assert!(ecrit.contains("\r\nMessage-ID: <"), "{ecrit}");
        // **CHAQUE NOM DEUX FOIS** : la seconde demande scelle l'emplacement
        // d'une copie qui n'existe pas, et l'ajouter casserait la signature.
        assert!(
            ecrit.contains("h=from:from:to:to:subject:subject:date:date:message-id:message-id"),
            "{ecrit}"
        );
    }

    /// **SANS DOMAINE À NOUS, RIEN N'EST COMPLÉTÉ.**
    ///
    /// On n'a alors rien d'unique à mettre à droite du `Message-ID:` — et un
    /// identifiant qui n'est unique que par chance ne vaut rien.
    #[tokio::test(flavor = "multi_thread")]
    async fn sans_domaine_a_nous_rien_n_est_complete() {
        let temporaire = Ephemere::nouveau();
        let mut remise = remise_pour(&temporaire.0, &[]);

        let ecrit = depose_tel_quel(
            &mut remise,
            &temporaire.0,
            "marie@example.com",
            "From: marie@example.com\r\nTo: ailleurs@autre.test\r\n\r\nbonjour\r\n",
        );
        assert!(!ecrit.contains("Date: "), "{ecrit}");
        assert!(!ecrit.contains("Message-ID: "), "{ecrit}");
    }

    /// **DEUX MESSAGES N'ONT PAS LE MÊME IDENTIFIANT**, même dans la même
    /// seconde.
    ///
    /// Une remise se construit par transaction : un compteur porté par elle
    /// repartirait de zéro à chaque message, et c'est exactement le cas que cet
    /// essai met en jeu.
    #[tokio::test(flavor = "multi_thread")]
    async fn deux_messages_n_ont_pas_le_meme_identifiant() {
        let temporaire = Ephemere::nouveau();
        let mut identifiants = std::collections::BTreeSet::new();
        for rang in 0..8 {
            let racine = temporaire.0.join(format!("envoi{rang}"));
            std::fs::create_dir_all(&racine).expect("dossier");
            let mut remise = remise_avec_file(&racine);
            let ecrit = depose_tel_quel(
                &mut remise,
                &racine,
                "marie@example.com",
                "From: marie@example.com\r\n\r\nbonjour\r\n",
            );
            let debut = ecrit.find("Message-ID: <").expect("complété") + 13;
            let fin = debut + ecrit[debut..].find('>').expect("fermé");
            assert!(
                identifiants.insert(ecrit[debut..fin].to_string()),
                "{ecrit}"
            );
        }
        assert_eq!(identifiants.len(), 8);
    }

    // ── ON N'ÉMET PAS AU NOM DE QUELQU'UN D'AUTRE (RFC 6409 §6.1) ───────────

    /// Tente un dépôt, et dit s'il a été accepté.
    fn tente(remise: &mut MaildirDelivery, compte: &[u8], message: &str) -> bool {
        remise.begin(Some(b"marie@example.com"));
        remise.submitter(compte);
        if remise.add_recipient(b"ailleurs@autre.test").is_err() {
            return false;
        }
        if remise.append(message.as_bytes()).is_err() {
            return false;
        }
        remise.finish().is_ok()
    }

    /// **UN COMPTE AUTHENTIFIÉ N'ÉCRIT PAS AU NOM D'UN AUTRE.**
    ///
    /// Rien ne le vérifiait sur ce chemin — la porte HTTP, elle, refusait déjà.
    /// Tant que rien n'était signé, une usurpation partait nue ; depuis que ce
    /// serveur signe ce qu'il émet, elle partirait AVEC NOTRE SIGNATURE et
    /// passerait DMARC chez le destinataire. Nous authentifierions un
    /// hameçonnage interne.
    #[tokio::test(flavor = "multi_thread")]
    async fn un_compte_n_ecrit_pas_au_nom_d_un_autre() {
        let temporaire = Ephemere::nouveau();
        let mut remise = remise_avec_file(&temporaire.0);

        assert!(
            !tente(
                &mut remise,
                b"marie",
                "From: patron@example.com\r\nTo: ailleurs@autre.test\r\n\r\nbonjour\r\n"
            ),
            "une usurpation interne est passée"
        );
        // Et rien n'a été mis en file : ce qu'on refuse ne part pas.
        assert!(
            !contenu(&temporaire.0.join("file"))
                .iter()
                .any(|nom| nom.ends_with(".eml")),
            "le message refusé est parti quand même"
        );
    }

    /// **SA PROPRE ADRESSE PASSE**, sans quoi cet essai ne dirait rien.
    #[tokio::test(flavor = "multi_thread")]
    async fn son_adresse_a_soi_passe() {
        let temporaire = Ephemere::nouveau();
        let mut remise = remise_avec_file(&temporaire.0);

        assert!(tente(
            &mut remise,
            b"marie",
            "From: marie@example.com\r\nTo: ailleurs@autre.test\r\n\r\nbonjour\r\n"
        ));
    }

    /// **SANS IDENTITÉ RETENUE, ON N'ÉMET RIEN.**
    ///
    /// Sans compte, sans `From:` lisible, ou avec une adresse qui ne route vers
    /// personne : on ne sait pas au nom de qui ce message part, et l'émettre
    /// reviendrait à signer une identité qu'on n'a pas vérifiée.
    #[tokio::test(flavor = "multi_thread")]
    async fn sans_identite_verifiable_rien_ne_part() {
        let temporaire = Ephemere::nouveau();
        let mut remise = remise_avec_file(&temporaire.0);

        // Aucun `From:` du tout.
        assert!(!tente(
            &mut remise,
            b"marie",
            "To: ailleurs@autre.test\r\n\r\nbonjour\r\n"
        ));
        // Un `From:` qui ne route vers aucun compte.
        assert!(!tente(
            &mut remise,
            b"marie",
            "From: inconnu@ailleurs.test\r\n\r\nbonjour\r\n"
        ));
        // Et un compte qu'on n'a pas retenu : `begin` sans `submitter`.
        remise.begin(Some(b"marie@example.com"));
        assert!(remise.add_recipient(b"ailleurs@autre.test").is_ok());
        assert!(
            remise
                .append(b"From: marie@example.com\r\n\r\nbonjour\r\n")
                .is_ok()
        );
        assert!(remise.finish().is_err(), "une transaction anonyme a émis");
    }

    /// **L'IDENTITÉ NE SURVIT PAS À LA TRANSACTION.**
    ///
    /// Sur une même connexion, un `AUTH` puis un `RSET` ne doivent pas laisser le
    /// message suivant partir au nom du compte du précédent.
    #[tokio::test(flavor = "multi_thread")]
    async fn l_identite_ne_survit_pas_a_la_transaction() {
        let temporaire = Ephemere::nouveau();
        let mut remise = remise_avec_file(&temporaire.0);

        assert!(tente(
            &mut remise,
            b"marie",
            "From: marie@example.com\r\n\r\nun\r\n"
        ));
        // La transaction suivante ne repose pas `submitter` : elle est anonyme.
        remise.begin(Some(b"marie@example.com"));
        assert!(remise.add_recipient(b"ailleurs@autre.test").is_ok());
        assert!(
            remise
                .append(b"From: marie@example.com\r\n\r\ndeux\r\n")
                .is_ok()
        );
        assert!(
            remise.finish().is_err(),
            "l'identité du message précédent a servi"
        );
    }
}
