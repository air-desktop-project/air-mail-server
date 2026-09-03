//! La vérification DKIM d'un message qui arrive (C9).
//!
//! # Le verdict n'arrive qu'APRÈS le corps, et cela change tout
//!
//! SPF conclut au `MAIL FROM:` — avant que le message existe. DKIM, lui, signe
//! le corps : son verdict ne peut pas être connu avant le dernier octet. Deux
//! conséquences, et les deux se voient ici.
//!
//! **Le condensat se calcule en flux.** On ne rassemble pas le message : un pair
//! choisirait sinon combien de mémoire on lui consacre. Seul le BLOC D'EN-TÊTE
//! est retenu — il faut pouvoir le relire pour condenser les champs que `h=`
//! nomme — et il est borné.
//!
//! **Rien n'est écrit dans le message.** Un en-tête de résultat se pose EN TÊTE,
//! or à ce moment-là le corps n'a pas encore été lu. L'écrire demanderait soit
//! de garder tout le message, soit de le récrire ; les deux méritent leur propre
//! décision, et c'est celle que DMARC portera. Ici, le verdict va au journal.
//!
//! # DKIM ne décide de rien tout seul
//!
//! Une signature qui échoue ne dit pas qu'un message est faux : elle dit que
//! CETTE signature ne vaut pas. Un message légitime traverse des listes de
//! diffusion qui le modifient, et sa signature tombe. RFC 7489 le pose : c'est
//! DMARC qui rapproche un `pass` DKIM du domaine de l'en-tête `From:`, et lui
//! seul qui décide. Ce module ne refuse donc aucun message.

use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use ams_dkim::{
    BodyHasher, Canon, Canonicalization, HeaderHasher, PublicKeyRecord, SIGNATURE_FIELD_MAX,
    Signature, Signer, SigningKey, TryCryptoRng, TryRng, decoder_base64, hash_signed_headers,
    verify,
};
use ams_mime::{Limits as MimeLimits, Message};

use crate::resolver::{Resolver, Txt};

/// Ce que le bloc d'en-tête peut faire.
///
/// Il est RETENU en entier : au-delà, on ne vérifie plus rien plutôt que de
/// laisser un pair choisir combien de mémoire il occupe. Deux cent
/// cinquante-six kibioctets majorent très largement un bloc réel — celui d'un
/// message qui a traversé vingt relais en fait quelques milliers.
const ENTETES_MAX: usize = 256 * 1024;

/// Le nombre de signatures qu'on vérifie.
///
/// Chacune coûte **une résolution DNS et une exponentiation modulaire**. Un
/// message qui en porterait cent ferait travailler la machine cent fois pour un
/// seul envoi : c'est une amplification, et elle se borne. Les messages réels en
/// portent une ou deux ; trois relais qui signent chacun font cinq au pire.
const SIGNATURES_MAX: usize = 5;

/// Ce qu'on a conclu d'une signature (RFC 8601 §2.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimVerdict {
    /// La signature est vraie.
    Pass,
    /// Elle est fausse : le corps ou les en-têtes ont changé.
    ///
    /// **Ce n'est pas « le message est faux »** : une liste de diffusion qui
    /// ajoute un pied de page casse une signature parfaitement honnête.
    Fail,
    /// La signature, la clé ou l'enregistrement sont irrecevables.
    PermError,
    /// La clé n'a pas pu être résolue. Le pair peut réessayer.
    TempError,
}

/// Ce qu'une signature a donné.
#[derive(Debug, Clone)]
pub struct DkimResult {
    /// Le domaine qui a signé (`d=`).
    pub domain: String,
    /// Le sélecteur (`s=`).
    pub selector: String,
    /// Le verdict.
    pub verdict: DkimVerdict,
    /// La clé se déclarait-elle en essai (`t=y`) ?
    ///
    /// RFC 6376 §3.6.1 : un échec ne doit alors pas être traité plus sévèrement
    /// qu'une absence de signature. Le dire ici évite que quelqu'un l'oublie
    /// plus loin.
    pub testing: bool,
}

/// De quoi vérifier les signatures d'un message.
#[derive(Debug, Clone)]
pub struct DkimChecker {
    resolveur: Resolver,
}

impl DkimChecker {
    /// Prépare un vérificateur sur un résolveur déjà ouvert.
    ///
    /// **Le même que SPF** : ce sont les mêmes serveurs, le même délai, et la
    /// même confiance — celle que la configuration accorde et que le serveur
    /// répète au démarrage.
    #[must_use]
    pub fn new(resolveur: Resolver) -> Self {
        Self { resolveur }
    }

    /// La clé publique d'un sélecteur, ou ce qui a empêché de l'avoir.
    async fn cle(&self, selecteur: &[u8], domaine: &[u8]) -> Result<Vec<Vec<u8>>, DkimVerdict> {
        // RFC 6376 §3.6.2.1 : `<sélecteur>._domainkey.<domaine>`, en `TXT`.
        let mut nom = Vec::with_capacity(
            selecteur
                .len()
                .saturating_add(domaine.len())
                .saturating_add(13),
        );
        nom.extend_from_slice(selecteur);
        nom.extend_from_slice(b"._domainkey.");
        nom.extend_from_slice(domaine);
        match self.resolveur.txt(&nom).await {
            Txt::Trouves(textes) => Ok(textes),
            // Pas de clé : la signature ne se vérifiera jamais (§6.1.2).
            Txt::Absent => Err(DkimVerdict::PermError),
            Txt::Panne => Err(DkimVerdict::TempError),
        }
    }
}

/// Ce qu'on trouve, ou non, à la place de la clé qu'on signe avec.
///
/// # POURQUOI QUATRE ISSUES, ET NON « BON » OU « MAUVAIS »
///
/// Les trois façons d'échouer ne demandent pas la même chose à l'exploitant. Une
/// clé DIFFÉRENTE veut dire que tout ce qu'on émet échoue déjà, et qu'il faut
/// corriger la zone. Une clé ABSENTE veut dire qu'il n'a pas encore publié, ou
/// que la propagation n'a pas eu lieu — attendre suffit peut-être. Un DNS
/// INJOIGNABLE ne dit rien du tout, et le faire passer pour un problème de zone
/// enverrait chercher au mauvais endroit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationDkim {
    /// Publié, et c'est bien notre clé.
    Conforme,
    /// Publié, mais ce n'est PAS notre clé : tout ce qu'on émet échoue.
    Differente,
    /// Rien à ce nom : pas encore publié, ou pas encore propagé.
    Absente,
    /// On n'a pas su demander. **On ne conclut pas**, et on le dit.
    Injoignable,
}

/// La clé publique qu'un enregistrement porte, décodée.
///
/// # ON COMPARE LES OCTETS, JAMAIS LE TEXTE
///
/// Un hébergeur DNS reformate volontiers un `TXT` : il replie une longue valeur
/// en plusieurs chaînes, normalise les espaces après les points-virgules,
/// réordonne parfois les étiquettes. Comparer le texte signalerait « différente »
/// sur un enregistrement PARFAITEMENT CORRECT, et l'exploitant apprendrait à
/// ignorer l'avertissement — ce qui vaut moins que pas d'avertissement du tout.
///
/// Ce qui compte est le couple `k=` et la clé une fois dépliée et décodée : c'est
/// exactement ce qu'un vérificateur distant compare.
fn cle_publiee(texte: &[u8]) -> Option<(ams_dkim::KeyType, Vec<u8>)> {
    let enregistrement = ams_dkim::PublicKeyRecord::parse(texte).ok()?;
    let mut sans_blancs = std::vec![0_u8; enregistrement.key.len()];
    let deplie = enregistrement.key_base64(&mut sans_blancs).ok()?;
    let mut octets = std::vec![0_u8; deplie.len()];
    let combien = ams_dkim::decoder_base64(deplie, &mut octets).ok()?;
    octets.truncate(combien);
    Some((enregistrement.key_type, octets))
}

/// Ce que la zone porte, comparé à ce qu'on signe avec (RFC 6376 §3.6.2.1).
///
/// # POURQUOI LE SERVEUR PEUT TRANCHER TOUT SEUL
///
/// Il connaît sa clé privée, donc l'enregistrement attendu ; il connaît son
/// sélecteur et ses domaines, donc le nom à interroger ; et il tient déjà un
/// résolveur — la file en exige un, et l'on ne signe que ce qui passe par elle.
///
/// Sans cette question, une zone mal publiée ne se découvre que par les rapports
/// DMARC du domaine, des jours plus tard, et seulement si quelqu'un les lit.
pub async fn publication_dkim(
    resolveur: &Resolver,
    selecteur: &str,
    domaine: &str,
    cle: &ams_dkim::SigningKey,
) -> PublicationDkim {
    let mut nom = Vec::with_capacity(
        selecteur
            .len()
            .saturating_add(domaine.len())
            .saturating_add(13),
    );
    nom.extend_from_slice(selecteur.as_bytes());
    nom.extend_from_slice(b"._domainkey.");
    nom.extend_from_slice(domaine.as_bytes());

    let textes = match resolveur.txt(&nom).await {
        Txt::Trouves(textes) => textes,
        Txt::Absent => return PublicationDkim::Absente,
        Txt::Panne => return PublicationDkim::Injoignable,
    };
    let Some(attendue) = cle_publiee(&cle.public_record()) else {
        // Ce qu'on vient de composer se relit : notre propre lecteur l'accepte,
        // et un essai le vérifie. Cette branche dirait un défaut de ce code.
        return PublicationDkim::Injoignable;
    };
    // **UN SEUL ENREGISTREMENT SUFFIT.** Un nom peut en porter plusieurs — une
    // rotation de clé en cours, par exemple — et trouver le nôtre parmi eux est
    // ce qui compte : les autres ne nous concernent pas.
    match textes
        .iter()
        .any(|texte| cle_publiee(texte) == Some(attendue.clone()))
    {
        true => PublicationDkim::Conforme,
        false => PublicationDkim::Differente,
    }
}

/// Où en est la détection de la ligne vide qui sépare en-tête et corps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// On accumule le bloc d'en-tête.
    Entetes,
    /// On condense le corps.
    Corps,
    /// Le bloc d'en-tête a débordé : on ne vérifie plus rien.
    Deborde,
}

/// Une signature retenue, et le condensat de corps qu'elle demande.
#[derive(Debug, Clone)]
struct Candidate {
    /// Le rang du champ `DKIM-Signature` dans le bloc d'en-tête.
    ///
    /// **On ne garde pas la signature analysée** : elle emprunterait le bloc
    /// que cette structure possède, ce qu'aucun type ne peut exprimer. On la
    /// relira — c'est quelques microsecondes, une fois par message.
    rang: usize,
    corps: BodyHasher,
}

/// La vérification d'un message pendant qu'il arrive.
#[derive(Debug, Clone)]
pub struct DkimStream {
    entetes: Vec<u8>,
    phase: Phase,
    candidats: Vec<Candidate>,
    condenser: bool,
}

impl DkimStream {
    /// Ouvre la lecture d'un message.
    ///
    /// `condenser` dit s'il faut suivre les signatures : DMARC a besoin du bloc
    /// d'en-tête même quand DKIM n'est pas vérifié, et condenser un corps qu'on
    /// ne vérifiera pas serait payer un SHA-256 pour rien.
    #[must_use]
    pub fn new(condenser: bool) -> Self {
        Self {
            entetes: Vec::new(),
            phase: Phase::Entetes,
            candidats: Vec::new(),
            condenser,
        }
    }

    /// Le bloc d'en-tête retenu, séparateur compris.
    ///
    /// Vide s'il a débordé, ou si le message n'en portait pas.
    #[must_use]
    pub fn headers(&self) -> &[u8] {
        &self.entetes
    }

    /// Donne un morceau du message, **dé-échappé** comme la remise le reçoit.
    pub fn update(&mut self, morceau: &[u8]) {
        match self.phase {
            Phase::Deborde => {}
            Phase::Corps => self.corps(morceau),
            Phase::Entetes => self.entetes(morceau),
        }
    }

    /// Accumule le bloc d'en-tête, et bascule dès qu'il se termine.
    fn entetes(&mut self, morceau: &[u8]) {
        if self.entetes.len().saturating_add(morceau.len()) > ENTETES_MAX {
            self.phase = Phase::Deborde;
            self.entetes = Vec::new();
            self.candidats = Vec::new();
            return;
        }
        // La ligne vide peut être coupée entre deux morceaux : on cherche donc à
        // partir des trois derniers octets déjà là.
        let depart = self.entetes.len().saturating_sub(3);
        self.entetes.extend_from_slice(morceau);
        let Some(rang) = self
            .entetes
            .get(depart..)
            .and_then(|queue| queue.windows(4).position(|f| f == b"\r\n\r\n"))
        else {
            return;
        };
        let fin = depart.saturating_add(rang).saturating_add(4);
        let reste = self.entetes.split_off(fin);
        self.demarrer();
        self.corps(&reste);
    }

    /// Le bloc est complet : on y cherche les signatures.
    fn demarrer(&mut self) {
        self.phase = Phase::Corps;
        let Ok(message) = Message::parse(&self.entetes, &MimeLimits::DEFAULT) else {
            // Un bloc qu'on ne sait pas découper ne se vérifie pas. Ce n'est pas
            // un refus du message : la session, elle, l'a accepté.
            return;
        };
        if !self.condenser {
            return;
        }
        for (rang, champ) in message.fields().enumerate() {
            if self.candidats.len() >= SIGNATURES_MAX {
                return;
            }
            if !champ.name_is(b"DKIM-Signature") {
                continue;
            }
            let Ok(signature) = Signature::parse(champ.raw_value()) else {
                // Une signature illisible ne se vérifie pas, et n'occupe pas une
                // des places : elle ne coûtera ni résolution ni exponentiation.
                continue;
            };
            self.candidats.push(Candidate {
                rang,
                corps: BodyHasher::new(signature.canonicalization.body, signature.body_length),
            });
        }
    }

    fn corps(&mut self, morceau: &[u8]) {
        for candidat in &mut self.candidats {
            candidat.corps.update(morceau);
        }
    }

    /// Termine, et rend un verdict par signature.
    ///
    /// Un message sans signature lisible rend une liste vide — c'est le `none`
    /// de la RFC 8601, et c'est la moitié du courrier.
    pub async fn finish(&mut self, checker: &DkimChecker) -> Vec<DkimResult> {
        let Ok(message) = Message::parse(&self.entetes, &MimeLimits::DEFAULT) else {
            return Vec::new();
        };
        let mut verdicts = Vec::with_capacity(self.candidats.len());
        for candidat in core::mem::take(&mut self.candidats) {
            let Some(champ) = message.fields().nth(candidat.rang) else {
                continue;
            };
            let Ok(signature) = Signature::parse(champ.raw_value()) else {
                continue;
            };
            let verdict = conclure(checker, &message, champ, &signature, candidat.corps).await;
            verdicts.push(verdict);
        }
        verdicts
    }
}

/// Conduit une signature jusqu'à son verdict.
async fn conclure(
    checker: &DkimChecker,
    message: &Message<'_>,
    champ: ams_mime::Field<'_>,
    signature: &Signature<'_>,
    corps: BodyHasher,
) -> DkimResult {
    let mut resultat = DkimResult {
        domain: String::from_utf8_lossy(signature.domain).into_owned(),
        selector: String::from_utf8_lossy(signature.selector).into_owned(),
        verdict: DkimVerdict::PermError,
        testing: false,
    };

    let (condensat_du_corps, ecrits) = corps.finish();
    // §6.1.1 : un corps plus court que ce que `l=` annonce fait échouer la
    // vérification. Sans ce contrôle, un pair ferait signer un long corps et
    // n'en livrerait qu'un début.
    if signature
        .body_length
        .is_some_and(|annonce| ecrits < annonce)
    {
        resultat.verdict = DkimVerdict::Fail;
        return resultat;
    }

    let textes = match checker.cle(signature.selector, signature.domain).await {
        Ok(textes) => textes,
        Err(verdict) => {
            resultat.verdict = verdict;
            return resultat;
        }
    };

    // Un sélecteur peut porter plusieurs `TXT` ; on prend le premier qui est une
    // clé DKIM lisible. Les autres parlent d'autre chose — un domaine en publie
    // pour bien des raisons.
    let Some((enregistrement, brut)) = textes
        .iter()
        .filter_map(|texte| PublicKeyRecord::parse(texte).ok().map(|lue| (lue, texte)))
        .next()
    else {
        return resultat;
    };
    let _ = brut;
    resultat.testing = enregistrement.testing;

    let mut sans_blancs = std::vec![0_u8; enregistrement.key.len()];
    let Ok(deplie) = enregistrement.key_base64(&mut sans_blancs) else {
        return resultat;
    };
    let mut cle = std::vec![0_u8; deplie.len()];
    let Ok(combien) = decoder_base64(deplie, &mut cle) else {
        return resultat;
    };
    cle.truncate(combien);

    let mut tampon = std::vec![0_u8; signature.signature.len()];
    let Ok(deplie) = signature.signature_base64(&mut tampon) else {
        return resultat;
    };
    let mut scellee = std::vec![0_u8; deplie.len()];
    let Ok(combien) = decoder_base64(deplie, &mut scellee) else {
        return resultat;
    };
    scellee.truncate(combien);

    let mut condensat = HeaderHasher::new(signature.canonicalization.header);
    hash_signed_headers(signature, &mut condensat, || {
        message
            .fields()
            .map(|champ| (champ.name(), champ.raw_value()))
    });
    if condensat
        .signature_field(champ.name(), champ.raw_value())
        .is_err()
    {
        return resultat;
    }

    resultat.verdict = match verify(
        signature,
        &enregistrement,
        &cle,
        &condensat_du_corps,
        &condensat.finish(),
        &scellee,
    ) {
        Ok(()) => DkimVerdict::Pass,
        // Le corps ou les en-têtes ont changé : la signature est fausse, et le
        // message n'est pas pour autant faux.
        Err(ams_dkim::Error::BodyHashMismatch | ams_dkim::Error::SignatureMismatch) => {
            DkimVerdict::Fail
        }
        // Tout le reste : une clé, une signature ou un algorithme irrecevables.
        Err(_) => DkimVerdict::PermError,
    };
    resultat
}

// ── Signer ce que ce serveur émet ───────────────────────────────────────────

/// De quoi signer : le sélecteur publié dans le DNS, et la clé qu'il nomme.
///
/// # LA CLÉ EST LUE UNE FOIS, AU DÉMARRAGE
///
/// Un serveur qui découvrirait à la première émission que sa clé est illisible
/// aurait déjà annoncé qu'il signe. Ce qui ne peut pas marcher doit refuser de
/// démarrer, et c'est pourquoi cette structure porte une clé DÉJÀ lue.
#[derive(Clone)]
pub struct DkimSigner {
    selector: String,
    key: Arc<SigningKey>,
}

/// # LA CLÉ N'APPARAÎT JAMAIS, ET C'EST POURQUOI CE `Debug` EST ÉCRIT À LA MAIN
///
/// `SigningKey` n'en a pas, délibérément : une clé privée qui figure dans une
/// trace n'est plus une clé privée, et c'est le genre de fuite qu'on ne
/// remarque qu'après. Le dérivé aurait forcé à lui en donner un.
impl core::fmt::Debug for DkimSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DkimSigner")
            .field("selector", &self.selector)
            .finish_non_exhaustive()
    }
}

/// Les champs qu'on couvre, dans l'ordre. **Chacun deux fois.**
///
/// # POURQUOI CEUX-LÀ, ET PAS TOUS
///
/// `h=` doit nommer ce qui identifie le message. Ceux-ci sont ceux qui disent de
/// qui il vient, à qui il va, de quoi il parle et comment il se lit — c'est-à-dire
/// tout ce qu'un lecteur regarde avant de décider s'il fait confiance.
///
/// `from` en fait partie, et c'est la condition sans laquelle la signature ne
/// dirait rien de l'auteur : le signataire refuse de l'omettre.
///
/// # POURQUOI CHACUN DEUX FOIS, ET C'EST LA MOITIÉ QUI COMPTE
///
/// §5.4.2 : un vérificateur prend, pour chaque nom listé, l'instance la plus
/// BASSE — celle d'origine. Un tiers qui PRÉFIXE un second `From:` laisse donc la
/// signature valable, pendant que la plupart des clients affichent le PREMIER.
/// Le message porte notre signature, s'aligne en DMARC sur notre domaine, et
/// s'affiche au nom de l'attaquant.
///
/// Nommer un champ deux fois scelle l'emplacement d'une seconde copie : elle
/// n'existe pas, la seconde demande porte donc sur du vide, et **l'ajouter casse
/// la signature**. C'est ce que §5.4.2 appelle « oversigning », et c'est la seule
/// parade — refuser un message à plusieurs `From:` ne protégerait que les nôtres.
///
/// # POURQUOI TOUS, ET NON LE SEUL `from`
///
/// `from` est le vecteur d'usurpation. Mais un second `Subject:` change ce qu'on
/// lit, un second `Content-Type:` change comment on le lit, et un second `To:`
/// change qui l'on croit destinataire. La règle uniforme — **tout ce qu'on
/// signe, on le signe aussi contre l'ajout** — se tient sans avoir à décider cas
/// par cas, et se garde vraie sans effort.
///
/// # UN CHAMP ABSENT NE FAIT PAS ÉCHOUER LA VÉRIFICATION
///
/// Ce commentaire l'a longtemps affirmé, et c'était faux. §5.4.2 est explicite :
/// un nom listé qu'aucun champ ne porte se condense comme du VIDE, des deux
/// côtés. [`hash_signed_headers`] le fait, et il sert à la fois à signer et à
/// vérifier — la symétrie est structurelle, pas espérée. C'est précisément ce
/// qui rend le sur-scellement possible.
const CHAMPS_SIGNES: [&[u8]; 14] = [
    b"from",
    b"from",
    b"to",
    b"to",
    b"subject",
    b"subject",
    b"date",
    b"date",
    b"message-id",
    b"message-id",
    b"mime-version",
    b"mime-version",
    b"content-type",
    b"content-type",
];

impl DkimSigner {
    /// Un signataire, à partir d'un sélecteur et d'une clé déjà lue.
    #[must_use]
    pub fn new(selector: String, key: Arc<SigningKey>) -> Self {
        Self { selector, key }
    }

    /// Signe un message, et rend celui qui porte sa signature.
    ///
    /// # UN MESSAGE QU'ON NE SAIT PAS SIGNER PART QUAND MÊME
    ///
    /// Il vaut mieux un rapport non signé qu'un rapport qui n'arrive pas : le
    /// destinataire n'en a pas moins besoin, et rien dans DMARC n'exige que nos
    /// propres rapports soient signés. Le refus serait une punition qu'on
    /// s'infligerait.
    ///
    /// Cela ne peut arriver que sur un défaut de ce code — la clé a été lue au
    /// démarrage, et le message vient d'être composé ici.
    #[must_use]
    pub fn sign(&self, message: Vec<u8>, from: &str, timestamp: u64) -> Vec<u8> {
        match self.champ(&message, from, timestamp) {
            Some(champ) => {
                // EN TÊTE, et non à la fin : §3.5 veut que le champ précède ce
                // qu'il couvre, et un vérificateur qui le trouve ailleurs ne
                // condense pas la même chose.
                let mut signe = champ;
                signe.extend_from_slice(&message);
                signe
            }
            None => message,
        }
    }

    /// Compose le champ `DKIM-Signature`, s'il se compose.
    fn champ(&self, message: &[u8], from: &str, timestamp: u64) -> Option<Vec<u8>> {
        let domaine = from.rsplit_once('@').map(|(_, apres)| apres)?;
        let lu = Message::parse(message, &MimeLimits::DEFAULT).ok()?;
        let canon = Canonicalization {
            header: Canon::Relaxed,
            body: Canon::Relaxed,
        };

        let mut corps = BodyHasher::new(canon.body, None);
        corps.update(lu.body());
        let (condensat, _) = corps.finish();

        let champs: Vec<(&[u8], &[u8])> = lu
            .fields()
            .map(|champ| (champ.name(), champ.raw_value()))
            .collect();

        let signataire = Signer {
            domain: domaine.as_bytes(),
            selector: self.selector.as_bytes(),
            canonicalization: canon,
            headers: &CHAMPS_SIGNES,
            timestamp: Some(timestamp),
            // Pas de `x=` : une signature qui expire fait échouer la
            // vérification d'un message archivé, et rien ici ne demande qu'elle
            // cesse de valoir.
            expiration: None,
            identity: None,
        };
        let mut sortie = std::vec![0_u8; SIGNATURE_FIELD_MAX];
        // L'AVEUGLEMENT, PARCE QUE NOUS SIGNONS À LA DEMANDE. Qui observe ce
        // serveur obtient autant de mesures qu'il veut ; sans aveuglement, RSA
        // les lui laisse exploiter.
        let mut alea = Urandom::ouvrir()?;
        let ecrits = signataire
            .sign_with(&self.key, &condensat, &champs, &mut alea, &mut sortie)
            .ok()?
            .len();
        sortie.truncate(ecrits);
        Some(sortie)
    }
}

/// Une source d'aléa qui lit `/dev/urandom`.
///
/// # POURQUOI UNE LECTURE BLOQUANTE EST ICI ACCEPTABLE
///
/// `/dev/urandom` ne bloque pas une fois la machine amorcée, et la signature
/// elle-même — une exponentiation RSA privée — occupe déjà le fil bien plus
/// longtemps. C'est pour cela que l'appelant signe hors de la boucle.
struct Urandom(std::fs::File);

impl Urandom {
    fn ouvrir() -> Option<Self> {
        std::fs::File::open("/dev/urandom").ok().map(Self)
    }
}

impl TryRng for Urandom {
    type Error = std::io::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut octets = [0_u8; 4];
        self.try_fill_bytes(&mut octets)?;
        Ok(u32::from_ne_bytes(octets))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut octets = [0_u8; 8];
        self.try_fill_bytes(&mut octets)?;
        Ok(u64::from_ne_bytes(octets))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        // ON NE SE RABAT SUR RIEN. Un aveuglement fait d'octets prévisibles ne
        // protège pas la clé : il donne à croire qu'elle l'est.
        std::io::Read::read_exact(&mut self.0, dst)
    }
}

impl TryCryptoRng for Urandom {}
