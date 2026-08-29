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
use std::vec::Vec;

use ams_dkim::{
    BodyHasher, HeaderHasher, PublicKeyRecord, Signature, decoder_base64, hash_signed_headers,
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
}

impl Default for DkimStream {
    fn default() -> Self {
        Self::new()
    }
}

impl DkimStream {
    /// Ouvre la vérification.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entetes: Vec::new(),
            phase: Phase::Entetes,
            candidats: Vec::new(),
        }
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
    pub async fn finish(self, checker: &DkimChecker) -> Vec<DkimResult> {
        let Ok(message) = Message::parse(&self.entetes, &MimeLimits::DEFAULT) else {
            return Vec::new();
        };
        let mut verdicts = Vec::with_capacity(self.candidats.len());
        for candidat in self.candidats {
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
