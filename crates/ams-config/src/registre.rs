// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le registre de réception (0.2.44) : ce que le serveur savait, à l'instant,
//! de chaque session SMTP et de chaque message — voir
//! `docs/registre-de-reception.md`.
//!
//! # CE N'EST PAS UN JOURNAL
//!
//! Il se **conserve**. Un fichier par jour UTC, fait de trames ; le premier
//! enregistrement porte le condensat du fichier précédent, le dernier — posé à
//! minuit — celui de tout ce qui le précède. Une archive retouchée, tronquée
//! ou retirée se voit à la vérification.
//!
//! # UNE TRAME
//!
//! Quatre octets de longueur, petit boutien, puis un message Cap'n Proto d'un
//! `Enregistrement`, à plat. La longueur est bornée ([`TRAME_MAX`]) : un
//! fichier abîmé ne fait pas lire au-delà.
//!
//! # CE MODULE NE LIT NI N'ÉCRIT AUCUN FICHIER
//!
//! Il code, découpe et vérifie des octets ; le serveur tient le fichier, et
//! l'outil d'administration le relit (C1).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::IpAddr;

use capnp::message::ReaderOptions;
use capnp::serialize;
use sha2::Digest as _;

use crate::ams_registre_capnp::{IssueSession as IssueS, IssueTransaction as IssueT};
use crate::ams_registre_capnp::{
    Resultat as ResultatC, StatutDns as StatutDnsC, StatutSalut as StatutSalutC,
};
use crate::ams_registre_capnp::{
    abandon, dkim, enregistrement, entete, inverse, salut, sceau, session, transaction,
};

/// La version du format.
pub const FORMAT: u16 = 1;

/// La plus grande trame qu'on écrive ou qu'on lise : un mébioctet.
///
/// Un enregistrement réel pèse quelques kilooctets ; la borne empêche un
/// fichier abîmé d'annoncer une longueur qui ferait tout lire d'un coup.
pub const TRAME_MAX: usize = 1024 * 1024;

/// La plus longue valeur texte qu'un enregistrement garde : ce qui vient du
/// pair est borné, et la troncature se note.
pub const TEXTE_MAX: usize = 998;

/// Combien de noms `PTR`, de signatures DKIM, d'adresses ou de destinataires
/// un enregistrement garde au plus.
pub const LISTE_MAX: usize = 64;

/// Un enregistrement du registre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enregistrement {
    /// Le premier d'un fichier.
    Entete(Entete),
    /// Une connexion, écrite à sa fermeture.
    Session(Box<Session>),
    /// Un message.
    Transaction(Box<Transaction>),
    /// Une transaction écrite acceptée, que la remise n'a pas pu conclure.
    Abandon(Abandon),
    /// Le dernier d'un fichier.
    Sceau(Sceau),
}

/// Le premier enregistrement d'un fichier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entete {
    /// La version du format.
    pub format: u16,
    /// Le jour UTC, `AAAA-MM-JJ`.
    pub jour: String,
    /// Le SHA-256 du fichier précédent, en entier ; `None` pour le premier.
    pub precedent: Option<[u8; 32]>,
    /// Le serveur qui l'a ouvert.
    pub version: String,
    /// L'heure d'ouverture, en millisecondes.
    pub ouvert: u64,
}

/// Le dernier enregistrement d'un fichier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sceau {
    /// Combien d'enregistrements le précèdent, entête compris.
    pub enregistrements: u64,
    /// Le SHA-256 de tous les octets qui le précèdent.
    pub condensat: [u8; 32],
    /// L'heure du scellement, en millisecondes.
    pub scelle: u64,
    /// Combien d'octets d'une trame coupée ont été retirés au redémarrage.
    pub tronques: u64,
}

/// Ce qu'une résolution DNS a rendu.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StatutDns {
    /// Rien n'a été demandé.
    #[default]
    NonCherche,
    /// Une réponse.
    Trouve,
    /// Le nom n'existe pas, ou n'a rien de ce type.
    Absent,
    /// Pas de réponse, ou une réponse illisible.
    Panne,
}

/// Ce que la résolution inverse de l'adresse du pair a répondu.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inverse {
    /// Ce qu'elle a rendu.
    pub statut: StatutDns,
    /// Les noms désignés.
    pub noms: Vec<String>,
    /// Le plus petit TTL vu.
    pub ttl: u32,
    /// La réponse portait le bit `AD`.
    pub authentifiee: bool,
    /// Un des noms résout vers l'adresse du pair.
    pub confirmee: bool,
}

/// Ce que vaut le nom annoncé par HELO ou EHLO.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StatutSalut {
    /// Rien n'a été vérifié.
    #[default]
    NonVerifie,
    /// Un littéral d'adresse.
    Litteral,
    /// Il résout vers l'adresse du pair.
    PointeLePair,
    /// Il résout, ailleurs.
    PointeAilleurs,
    /// Il ne résout pas.
    NeResoutPas,
    /// La résolution a échoué.
    Panne,
}

/// Le nom annoncé par HELO ou EHLO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Salut {
    /// Tel qu'écrit, borné.
    pub nom: String,
    /// Ce qu'il vaut.
    pub statut: StatutSalut,
    /// Les adresses vers lesquelles il résout.
    pub adresses: Vec<IpAddr>,
}

/// Ce que TLS a négocié.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls {
    /// `TLS1.3`, `TLS1.2`.
    pub version: String,
    /// La suite, sous son nom IANA.
    pub suite: String,
}

/// Comment une session s'est terminée.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IssueSession {
    /// Servie jusqu'à son terme.
    #[default]
    Servie,
    /// Le débit dépassait le seuil.
    Ralentie,
    /// Le pair a parlé derrière son `STARTTLS`.
    Injection,
    /// Coupée : délai, erreur d'entrée-sortie, faute de protocole.
    Interrompue,
}

/// Une connexion SMTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// L'identifiant de session.
    pub id: [u8; 16],
    /// L'ouverture, en millisecondes.
    pub ouverte: u64,
    /// La fermeture, en millisecondes.
    pub fermee: u64,
    /// L'écoute, `adresse:port`.
    pub ecoute: String,
    /// L'adresse du pair.
    pub pair: IpAddr,
    /// Son port.
    pub port: u16,
    /// La résolution inverse.
    pub inverse: Inverse,
    /// Le HELO ou l'EHLO.
    pub salut: Salut,
    /// TLS, si la connexion s'est chiffrée.
    pub tls: Option<Tls>,
    /// Les commandes traitées.
    pub commandes: u64,
    /// Les messages acceptés.
    pub messages: u64,
    /// Le pair s'est-il authentifié ?
    pub authentifiee: bool,
    /// Le mécanisme SASL, ou vide.
    pub mecanisme: String,
    /// Comment elle s'est terminée.
    pub issue: IssueSession,
    /// Ce qui l'a interrompue, ou vide.
    pub erreur: String,
    /// La version du serveur.
    pub version: String,
    /// Ce que le pair a dit de lui par `XABOUT`, ou vide.
    pub presentation: String,
}

/// Un résultat d'authentification, dans les mots de RFC 8601.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Resultat {
    /// Rien d'évalué, ou rien de publié.
    #[default]
    None,
    /// Réussi.
    Pass,
    /// Échoué.
    Fail,
    /// Échec doux (SPF `~all`).
    SoftFail,
    /// Neutre.
    Neutral,
    /// Erreur temporaire.
    TempError,
    /// Erreur permanente.
    PermError,
    /// La signature tient, mais une politique la récuse.
    Policy,
}

impl Resultat {
    /// Le mot de RFC 8601.
    #[must_use]
    pub const fn mot(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::SoftFail => "softfail",
            Self::Neutral => "neutral",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
            Self::Policy => "policy",
        }
    }
}

/// Le verdict SPF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spf {
    /// Le résultat.
    pub resultat: Resultat,
    /// L'identité vérifiée est le HELO, et non le MAIL FROM.
    pub helo: bool,
    /// Le domaine vérifié.
    pub domaine: String,
}

/// Une signature DKIM et son verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim {
    /// Le résultat.
    pub resultat: Resultat,
    /// `d=`.
    pub domaine: String,
    /// `s=`.
    pub selecteur: String,
}

/// Le verdict DMARC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dmarc {
    /// Le résultat.
    pub resultat: Resultat,
    /// Le domaine du `From:`.
    pub domaine: String,
    /// La politique publiée.
    pub politique: String,
    /// Appliquée, et non seulement publiée.
    pub appliquee: bool,
    /// Mise en quarantaine.
    pub ecartee: bool,
}

/// Un destinataire, et où le message est allé.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Destinataire {
    /// L'adresse.
    pub adresse: String,
    /// Le compte local, vide pour un relais.
    pub compte: String,
    /// La partie unique du nom Maildir.
    pub unique: String,
    /// Mis en quarantaine.
    pub ecarte: bool,
    /// Relayé vers l'extérieur.
    pub relaye: bool,
}

/// Les en-têtes utiles d'un message — des indices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnTetes {
    /// `Message-ID`.
    pub message_id: String,
    /// `Date`.
    pub date: String,
    /// `From`.
    pub from: String,
    /// `Sender`.
    pub sender: String,
    /// `Reply-To`.
    pub reply_to: String,
    /// `List-Id`.
    pub list_id: String,
    /// `List-Unsubscribe` est-il présent ?
    pub list_unsubscribe: bool,
    /// Des en-têtes ARC sont-ils présents ?
    pub arc: bool,
    /// Le SHA-256 de l'objet, s'il y en a un.
    pub objet: Option<[u8; 32]>,
    /// Les adresses de `To` et `Cc`.
    pub destinataires_visibles: u32,
    /// Les `Received:` à l'arrivée.
    pub sauts: u32,
    /// Une valeur a été tronquée.
    pub tronque: bool,
}

/// Comment une transaction s'est conclue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IssueTransaction {
    /// Acceptée.
    #[default]
    Acceptee,
    /// Refusée par une politique DMARC.
    RefuseePolitique,
    /// Refusée définitivement.
    RefuseeDefinitive,
    /// Refusée temporairement.
    RefuseeTemporaire,
}

/// Un message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// La session.
    pub session: [u8; 16],
    /// Son rang dans la session, à partir de un.
    pub numero: u32,
    /// La réception, en millisecondes.
    pub recue: u64,
    /// Une soumission authentifiée.
    pub soumission: bool,
    /// Le MAIL FROM, vide pour un chemin nul.
    pub mail_from: String,
    /// Les destinataires.
    pub destinataires: Vec<Destinataire>,
    /// Les octets reçus.
    pub octets: u64,
    /// Les en-têtes utiles.
    pub entetes: EnTetes,
    /// SPF, s'il a été évalué.
    pub spf: Option<Spf>,
    /// Les signatures DKIM.
    pub dkim: Vec<Dkim>,
    /// DMARC, s'il a été évalué.
    pub dmarc: Option<Dmarc>,
    /// L'en-tête `Authentication-Results` écrit.
    pub authentification: String,
    /// Comment elle s'est conclue.
    pub issue: IssueTransaction,
    /// La résolution inverse, attendue avant d'écrire.
    pub inverse: Inverse,
    /// Le HELO ou l'EHLO.
    pub salut: Salut,
    /// L'adresse du pair.
    pub pair: IpAddr,
    /// TLS, si la connexion s'est chiffrée.
    pub tls: Option<Tls>,
    /// Ce que le pair a dit de lui par `XABOUT`, ou vide.
    pub presentation: String,
}

/// Une transaction écrite acceptée, que la remise n'a pas pu conclure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abandon {
    /// La session.
    pub session: [u8; 16],
    /// Le rang de la transaction.
    pub numero: u32,
    /// Quand, en millisecondes.
    pub quand: u64,
    /// Pourquoi.
    pub raison: String,
}

/// Ce qui ne va pas dans un fichier du registre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// Une trame coupée : le fichier s'arrête au milieu, à cet octet.
    Coupee(usize),
    /// Une trame qui ne se lit pas, à cet octet.
    Illisible(usize),
    /// Le fichier ne commence pas par un entête.
    SansEntete,
    /// Un second entête, à cet octet.
    EnteteEnTrop(usize),
    /// Le sceau ne correspond pas à ce qui le précède.
    SceauFaux,
    /// Des octets après le sceau.
    ApresLeSceau,
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Coupee(a) => write!(f, "trame coupée à l'octet {a}"),
            Self::Illisible(a) => write!(f, "trame illisible à l'octet {a}"),
            Self::SansEntete => f.write_str("le fichier ne commence pas par un entête"),
            Self::EnteteEnTrop(a) => write!(f, "un second entête à l'octet {a}"),
            Self::SceauFaux => f.write_str("le sceau ne correspond pas au contenu"),
            Self::ApresLeSceau => f.write_str("des octets suivent le sceau"),
        }
    }
}

/// Borne un texte venu de l'extérieur à [`TEXTE_MAX`] octets, sur une
/// frontière de caractère. Rend le texte, et s'il a été tronqué.
#[must_use]
pub fn borne(texte: &str) -> (String, bool) {
    if texte.len() <= TEXTE_MAX {
        return (String::from(texte), false);
    }
    let mut fin = TEXTE_MAX;
    while !texte.is_char_boundary(fin) {
        fin = fin.saturating_sub(1);
    }
    (String::from(texte.get(..fin).unwrap_or_default()), true)
}

/// Des octets venus de l'extérieur, en texte borné : ce qui n'est pas UTF-8 se
/// remplace, comme partout où l'on consigne ce qu'un pair a écrit.
#[must_use]
pub fn borne_octets(octets: &[u8]) -> (String, bool) {
    borne(&String::from_utf8_lossy(octets))
}

/// Le jour UTC d'un instant en millisecondes, `AAAA-MM-JJ` — le nom du
/// fichier qui le reçoit.
///
/// Le calcul civil est celui d'`ams-mime` (Howard Hinnant), en arithmétique
/// saturante : aucune branche de plus à couvrir.
#[must_use]
pub fn jour_utc(ms: u64) -> String {
    let jours = ms / 86_400_000;
    let z = jours.saturating_add(719_468);
    let ere = z / 146_097;
    let jour_de_l_ere = z % 146_097;
    let an_de_l_ere = jour_de_l_ere
        .saturating_sub(jour_de_l_ere / 1_460)
        .saturating_add(jour_de_l_ere / 36_524)
        .saturating_sub(jour_de_l_ere / 146_096)
        / 365;
    let annee = an_de_l_ere.saturating_add(ere.saturating_mul(400));
    let jour_de_l_an = jour_de_l_ere.saturating_sub(
        an_de_l_ere
            .saturating_mul(365)
            .saturating_add(an_de_l_ere / 4)
            .saturating_sub(an_de_l_ere / 100),
    );
    let mois_decale = jour_de_l_an.saturating_mul(5).saturating_add(2) / 153;
    let jour = jour_de_l_an
        .saturating_sub(mois_decale.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let (mois, annee) = if mois_decale < 10 {
        (mois_decale.saturating_add(3), annee)
    } else {
        (mois_decale.saturating_sub(9), annee.saturating_add(1))
    };
    alloc::format!("{annee:04}-{mois:02}-{jour:02}")
}

// ── LE CODAGE ───────────────────────────────────────────────────────────────

fn nombre(n: usize) -> u32 {
    u32::try_from(n.min(LISTE_MAX)).unwrap_or(0)
}

fn octets_d_adresse(adresse: IpAddr) -> Vec<u8> {
    match adresse {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn adresse_d_octets(octets: &[u8]) -> Option<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(octets) {
        return Some(IpAddr::from(v4));
    }
    <[u8; 16]>::try_from(octets).ok().map(IpAddr::from)
}

const fn statut_dns_c(statut: StatutDns) -> StatutDnsC {
    match statut {
        StatutDns::NonCherche => StatutDnsC::NonCherche,
        StatutDns::Trouve => StatutDnsC::Trouve,
        StatutDns::Absent => StatutDnsC::Absent,
        StatutDns::Panne => StatutDnsC::Panne,
    }
}

const fn statut_salut_c(statut: StatutSalut) -> StatutSalutC {
    match statut {
        StatutSalut::NonVerifie => StatutSalutC::NonVerifie,
        StatutSalut::Litteral => StatutSalutC::Litteral,
        StatutSalut::PointeLePair => StatutSalutC::PointeLePair,
        StatutSalut::PointeAilleurs => StatutSalutC::PointeAilleurs,
        StatutSalut::NeResoutPas => StatutSalutC::NeResoutPas,
        StatutSalut::Panne => StatutSalutC::Panne,
    }
}

const fn resultat_c(resultat: Resultat) -> ResultatC {
    match resultat {
        Resultat::None => ResultatC::None,
        Resultat::Pass => ResultatC::Pass,
        Resultat::Fail => ResultatC::Fail,
        Resultat::SoftFail => ResultatC::SoftFail,
        Resultat::Neutral => ResultatC::Neutral,
        Resultat::TempError => ResultatC::TempError,
        Resultat::PermError => ResultatC::PermError,
        Resultat::Policy => ResultatC::Policy,
    }
}

fn ecrire_inverse(mut ecrit: inverse::Builder<'_>, lu: &Inverse) {
    ecrit.set_statut(statut_dns_c(lu.statut));
    ecrit.set_ttl(lu.ttl);
    ecrit.set_authentifiee(lu.authentifiee);
    ecrit.set_confirmee(lu.confirmee);
    let mut noms = ecrit.init_noms(nombre(lu.noms.len()));
    for (rang, nom) in (0_u32..).zip(lu.noms.iter().take(LISTE_MAX)) {
        noms.set(rang, nom.as_str());
    }
}

fn ecrire_salut(mut ecrit: salut::Builder<'_>, lu: &Salut) {
    ecrit.set_nom(lu.nom.as_str());
    ecrit.set_statut(statut_salut_c(lu.statut));
    let mut adresses = ecrit.init_adresses(nombre(lu.adresses.len()));
    for (rang, adresse) in (0_u32..).zip(lu.adresses.iter().take(LISTE_MAX)) {
        adresses.set(rang, &octets_d_adresse(*adresse));
    }
}

fn ecrire_session(mut ecrit: session::Builder<'_>, lu: &Session) {
    ecrit.set_id(&lu.id);
    ecrit.set_ouverte(lu.ouverte);
    ecrit.set_fermee(lu.fermee);
    ecrit.set_ecoute(lu.ecoute.as_str());
    ecrit.set_pair(&octets_d_adresse(lu.pair));
    ecrit.set_port(lu.port);
    ecrire_inverse(ecrit.reborrow().init_inverse(), &lu.inverse);
    ecrire_salut(ecrit.reborrow().init_salut(), &lu.salut);
    if let Some(tls) = &lu.tls {
        let mut chiffre = ecrit.reborrow().init_tls();
        chiffre.set_version(tls.version.as_str());
        chiffre.set_suite(tls.suite.as_str());
    }
    ecrit.set_commandes(lu.commandes);
    ecrit.set_messages(lu.messages);
    ecrit.set_authentifiee(lu.authentifiee);
    ecrit.set_mecanisme(lu.mecanisme.as_str());
    ecrit.set_issue(match lu.issue {
        IssueSession::Servie => IssueS::Servie,
        IssueSession::Ralentie => IssueS::Ralentie,
        IssueSession::Injection => IssueS::Injection,
        IssueSession::Interrompue => IssueS::Interrompue,
    });
    ecrit.set_erreur(lu.erreur.as_str());
    ecrit.set_version(lu.version.as_str());
    ecrit.set_presentation(lu.presentation.as_str());
}

fn ecrire_transaction(mut ecrit: transaction::Builder<'_>, lu: &Transaction) {
    ecrit.set_session(&lu.session);
    ecrit.set_numero(lu.numero);
    ecrit.set_recue(lu.recue);
    ecrit.set_soumission(lu.soumission);
    ecrit.set_mail_from(lu.mail_from.as_str());
    {
        let mut liste = ecrit
            .reborrow()
            .init_destinataires(nombre(lu.destinataires.len()));
        for (rang, destinataire) in (0_u32..).zip(lu.destinataires.iter().take(LISTE_MAX)) {
            let mut case = liste.reborrow().get(rang);
            case.set_adresse(destinataire.adresse.as_str());
            case.set_compte(destinataire.compte.as_str());
            case.set_unique(destinataire.unique.as_str());
            case.set_ecarte(destinataire.ecarte);
            case.set_relaye(destinataire.relaye);
        }
    }
    ecrit.set_octets(lu.octets);
    {
        let tetes = &lu.entetes;
        let mut case = ecrit.reborrow().init_entetes();
        case.set_message_id(tetes.message_id.as_str());
        case.set_date(tetes.date.as_str());
        case.set_from(tetes.from.as_str());
        case.set_sender(tetes.sender.as_str());
        case.set_reply_to(tetes.reply_to.as_str());
        case.set_list_id(tetes.list_id.as_str());
        case.set_list_unsubscribe(tetes.list_unsubscribe);
        case.set_arc(tetes.arc);
        if let Some(objet) = &tetes.objet {
            case.set_objet(objet);
        }
        case.set_destinataires_visibles(tetes.destinataires_visibles);
        case.set_sauts(tetes.sauts);
        case.set_tronque(tetes.tronque);
    }
    if let Some(spf) = &lu.spf {
        let mut case = ecrit.reborrow().init_spf();
        case.set_resultat(resultat_c(spf.resultat));
        case.set_helo(spf.helo);
        case.set_domaine(spf.domaine.as_str());
    }
    {
        let mut liste = ecrit.reborrow().init_dkim(nombre(lu.dkim.len()));
        for (rang, signature) in (0_u32..).zip(lu.dkim.iter().take(LISTE_MAX)) {
            let mut case: dkim::Builder<'_> = liste.reborrow().get(rang);
            case.set_resultat(resultat_c(signature.resultat));
            case.set_domaine(signature.domaine.as_str());
            case.set_selecteur(signature.selecteur.as_str());
        }
    }
    if let Some(dmarc) = &lu.dmarc {
        let mut case = ecrit.reborrow().init_dmarc();
        case.set_resultat(resultat_c(dmarc.resultat));
        case.set_domaine(dmarc.domaine.as_str());
        case.set_politique(dmarc.politique.as_str());
        case.set_appliquee(dmarc.appliquee);
        case.set_ecartee(dmarc.ecartee);
    }
    ecrit.set_authentification(lu.authentification.as_str());
    ecrit.set_issue(match lu.issue {
        IssueTransaction::Acceptee => IssueT::Acceptee,
        IssueTransaction::RefuseePolitique => IssueT::RefuseePolitique,
        IssueTransaction::RefuseeDefinitive => IssueT::RefuseeDefinitive,
        IssueTransaction::RefuseeTemporaire => IssueT::RefuseeTemporaire,
    });
    ecrire_inverse(ecrit.reborrow().init_inverse(), &lu.inverse);
    ecrire_salut(ecrit.reborrow().init_salut(), &lu.salut);
    ecrit.set_pair(&octets_d_adresse(lu.pair));
    if let Some(tls) = &lu.tls {
        let mut chiffre = ecrit.reborrow().init_tls();
        chiffre.set_version(tls.version.as_str());
        chiffre.set_suite(tls.suite.as_str());
    }
    ecrit.set_presentation(lu.presentation.as_str());
}

/// Une trame : la longueur, puis l'enregistrement.
///
/// # Errors
///
/// Un enregistrement qui dépasserait [`TRAME_MAX`] — ce que les bornes de
/// texte et de liste rendent impossible, et qu'on refuse quand même plutôt que
/// d'écrire ce qu'aucun lecteur ne relirait.
pub fn trame(quoi: &Enregistrement) -> Result<Vec<u8>, Faute> {
    let mut message = capnp::message::Builder::new_default();
    {
        let racine = message.init_root::<enregistrement::Builder<'_>>();
        match quoi {
            Enregistrement::Entete(lu) => {
                let mut ecrit: entete::Builder<'_> = racine.init_entete();
                ecrit.set_format(lu.format);
                ecrit.set_jour(lu.jour.as_str());
                if let Some(precedent) = &lu.precedent {
                    ecrit.set_precedent(precedent);
                }
                ecrit.set_version(lu.version.as_str());
                ecrit.set_ouvert(lu.ouvert);
            }
            Enregistrement::Session(lu) => ecrire_session(racine.init_session(), lu),
            Enregistrement::Transaction(lu) => ecrire_transaction(racine.init_transaction(), lu),
            Enregistrement::Abandon(lu) => {
                let mut ecrit: abandon::Builder<'_> = racine.init_abandon();
                ecrit.set_session(&lu.session);
                ecrit.set_numero(lu.numero);
                ecrit.set_quand(lu.quand);
                ecrit.set_raison(lu.raison.as_str());
            }
            Enregistrement::Sceau(lu) => {
                let mut ecrit: sceau::Builder<'_> = racine.init_sceau();
                ecrit.set_enregistrements(lu.enregistrements);
                ecrit.set_condensat(&lu.condensat);
                ecrit.set_scelle(lu.scelle);
                ecrit.set_tronques(lu.tronques);
            }
        }
    }
    let corps = serialize::write_message_to_words(&message);
    let longueur = u32::try_from(corps.len())
        .ok()
        .filter(|_| corps.len() <= TRAME_MAX)
        .ok_or(Faute::Illisible(0))?;
    let mut sortie = Vec::with_capacity(corps.len().saturating_add(4));
    sortie.extend_from_slice(&longueur.to_le_bytes());
    sortie.extend_from_slice(&corps);
    Ok(sortie)
}

// ── LA LECTURE ──────────────────────────────────────────────────────────────

fn texte(lu: capnp::Result<capnp::text::Reader<'_>>) -> String {
    lu.ok()
        .and_then(|brut| brut.to_str().ok())
        .map(String::from)
        .unwrap_or_default()
}

fn donnees(lu: capnp::Result<capnp::data::Reader<'_>>) -> Vec<u8> {
    lu.map(<[u8]>::to_vec).unwrap_or_default()
}

fn condensat(lu: capnp::Result<capnp::data::Reader<'_>>) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(donnees(lu).as_slice()).ok()
}

fn identifiant(lu: capnp::Result<capnp::data::Reader<'_>>) -> [u8; 16] {
    <[u8; 16]>::try_from(donnees(lu).as_slice()).unwrap_or([0; 16])
}

fn adresse(lu: capnp::Result<capnp::data::Reader<'_>>) -> IpAddr {
    adresse_d_octets(&donnees(lu)).unwrap_or(IpAddr::from([0_u8; 4]))
}

fn resultat(lu: Result<ResultatC, capnp::NotInSchema>) -> Resultat {
    match lu {
        Ok(ResultatC::Pass) => Resultat::Pass,
        Ok(ResultatC::Fail) => Resultat::Fail,
        Ok(ResultatC::SoftFail) => Resultat::SoftFail,
        Ok(ResultatC::Neutral) => Resultat::Neutral,
        Ok(ResultatC::TempError) => Resultat::TempError,
        Ok(ResultatC::PermError) => Resultat::PermError,
        Ok(ResultatC::Policy) => Resultat::Policy,
        Ok(ResultatC::None) | Err(_) => Resultat::None,
    }
}

fn lire_inverse(lu: capnp::Result<inverse::Reader<'_>>) -> Inverse {
    lu.map(|lu| Inverse {
        statut: match lu.get_statut() {
            Ok(StatutDnsC::Trouve) => StatutDns::Trouve,
            Ok(StatutDnsC::Absent) => StatutDns::Absent,
            Ok(StatutDnsC::Panne) => StatutDns::Panne,
            Ok(StatutDnsC::NonCherche) | Err(_) => StatutDns::NonCherche,
        },
        noms: lu
            .get_noms()
            .map(|noms| noms.iter().take(LISTE_MAX).map(texte).collect())
            .unwrap_or_default(),
        ttl: lu.get_ttl(),
        authentifiee: lu.get_authentifiee(),
        confirmee: lu.get_confirmee(),
    })
    .unwrap_or_default()
}

fn lire_salut(lu: capnp::Result<salut::Reader<'_>>) -> Salut {
    lu.map(|lu| Salut {
        nom: texte(lu.get_nom()),
        statut: match lu.get_statut() {
            Ok(StatutSalutC::Litteral) => StatutSalut::Litteral,
            Ok(StatutSalutC::PointeLePair) => StatutSalut::PointeLePair,
            Ok(StatutSalutC::PointeAilleurs) => StatutSalut::PointeAilleurs,
            Ok(StatutSalutC::NeResoutPas) => StatutSalut::NeResoutPas,
            Ok(StatutSalutC::Panne) => StatutSalut::Panne,
            Ok(StatutSalutC::NonVerifie) | Err(_) => StatutSalut::NonVerifie,
        },
        adresses: lu
            .get_adresses()
            .map(|liste| {
                liste
                    .iter()
                    .take(LISTE_MAX)
                    .filter_map(|octets| adresse_d_octets(&donnees(octets)))
                    .collect()
            })
            .unwrap_or_default(),
    })
    .unwrap_or_default()
}

fn lire_tls(
    present: bool,
    lu: capnp::Result<crate::ams_registre_capnp::tls::Reader<'_>>,
) -> Option<Tls> {
    let lu = lu.ok().filter(|_| present)?;
    Some(Tls {
        version: texte(lu.get_version()),
        suite: texte(lu.get_suite()),
    })
}

fn lire_session(lu: session::Reader<'_>) -> Session {
    Session {
        id: identifiant(lu.get_id()),
        ouverte: lu.get_ouverte(),
        fermee: lu.get_fermee(),
        ecoute: texte(lu.get_ecoute()),
        pair: adresse(lu.get_pair()),
        port: lu.get_port(),
        inverse: lire_inverse(lu.get_inverse()),
        salut: lire_salut(lu.get_salut()),
        tls: lire_tls(lu.has_tls(), lu.get_tls()),
        commandes: lu.get_commandes(),
        messages: lu.get_messages(),
        authentifiee: lu.get_authentifiee(),
        mecanisme: texte(lu.get_mecanisme()),
        issue: match lu.get_issue() {
            Ok(IssueS::Ralentie) => IssueSession::Ralentie,
            Ok(IssueS::Injection) => IssueSession::Injection,
            Ok(IssueS::Interrompue) => IssueSession::Interrompue,
            Ok(IssueS::Servie) | Err(_) => IssueSession::Servie,
        },
        erreur: texte(lu.get_erreur()),
        version: texte(lu.get_version()),
        presentation: texte(lu.get_presentation()),
    }
}

fn lire_entetes(lu: capnp::Result<crate::ams_registre_capnp::en_tetes::Reader<'_>>) -> EnTetes {
    lu.map(|lu| EnTetes {
        message_id: texte(lu.get_message_id()),
        date: texte(lu.get_date()),
        from: texte(lu.get_from()),
        sender: texte(lu.get_sender()),
        reply_to: texte(lu.get_reply_to()),
        list_id: texte(lu.get_list_id()),
        list_unsubscribe: lu.get_list_unsubscribe(),
        arc: lu.get_arc(),
        objet: lu.has_objet().then(|| condensat(lu.get_objet())).flatten(),
        destinataires_visibles: lu.get_destinataires_visibles(),
        sauts: lu.get_sauts(),
        tronque: lu.get_tronque(),
    })
    .unwrap_or_default()
}

fn lire_transaction(lu: transaction::Reader<'_>) -> Transaction {
    Transaction {
        session: identifiant(lu.get_session()),
        numero: lu.get_numero(),
        recue: lu.get_recue(),
        soumission: lu.get_soumission(),
        mail_from: texte(lu.get_mail_from()),
        destinataires: lu
            .get_destinataires()
            .map(|liste| {
                liste
                    .iter()
                    .take(LISTE_MAX)
                    .map(|case| Destinataire {
                        adresse: texte(case.get_adresse()),
                        compte: texte(case.get_compte()),
                        unique: texte(case.get_unique()),
                        ecarte: case.get_ecarte(),
                        relaye: case.get_relaye(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        octets: lu.get_octets(),
        entetes: lire_entetes(lu.get_entetes()),
        spf: lu.get_spf().ok().filter(|_| lu.has_spf()).map(|case| Spf {
            resultat: resultat(case.get_resultat()),
            helo: case.get_helo(),
            domaine: texte(case.get_domaine()),
        }),
        dkim: lu
            .get_dkim()
            .map(|liste| {
                liste
                    .iter()
                    .take(LISTE_MAX)
                    .map(|case| Dkim {
                        resultat: resultat(case.get_resultat()),
                        domaine: texte(case.get_domaine()),
                        selecteur: texte(case.get_selecteur()),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        dmarc: lu
            .get_dmarc()
            .ok()
            .filter(|_| lu.has_dmarc())
            .map(|case| Dmarc {
                resultat: resultat(case.get_resultat()),
                domaine: texte(case.get_domaine()),
                politique: texte(case.get_politique()),
                appliquee: case.get_appliquee(),
                ecartee: case.get_ecartee(),
            }),
        authentification: texte(lu.get_authentification()),
        issue: match lu.get_issue() {
            Ok(IssueT::RefuseePolitique) => IssueTransaction::RefuseePolitique,
            Ok(IssueT::RefuseeDefinitive) => IssueTransaction::RefuseeDefinitive,
            Ok(IssueT::RefuseeTemporaire) => IssueTransaction::RefuseeTemporaire,
            Ok(IssueT::Acceptee) | Err(_) => IssueTransaction::Acceptee,
        },
        inverse: lire_inverse(lu.get_inverse()),
        salut: lire_salut(lu.get_salut()),
        pair: adresse(lu.get_pair()),
        tls: lire_tls(lu.has_tls(), lu.get_tls()),
        presentation: texte(lu.get_presentation()),
    }
}

/// Décode le corps d'une trame — sans ses quatre octets de longueur.
fn decoder(corps: &[u8]) -> Option<Enregistrement> {
    // **UN TAMPON ALIGNÉ** : Cap'n Proto lit des mots de huit octets, et la
    // longueur de quatre octets qui précède chaque trame décale le reste. On
    // recopie donc le corps — un message écrit fait toujours un nombre entier
    // de mots.
    if !corps.len().is_multiple_of(8) {
        return None;
    }
    let mut mots = capnp::Word::allocate_zeroed_vec(corps.len() / 8);
    capnp::Word::words_to_bytes_mut(&mut mots).copy_from_slice(corps);
    let aligne = capnp::Word::words_to_bytes(&mots);
    let mut reste = aligne;
    let message = serialize::read_message_from_flat_slice(
        &mut reste,
        ReaderOptions {
            traversal_limit_in_words: Some(corps.len().saturating_div(8).saturating_add(64)),
            nesting_limit: 8,
        },
    )
    .ok()?;
    if !reste.is_empty() {
        return None;
    }
    let racine: enregistrement::Reader<'_> = message.get_root().ok()?;
    Some(match racine.which().ok()? {
        enregistrement::Entete(lu) => {
            let lu = lu.ok()?;
            Enregistrement::Entete(Entete {
                format: lu.get_format(),
                jour: texte(lu.get_jour()),
                precedent: condensat(lu.get_precedent()),
                version: texte(lu.get_version()),
                ouvert: lu.get_ouvert(),
            })
        }
        enregistrement::Session(lu) => Enregistrement::Session(Box::new(lire_session(lu.ok()?))),
        enregistrement::Transaction(lu) => {
            Enregistrement::Transaction(Box::new(lire_transaction(lu.ok()?)))
        }
        enregistrement::Abandon(lu) => {
            let lu = lu.ok()?;
            Enregistrement::Abandon(Abandon {
                session: identifiant(lu.get_session()),
                numero: lu.get_numero(),
                quand: lu.get_quand(),
                raison: texte(lu.get_raison()),
            })
        }
        enregistrement::Sceau(lu) => {
            let lu = lu.ok()?;
            Enregistrement::Sceau(Sceau {
                enregistrements: lu.get_enregistrements(),
                condensat: condensat(lu.get_condensat()).unwrap_or([0; 32]),
                scelle: lu.get_scelle(),
                tronques: lu.get_tronques(),
            })
        }
    })
}

/// Lit la trame qui commence à `debut`. Rend l'enregistrement et l'octet où
/// commence la suivante.
///
/// # Errors
///
/// [`Faute::Coupee`] si le fichier s'arrête avant la fin de la trame,
/// [`Faute::Illisible`] si elle ne se décode pas ou annonce plus que
/// [`TRAME_MAX`].
pub fn lire_trame(octets: &[u8], debut: usize) -> Result<(Enregistrement, usize), Faute> {
    let reste = octets.get(debut..).unwrap_or_default();
    let Some(longueur) = reste.get(..4) else {
        return Err(Faute::Coupee(debut));
    };
    let longueur = usize::try_from(u32::from_le_bytes([
        longueur.first().copied().unwrap_or(0),
        longueur.get(1).copied().unwrap_or(0),
        longueur.get(2).copied().unwrap_or(0),
        longueur.get(3).copied().unwrap_or(0),
    ]))
    .unwrap_or(usize::MAX);
    if longueur > TRAME_MAX {
        return Err(Faute::Illisible(debut));
    }
    let fin = longueur.saturating_add(4);
    let corps = reste.get(4..fin).ok_or(Faute::Coupee(debut))?;
    let lu = decoder(corps).ok_or(Faute::Illisible(debut))?;
    Ok((lu, debut.saturating_add(fin)))
}

/// Ce qu'un fichier vérifié contient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bilan {
    /// Son entête.
    pub entete: Entete,
    /// Combien d'enregistrements, sceau non compris.
    pub enregistrements: u64,
    /// Son sceau, s'il est scellé.
    pub sceau: Option<Sceau>,
    /// Le SHA-256 du fichier entier : ce que le suivant doit citer.
    pub condensat: [u8; 32],
}

/// Vérifie un fichier du registre : trames entières, entête d'abord, sceau
/// juste — et rien après lui.
///
/// # Errors
///
/// La première [`Faute`].
pub fn verifier(octets: &[u8]) -> Result<Bilan, Faute> {
    let (premier, mut suite) = lire_trame(octets, 0)?;
    let Enregistrement::Entete(entete) = premier else {
        return Err(Faute::SansEntete);
    };
    let mut enregistrements: u64 = 1;
    let mut sceau = None;
    while suite < octets.len() {
        if sceau.is_some() {
            return Err(Faute::ApresLeSceau);
        }
        let debut = suite;
        let (lu, apres) = lire_trame(octets, debut)?;
        match lu {
            Enregistrement::Entete(_) => return Err(Faute::EnteteEnTrop(debut)),
            Enregistrement::Sceau(pose) => {
                let precede: [u8; 32] =
                    sha2::Sha256::digest(octets.get(..debut).unwrap_or_default()).into();
                if pose.condensat != precede || pose.enregistrements != enregistrements {
                    return Err(Faute::SceauFaux);
                }
                sceau = Some(pose);
            }
            _ => enregistrements = enregistrements.saturating_add(1),
        }
        suite = apres;
    }
    Ok(Bilan {
        entete,
        enregistrements,
        sceau,
        condensat: sha2::Sha256::digest(octets).into(),
    })
}

/// La longueur des trames entières au début de ces octets : ce qu'on garde
/// d'un fichier retrouvé coupé, et combien d'enregistrements elles portent.
#[must_use]
pub fn trames_entieres(octets: &[u8]) -> (usize, u64) {
    let mut fin = 0;
    let mut combien: u64 = 0;
    while let Ok((_, apres)) = lire_trame(octets, fin) {
        fin = apres;
        combien = combien.saturating_add(1);
    }
    (fin, combien)
}

// ── LE JSON ─────────────────────────────────────────────────────────────────

fn chaine(sortie: &mut String, valeur: &str) {
    sortie.push('"');
    for c in valeur.chars() {
        match c {
            '"' => sortie.push_str("\\\""),
            '\\' => sortie.push_str("\\\\"),
            '\n' => sortie.push_str("\\n"),
            '\r' => sortie.push_str("\\r"),
            '\t' => sortie.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(sortie, "\\u{:04x}", u32::from(c));
            }
            c => sortie.push(c),
        }
    }
    sortie.push('"');
}

fn hex(octets: &[u8]) -> String {
    let mut sortie = String::with_capacity(octets.len().saturating_mul(2));
    for octet in octets {
        let _ = write!(sortie, "{octet:02x}");
    }
    sortie
}

/// Un objet JSON, champ par champ.
struct Objet(String);

impl Objet {
    fn new() -> Self {
        Self(String::from("{"))
    }
    fn cle(&mut self, nom: &str) {
        if self.0.len() > 1 {
            self.0.push(',');
        }
        chaine(&mut self.0, nom);
        self.0.push(':');
    }
    fn texte(&mut self, nom: &str, valeur: &str) {
        self.cle(nom);
        chaine(&mut self.0, valeur);
    }
    fn brut(&mut self, nom: &str, valeur: &str) {
        self.cle(nom);
        self.0.push_str(valeur);
    }
    fn nombre(&mut self, nom: &str, valeur: u64) {
        self.cle(nom);
        let _ = write!(self.0, "{valeur}");
    }
    fn booleen(&mut self, nom: &str, valeur: bool) {
        self.brut(nom, if valeur { "true" } else { "false" });
    }
    fn fin(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

fn tableau<T>(elements: &[T], un: impl Fn(&T) -> String) -> String {
    let mut sortie = String::from("[");
    for (rang, element) in elements.iter().enumerate() {
        if rang > 0 {
            sortie.push(',');
        }
        sortie.push_str(&un(element));
    }
    sortie.push(']');
    sortie
}

fn json_texte(valeur: &str) -> String {
    let mut sortie = String::new();
    chaine(&mut sortie, valeur);
    sortie
}

const fn mot_dns(statut: StatutDns) -> &'static str {
    match statut {
        StatutDns::NonCherche => "non-cherche",
        StatutDns::Trouve => "trouve",
        StatutDns::Absent => "absent",
        StatutDns::Panne => "panne",
    }
}

const fn mot_salut(statut: StatutSalut) -> &'static str {
    match statut {
        StatutSalut::NonVerifie => "non-verifie",
        StatutSalut::Litteral => "litteral",
        StatutSalut::PointeLePair => "pointe-le-pair",
        StatutSalut::PointeAilleurs => "pointe-ailleurs",
        StatutSalut::NeResoutPas => "ne-resout-pas",
        StatutSalut::Panne => "panne",
    }
}

fn json_inverse(lu: &Inverse) -> String {
    let mut objet = Objet::new();
    objet.texte("statut", mot_dns(lu.statut));
    objet.brut("noms", &tableau(&lu.noms, |nom| json_texte(nom)));
    objet.nombre("ttl", u64::from(lu.ttl));
    objet.booleen("authentifiee", lu.authentifiee);
    objet.booleen("confirmee", lu.confirmee);
    objet.fin()
}

fn json_salut(lu: &Salut) -> String {
    let mut objet = Objet::new();
    objet.texte("nom", &lu.nom);
    objet.texte("statut", mot_salut(lu.statut));
    objet.brut(
        "adresses",
        &tableau(&lu.adresses, |adresse| {
            json_texte(&alloc::format!("{adresse}"))
        }),
    );
    objet.fin()
}

fn json_tls(lu: Option<&Tls>) -> String {
    lu.map_or_else(
        || String::from("null"),
        |tls| {
            let mut objet = Objet::new();
            objet.texte("version", &tls.version);
            objet.texte("suite", &tls.suite);
            objet.fin()
        },
    )
}

/// L'enregistrement en une ligne JSON — ce que `air-mail-admin registre`
/// écrit.
#[must_use]
pub fn en_json(quoi: &Enregistrement) -> String {
    let mut objet = Objet::new();
    match quoi {
        Enregistrement::Entete(lu) => {
            objet.texte("type", "entete");
            objet.nombre("format", u64::from(lu.format));
            objet.texte("jour", &lu.jour);
            objet.texte(
                "precedent",
                &lu.precedent.map(|c| hex(&c)).unwrap_or_default(),
            );
            objet.texte("version", &lu.version);
            objet.nombre("ouvert", lu.ouvert);
        }
        Enregistrement::Session(lu) => {
            objet.texte("type", "session");
            objet.texte("id", &hex(&lu.id));
            objet.nombre("ouverte", lu.ouverte);
            objet.nombre("fermee", lu.fermee);
            objet.texte("ecoute", &lu.ecoute);
            objet.texte("pair", &alloc::format!("{}", lu.pair));
            objet.nombre("port", u64::from(lu.port));
            objet.brut("inverse", &json_inverse(&lu.inverse));
            objet.brut("salut", &json_salut(&lu.salut));
            objet.brut("tls", &json_tls(lu.tls.as_ref()));
            objet.nombre("commandes", lu.commandes);
            objet.nombre("messages", lu.messages);
            objet.booleen("authentifiee", lu.authentifiee);
            objet.texte("mecanisme", &lu.mecanisme);
            objet.texte(
                "issue",
                match lu.issue {
                    IssueSession::Servie => "servie",
                    IssueSession::Ralentie => "ralentie",
                    IssueSession::Injection => "injection",
                    IssueSession::Interrompue => "interrompue",
                },
            );
            objet.texte("erreur", &lu.erreur);
            objet.texte("version", &lu.version);
            objet.texte("presentation", &lu.presentation);
        }
        Enregistrement::Transaction(lu) => {
            objet.texte("type", "transaction");
            objet.texte("session", &hex(&lu.session));
            objet.nombre("numero", u64::from(lu.numero));
            objet.nombre("recue", lu.recue);
            objet.booleen("soumission", lu.soumission);
            objet.texte("mailFrom", &lu.mail_from);
            objet.brut(
                "destinataires",
                &tableau(&lu.destinataires, |d| {
                    let mut case = Objet::new();
                    case.texte("adresse", &d.adresse);
                    case.texte("compte", &d.compte);
                    case.texte("unique", &d.unique);
                    case.booleen("ecarte", d.ecarte);
                    case.booleen("relaye", d.relaye);
                    case.fin()
                }),
            );
            objet.nombre("octets", lu.octets);
            let tetes = &lu.entetes;
            let mut case = Objet::new();
            case.texte("messageId", &tetes.message_id);
            case.texte("date", &tetes.date);
            case.texte("from", &tetes.from);
            case.texte("sender", &tetes.sender);
            case.texte("replyTo", &tetes.reply_to);
            case.texte("listId", &tetes.list_id);
            case.booleen("listUnsubscribe", tetes.list_unsubscribe);
            case.booleen("arc", tetes.arc);
            case.texte("objet", &tetes.objet.map(|c| hex(&c)).unwrap_or_default());
            case.nombre(
                "destinatairesVisibles",
                u64::from(tetes.destinataires_visibles),
            );
            case.nombre("sauts", u64::from(tetes.sauts));
            case.booleen("tronque", tetes.tronque);
            objet.brut("entetes", &case.fin());
            objet.brut(
                "spf",
                &lu.spf.as_ref().map_or_else(
                    || String::from("null"),
                    |spf| {
                        let mut case = Objet::new();
                        case.texte("resultat", spf.resultat.mot());
                        case.booleen("helo", spf.helo);
                        case.texte("domaine", &spf.domaine);
                        case.fin()
                    },
                ),
            );
            objet.brut(
                "dkim",
                &tableau(&lu.dkim, |signature| {
                    let mut case = Objet::new();
                    case.texte("resultat", signature.resultat.mot());
                    case.texte("domaine", &signature.domaine);
                    case.texte("selecteur", &signature.selecteur);
                    case.fin()
                }),
            );
            objet.brut(
                "dmarc",
                &lu.dmarc.as_ref().map_or_else(
                    || String::from("null"),
                    |dmarc| {
                        let mut case = Objet::new();
                        case.texte("resultat", dmarc.resultat.mot());
                        case.texte("domaine", &dmarc.domaine);
                        case.texte("politique", &dmarc.politique);
                        case.booleen("appliquee", dmarc.appliquee);
                        case.booleen("ecartee", dmarc.ecartee);
                        case.fin()
                    },
                ),
            );
            objet.texte("authentification", &lu.authentification);
            objet.texte(
                "issue",
                match lu.issue {
                    IssueTransaction::Acceptee => "acceptee",
                    IssueTransaction::RefuseePolitique => "refusee-politique",
                    IssueTransaction::RefuseeDefinitive => "refusee-definitive",
                    IssueTransaction::RefuseeTemporaire => "refusee-temporaire",
                },
            );
            objet.brut("inverse", &json_inverse(&lu.inverse));
            objet.brut("salut", &json_salut(&lu.salut));
            objet.texte("pair", &alloc::format!("{}", lu.pair));
            objet.brut("tls", &json_tls(lu.tls.as_ref()));
            objet.texte("presentation", &lu.presentation);
        }
        Enregistrement::Abandon(lu) => {
            objet.texte("type", "abandon");
            objet.texte("session", &hex(&lu.session));
            objet.nombre("numero", u64::from(lu.numero));
            objet.nombre("quand", lu.quand);
            objet.texte("raison", &lu.raison);
        }
        Enregistrement::Sceau(lu) => {
            objet.texte("type", "sceau");
            objet.nombre("enregistrements", lu.enregistrements);
            objet.texte("condensat", &hex(&lu.condensat));
            objet.nombre("scelle", lu.scelle);
            objet.nombre("tronques", lu.tronques);
        }
    }
    objet.fin()
}

/// Le SHA-256 en hexadécimal — pour l'outil, qui compare les chaînons.
#[must_use]
pub fn en_hex(octets: &[u8]) -> String {
    hex(octets)
}

// ── LES EN-TÊTES D'UN MESSAGE ───────────────────────────────────────────────

/// Les en-têtes utiles d'un bloc d'en-tête (RFC 5322 §2.2), dépliés.
///
/// **CE SONT DES INDICES** : rien ne les authentifie en soi. Le premier de
/// chaque champ l'emporte ; `Received`, `To` et `Cc` se comptent.
#[must_use]
pub fn en_tetes(bloc: &[u8]) -> EnTetes {
    let mut vus = EnTetes::default();
    let mut objet_vu = false;
    for (nom, valeur) in champs(bloc) {
        let valeur = String::from_utf8_lossy(&valeur);
        let valeur = valeur.trim();
        let mut poser = |case: &mut String| {
            if case.is_empty() {
                let (borne, coupe) = borne(valeur);
                *case = borne;
                vus.tronque |= coupe;
            }
        };
        match nom.to_ascii_lowercase().as_slice() {
            b"message-id" => poser(&mut vus.message_id),
            b"date" => poser(&mut vus.date),
            b"from" => poser(&mut vus.from),
            b"sender" => poser(&mut vus.sender),
            b"reply-to" => poser(&mut vus.reply_to),
            b"list-id" => poser(&mut vus.list_id),
            b"list-unsubscribe" => vus.list_unsubscribe = true,
            b"arc-seal" | b"arc-message-signature" | b"arc-authentication-results" => {
                vus.arc = true;
            }
            b"subject" if !objet_vu => {
                objet_vu = true;
                vus.objet = Some(sha2::Sha256::digest(valeur.as_bytes()).into());
            }
            b"to" | b"cc" => {
                let adresses = valeur.bytes().filter(|octet| *octet == b'@').count();
                vus.destinataires_visibles = vus
                    .destinataires_visibles
                    .saturating_add(u32::try_from(adresses).unwrap_or(u32::MAX));
            }
            b"received" => vus.sauts = vus.sauts.saturating_add(1),
            _ => {}
        }
    }
    vus
}

/// Les champs d'un bloc d'en-tête : nom, et valeur dépliée. S'arrête à la
/// ligne vide ; une ligne sans `:` s'ignore.
fn champs(bloc: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut champs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for ligne in bloc.split(|octet| *octet == b'\n') {
        let ligne = ligne.strip_suffix(b"\r").unwrap_or(ligne);
        if ligne.is_empty() {
            break;
        }
        if ligne
            .first()
            .is_some_and(|octet| *octet == b' ' || *octet == b'\t')
        {
            if let Some((_, valeur)) = champs.last_mut() {
                valeur.push(b' ');
                valeur.extend_from_slice(ligne.trim_ascii());
            }
            continue;
        }
        if let Some(deux_points) = ligne.iter().position(|octet| *octet == b':') {
            let nom = ligne.get(..deux_points).unwrap_or_default().trim_ascii();
            let valeur = ligne
                .get(deux_points.saturating_add(1)..)
                .unwrap_or_default();
            champs.push((nom.to_vec(), valeur.to_vec()));
        }
    }
    champs
}

#[cfg(test)]
mod tests;
