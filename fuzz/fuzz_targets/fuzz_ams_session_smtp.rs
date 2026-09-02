//! Fuzz : la session SMTP — **le vocabulaire de sortie est clos**.
//!
//! Une session serveur est pilotée par un pair hostile : c'est lui qui choisit
//! l'ordre des commandes, leur contenu, et le moment où il s'arrête. Cette cible
//! lui donne cette liberté, plus les événements que la boucle peut intercaler
//! (poignée de main TLS, verdict SASL, verdict de message).
//!
//! # La propriété qui porte les autres
//!
//! **Toute réponse appartient à une liste finie, connue d'avance.** La session
//! ne compose ses réponses qu'avec des textes constants et son propre domaine ;
//! si elle reprenait un seul octet venu du pair, la réponse sortirait de la
//! liste et cette cible le dirait.
//!
//! C'est plus fort que « aucun CR n'a survécu » : cela interdit l'écho *tout
//! court*, donc aussi la fuite d'un nom de boîte dans un message d'erreur — le
//! genre de détail qui transforme un serveur en annuaire.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use std::cell::Cell;

use ams_proto_smtp::{ChunkEvent, Limits, Path};
use ams_session::{Action, Config, DataOutcome, Error, Policy, RecipientVerdict, SmtpSession};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Le domaine du serveur, fixe : le vocabulaire clos en dépend.
const DOMAINE: &[u8] = b"mail.example.com";

/// Une politique qui déroule des verdicts arbitraires, en boucle.
struct Politique {
    verdicts: Vec<u8>,
    curseur: Cell<usize>,
    /// La session a-t-elle JAMAIS annoncé un déposant authentifié ?
    ///
    /// **C'EST LA PROPRIÉTÉ QUI GARDE LE RELAIS FERMÉ.** Cette politique
    /// n'authentifie personne ; si un `true` arrivait ici, une politique réelle
    /// accepterait un destinataire qui n'est pas d'ici — c'est-à-dire relaierait
    /// pour un pair qui n'a rien prouvé.
    depose: Cell<bool>,
}

/// Elle n'authentifie PERSONNE : le défaut du trait refuse, et c'est ce qui
/// permet au harnais d'affirmer qu'aucune suite d'octets n'ouvre de session.
impl ams_session::Authenticator for Politique {}

impl Policy for Politique {
    fn accepts_recipient(&self, _forward_path: &Path<'_>, submitter: bool) -> RecipientVerdict {
        if submitter {
            self.depose.set(true);
        }
        if self.verdicts.is_empty() {
            return RecipientVerdict::RejectPermanent;
        }
        let rang = self.curseur.get();
        self.curseur.set(rang.wrapping_add(1));
        match self.verdicts[rang % self.verdicts.len()] % 4 {
            0 => RecipientVerdict::Accept,
            1 => RecipientVerdict::RejectPermanent,
            2 => RecipientVerdict::RejectTemporary,
            _ => RecipientVerdict::RelayDenied,
        }
    }
}

/// Ce qu'une boucle peut faire subir à une session.
#[derive(Debug, Arbitrary)]
enum Evenement {
    /// Le pair envoie une ligne.
    Ligne(Vec<u8>),
    /// La poignée de main TLS a abouti.
    TlsEtabli,
    /// Le pair répond au défi SASL — n'importe quels octets.
    ReponseSasl(Vec<u8>),
    /// Le message a été lu.
    MessageRegle(u8),
}

#[derive(Debug, Arbitrary)]
struct Entree {
    verdicts: Vec<u8>,
    evenements: Vec<Evenement>,
}

/// Toutes les réponses que la session peut produire. Rien d'autre n'est licite.
fn vocabulaire() -> Vec<Vec<u8>> {
    let domaine = String::from_utf8(DOMAINE.to_vec()).expect("ASCII");
    let mut liste: Vec<Vec<u8>> = Vec::new();
    // **LES FORMES D'`EHLO`, TOUTES**. Cette liste était périmée de trois
    // tranches — ni `CHUNKING`, ni `PIPELINING`, ni `ENHANCEDSTATUSCODES` — et
    // rien ne le disait : le fuzz ne composait pas d'`EHLO` valable assez
    // souvent pour tomber dessus. Les graines écrites depuis en portent un, et
    // la faute est sortie au premier tour.
    let annonce = format!(
        "250-{domaine}\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n"
    );
    liste.push(format!("{annonce}250-CHUNKING\r\n250 STARTTLS\r\n").into_bytes());
    liste.push(format!("{annonce}250-CHUNKING\r\n250 AUTH PLAIN\r\n").into_bytes());
    liste.push(format!("{annonce}250 CHUNKING\r\n").into_bytes());
    liste.push(format!("220 {domaine} ESMTP\r\n").into_bytes());
    liste.push(format!("250 {domaine}\r\n").into_bytes());
    for texte in [
        "250 2.1.0 Sender ok",
        "250 2.1.5 Recipient ok",
        "250 2.0.0 Reset ok",
        "250 2.0.0 OK",
        "250 2.0.0 Message accepted",
        "221 2.0.0 Bye",
        "220 2.0.0 Ready to start TLS",
        "235 2.7.0 Authentication successful",
        "334 ",
        "354 Start mail input; end with <CRLF>.<CRLF>",
        "252 2.0.0 Cannot verify; message will be attempted",
        "214 2.0.0 See RFC 5321",
        "450 4.2.1 Mailbox busy, try again later",
        "451 4.3.2 Message not accepted, try again later",
        "452 4.5.3 Too many recipients",
        "500 5.5.2 Line too long",
        "500 5.5.2 Line must end with CRLF",
        "500 5.5.1 Command not recognised",
        "501 5.5.2 Syntax error in parameters or arguments",
        "501 5.7.0 Authentication aborted",
        "504 5.7.0 Unrecognized authentication type",
        "502 5.5.4 Command not implemented",
        "502 5.5.4 EXPN not available",
        "503 5.5.0 Send EHLO first",
        "503 5.5.0 Nested MAIL command",
        "503 5.5.0 Need MAIL before RCPT",
        "503 5.5.0 Need RCPT before DATA",
        "503 5.5.0 TLS already active",
        "503 5.5.0 Already authenticated",
        "535 5.7.1 Authentication credentials invalid",
        "538 5.7.1 Encryption required for authentication",
        "550 5.1.1 Mailbox unavailable",
        "550 5.7.1 Relay access denied",
        "554 5.7.1 Message rejected",
        // `BDAT` (RFC 3030), la garde anti-boucle (§6.3) et le refus de
        // service : autant de réponses que cette liste ignorait.
        "250 2.0.0 Chunk ok",
        "503 5.5.0 Need MAIL and RCPT before BDAT",
        "503 5.5.0 Need RCPT before BDAT",
        "503 5.5.0 BDAT already started; finish with BDAT LAST",
        "554 5.4.6 Too many hops; message is looping",
        "554 5.6.0 Bare CR or LF in message data",
        "552 5.3.4 Message exceeds maximum size",
        "421 4.3.2 Service not available, closing transmission channel",
        "451 4.3.0 Message not accepted, try again later",
        "550 5.7.1 Message rejected: sender domain policy (DMARC)",
        "550 5.7.23 Sender address rejected: not authorized by SPF",
        "451 4.4.3 Temporary error while checking SPF, try again later",
        // Les paramètres ESMTP qu'on ne sert pas (§4.1.1.11).
        "504 5.5.4 Parameter not recognised",
    ] {
        liste.push(format!("{texte}\r\n").into_bytes());
    }
    liste
}

/// Vérifie qu'une réponse appartient au vocabulaire, et qu'elle est bien formée.
/// Consomme un morceau annoncé, et rend la main comme la boucle le ferait.
///
/// **ON LIT EXACTEMENT CE QUI EST ANNONCÉ.** Ici les octets viennent d'un flux
/// fabriqué à partir de la taille elle-même : ce qui compte n'est pas leur
/// contenu, c'est que le récepteur s'arrête au bon endroit et que la session
/// réponde ensuite dans son vocabulaire clos.
fn avaler_le_morceau(
    session: &mut SmtpSession<'_, &Politique>,
    size: u64,
    last: bool,
    tampon: &mut [u8],
    connu: &[Vec<u8>],
) {
    // Une taille arbitraire vient du pair ; on n'alloue pas d'après elle (C3).
    let combien = usize::try_from(size).unwrap_or(usize::MAX).min(4096);
    let flux = vec![b'x'; combien];
    let mut reste: &[u8] = &flux;
    loop {
        let Ok((evenement, consomme)) = session.feed_chunk(reste) else {
            return;
        };
        reste = reste.get(consomme..).unwrap_or_default();
        match evenement {
            ChunkEvent::Content(_) => {}
            ChunkEvent::ChunkComplete | ChunkEvent::Complete => break,
            // Le flux fabriqué est plus court que ce que le pair a annoncé :
            // c'est le cas d'une connexion coupée en plein morceau.
            ChunkEvent::NeedMore => return,
        }
    }
    if last {
        if let Ok(tour) = session.on_data_settled(DataOutcome::Accepted, tampon) {
            verifier_reponse_a_une_commande(tour.reply(), connu);
        }
        return;
    }
    if let Ok(tour) = session.on_chunk_received(tampon) {
        verifier_reponse_a_une_commande(tour.reply(), connu);
        assert_eq!(tour.action(), Action::Continue);
    }
}

fn verifier_reponse(reply: &[u8], connu: &[Vec<u8>]) {
    assert!(
        reply.ends_with(b"\r\n"),
        "réponse sans CRLF final : {reply:?}"
    );
    assert!(
        connu.iter().any(|attendu| attendu == reply),
        "réponse hors du vocabulaire clos — écho probable : {:?}",
        String::from_utf8_lossy(reply)
    );
}

/// La même chose, **et l'état étendu** : c'est la réponse à une COMMANDE.
///
/// La bannière, elle, n'en porte pas : elle précède l'`EHLO`, donc la
/// négociation de RFC 2034, et n'est la réponse à rien. Aucun serveur n'en met
/// là, et un client qui lirait un état sur la bannière lirait un verdict là où
/// il n'y a qu'une salutation.
fn verifier_reponse_a_une_commande(reply: &[u8], connu: &[Vec<u8>]) {
    verifier_reponse(reply, connu);
    verifier_l_etat_etendu(reply);
}

/// **CHAQUE RÉPONSE PORTE UN ÉTAT ÉTENDU QUI S'ACCORDE AVEC SON CODE**
/// (RFC 2034 §4, RFC 3463 §3.2).
///
/// Un `550 4.x.x` ferait réessayer un pair qu'on refuse définitivement ; un
/// `250 5.x.x` n'a aucun sens. C'est la propriété que le typage seul ne peut pas
/// tenir, puisque l'état et le code sont choisis séparément.
///
/// Les `3xx` n'en portent PAS : §4 ne les mentionne pas, et RFC 3463 ne définit
/// aucune classe `3`. Ce sont des invitations à continuer, pas des verdicts.
fn verifier_l_etat_etendu(reply: &[u8]) {
    // Une réponse multiligne — l'`EHLO` — négocie l'extension : elle n'en porte
    // pas, et c'est la seule exception.
    if reply.get(3) == Some(&b'-') {
        return;
    }
    let Some(classe) = reply.first().copied() else {
        return;
    };
    let reste = reply.get(4..).unwrap_or_default();
    if classe == b'3' {
        assert!(
            !ressemble_a_un_etat(reste),
            "une `3xx` porte un état étendu : {:?}",
            String::from_utf8_lossy(reply)
        );
        return;
    }
    assert!(
        ressemble_a_un_etat(reste),
        "une réponse sans état étendu : {:?}",
        String::from_utf8_lossy(reply)
    );
    assert_eq!(
        reste.first().copied(),
        Some(classe),
        "la classe de l'état contredit le code : {:?}",
        String::from_utf8_lossy(reply)
    );
}

/// Ces octets commencent-ils par `chiffre.chiffres.chiffres` suivi d'une espace ?
fn ressemble_a_un_etat(reste: &[u8]) -> bool {
    let mut morceaux = reste.splitn(2, |octet| *octet == b' ');
    let Some(etat) = morceaux.next() else {
        return false;
    };
    if morceaux.next().is_none() {
        return false;
    }
    let mut nombres = etat.split(|octet| *octet == b'.');
    let trois: Vec<&[u8]> = nombres.by_ref().take(3).collect();
    if trois.len() != 3 || nombres.next().is_some() {
        return false;
    }
    trois.iter().enumerate().all(|(rang, nombre)| {
        !nombre.is_empty()
            && nombre.len() <= 3
            && nombre.iter().all(u8::is_ascii_digit)
            // La classe est d'un seul chiffre, et vaut 2, 4 ou 5.
            && (rang != 0 || matches!(nombre, [b'2' | b'4' | b'5']))
    })
}

fuzz_target!(|entree: Entree| {
    let connu = vocabulaire();
    let config = Config::new(DOMAINE, 2, 10_485_760, Limits::DEFAULT).expect("configurable");
    let politique = Politique {
        verdicts: entree.verdicts,
        curseur: Cell::new(0),
        depose: Cell::new(false),
    };
    let mut session = SmtpSession::new(config, &politique);
    let mut tampon = [0_u8; 512];

    // La bannière aussi appartient au vocabulaire.
    let banniere = session.greeting(&mut tampon).expect("tampon suffisant");
    verifier_reponse(banniere, &connu);

    for evenement in entree.evenements {
        match evenement {
            Evenement::TlsEtabli => {
                session.on_tls_established();
                // Après la poignée de main, RIEN n'a survécu (RFC 3207 §4.2).
                assert!(session.is_encrypted());
                assert!(!session.is_authenticated());
            }
            Evenement::ReponseSasl(reponse) => {
                // N'IMPORTE QUELS OCTETS : base64 valide ou non, `PLAIN` bien
                // formé ou non, annulation par `*`. La session doit rendre une
                // réponse de son vocabulaire, et jamais paniquer.
                if let Ok(tour) = session.feed_auth(&reponse, &mut tampon) {
                    verifier_reponse_a_une_commande(tour.reply(), &connu);
                    assert_eq!(tour.action(), Action::Continue);
                    // ON NE S'AUTHENTIFIE PAS PAR HASARD : la politique de ce
                    // harnais ne connaît AUCUN compte, donc aucune suite
                    // d'octets ne doit ouvrir de session.
                    assert!(
                        !session.is_authenticated(),
                        "une réponse SASL a ouvert une session sans compte : {:?}",
                        String::from_utf8_lossy(&reponse)
                    );
                }
            }
            Evenement::MessageRegle(choix) => {
                let verdict = match choix % 3 {
                    0 => DataOutcome::Accepted,
                    1 => DataOutcome::RejectedPermanent,
                    _ => DataOutcome::RejectedTemporary,
                };
                if let Ok(tour) = session.on_data_settled(verdict, &mut tampon) {
                    verifier_reponse_a_une_commande(tour.reply(), &connu);
                    assert_eq!(tour.action(), Action::Continue);
                }
            }
            Evenement::Ligne(ligne) => {
                let tour = match session.handle(&ligne, &mut tampon) {
                    Ok(tour) => tour,
                    // Une session close ou hors phase refuse : c'est prévu.
                    Err(Error::SessionClosed | Error::NotInCommandPhase) => continue,
                    Err(autre) => panic!("le tampon de 512 octets suffit toujours : {autre:?}"),
                };
                let reply = tour.reply();
                verifier_reponse_a_une_commande(reply, &connu);

                match tour.action() {
                    // LE REFUS EMBLÉMATIQUE DE C6, ÉPROUVÉ : jamais d'échange
                    // SASL sans chiffrement.
                    Action::ReadAuthResponse => {
                        assert!(
                            session.is_encrypted(),
                            "AUTH engagé hors chiffrement : {:?}",
                            String::from_utf8_lossy(&ligne)
                        );
                        assert!(reply.starts_with(b"334 "), "AUTH sans défi 334");
                    }
                    Action::StartTls => {
                        assert!(
                            !session.is_encrypted(),
                            "STARTTLS sur session déjà chiffrée"
                        );
                        assert!(reply.starts_with(b"220 "));
                    }
                    Action::ReceiveData => assert!(reply.starts_with(b"354 ")),
                    // **UN `BDAT` NE RÉPOND QU'APRÈS LES OCTETS** (RFC 3030 §2).
                    // Le moindre octet émis ici arriverait au milieu du morceau
                    // que le pair est déjà en train d'envoyer, et il ne saurait
                    // pas de quoi cette réponse parle.
                    Action::ReceiveChunk { size, last } => {
                        assert!(
                            reply.is_empty(),
                            "un BDAT a répondu avant ses octets : {}",
                            String::from_utf8_lossy(reply)
                        );
                        avaler_le_morceau(&mut session, size, last, &mut tampon, &connu);
                    }
                    Action::Close => assert!(reply.starts_with(b"221 ")),
                    // UN TOUR QUI DIFFÈRE NE RÉPOND PAS. Le moindre octet émis
                    // ici serait une réponse au `MAIL FROM:` composée AVANT de
                    // savoir ce que vaut l'expéditeur — et le pair, lui, ne
                    // saurait pas laquelle des deux compte.
                    //
                    // La session par défaut ne demande aucune vérification
                    // (`SenderPolicy::Ignore`), donc ce bras ne s'emprunte pas
                    // ici. Il tient quand même la propriété : si un jour la
                    // configuration de ce harnais change, elle sera éprouvée.
                    Action::CheckSender => assert!(
                        reply.is_empty(),
                        "un tour qui diffère a pourtant répondu : {}",
                        String::from_utf8_lossy(reply)
                    ),
                    Action::Continue => {}
                }
            }
        }
    }

    // **AUCUNE SUITE D'OCTETS NE FAIT DE CE PAIR UN DÉPOSANT.**
    //
    // Cette politique n'authentifie personne — le défaut du trait refuse — et la
    // session ne doit donc jamais lui annoncer un déposant authentifié. Un seul
    // `true` ici, et une politique réelle accepterait un destinataire qui n'est
    // pas d'ici : c'est-à-dire relaierait pour un pair qui n'a rien prouvé.
    assert!(
        !politique.depose.get(),
        "la session a annoncé un déposant authentifié sans authentification"
    );
    assert!(!session.is_authenticated());
});
