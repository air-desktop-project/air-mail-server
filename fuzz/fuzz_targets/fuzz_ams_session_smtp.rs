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

use ams_proto_smtp::{Limits, Path};
use ams_session::{Action, Config, DataOutcome, Error, Policy, RecipientVerdict, SmtpSession};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Le domaine du serveur, fixe : le vocabulaire clos en dépend.
const DOMAINE: &[u8] = b"mail.example.com";

/// Une politique qui déroule des verdicts arbitraires, en boucle.
struct Politique {
    verdicts: Vec<u8>,
    curseur: Cell<usize>,
}

/// Elle n'authentifie PERSONNE : le défaut du trait refuse, et c'est ce qui
/// permet au harnais d'affirmer qu'aucune suite d'octets n'ouvre de session.
impl ams_session::Authenticator for Politique {}

impl Policy for Politique {
    fn accepts_recipient(&self, _forward_path: &Path<'_>) -> RecipientVerdict {
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
    // Les deux formes d'`EHLO`, avant et après chiffrement.
    liste.push(format!("250-{domaine}\r\n250-SIZE 10485760\r\n250 STARTTLS\r\n").into_bytes());
    liste.push(format!("250-{domaine}\r\n250-SIZE 10485760\r\n250 AUTH PLAIN\r\n").into_bytes());
    liste.push(format!("220 {domaine} ESMTP\r\n").into_bytes());
    liste.push(format!("250 {domaine}\r\n").into_bytes());
    for texte in [
        "250 Sender ok",
        "250 Recipient ok",
        "250 Reset ok",
        "250 OK",
        "250 Message accepted",
        "221 Bye",
        "220 Ready to start TLS",
        "235 Authentication successful",
        "334 ",
        "354 Start mail input; end with <CRLF>.<CRLF>",
        "252 Cannot verify; message will be attempted",
        "214 See RFC 5321",
        "450 Mailbox busy, try again later",
        "451 Message not accepted, try again later",
        "452 Too many recipients",
        "500 Line too long",
        "500 Line must end with CRLF",
        "500 Command not recognised",
        "501 Syntax error in parameters or arguments",
        "501 Authentication aborted",
        "504 Unrecognized authentication type",
        "502 Command not implemented",
        "502 EXPN not available",
        "503 Send EHLO first",
        "503 Nested MAIL command",
        "503 Need MAIL before RCPT",
        "503 Need RCPT before DATA",
        "503 TLS already active",
        "503 Already authenticated",
        "535 Authentication credentials invalid",
        "538 Encryption required for authentication",
        "550 Mailbox unavailable",
        "550 Relay access denied",
        "554 Message rejected",
    ] {
        liste.push(format!("{texte}\r\n").into_bytes());
    }
    liste
}

/// Vérifie qu'une réponse appartient au vocabulaire, et qu'elle est bien formée.
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

fuzz_target!(|entree: Entree| {
    let connu = vocabulaire();
    let config = Config::new(DOMAINE, 2, 10_485_760, Limits::DEFAULT).expect("configurable");
    let politique = Politique {
        verdicts: entree.verdicts,
        curseur: Cell::new(0),
    };
    let mut session = SmtpSession::new(config, politique);
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
                    verifier_reponse(tour.reply(), &connu);
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
                    verifier_reponse(tour.reply(), &connu);
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
                verifier_reponse(reply, &connu);

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
});
