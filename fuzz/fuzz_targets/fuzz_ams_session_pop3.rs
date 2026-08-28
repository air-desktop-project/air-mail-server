// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la session POP3, pilotée par un pair hostile.**
//!
//! Le fuzzer joue une conversation entière — lignes quelconques, poignée de main
//! TLS à n'importe quel moment, ouverture de boîte accordée ou refusée — et
//! vérifie ce que la session promet.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, et rien ne déborde d'un tampon.
//! 2. **Le vocabulaire de sortie est CLOS.** Toute réponse commence par `+OK` ou
//!    `-ERR` et finit par un `CRLF` : un serveur qui renverrait ce qu'un pair
//!    lui a envoyé lui offrirait un moyen d'écrire dans le dialogue.
//! 3. **Aucune session ne s'ouvre sans le bon mot de passe** — la politique de
//!    ce harnais n'en connaît qu'un.
//! 4. **`USER`/`PASS` n'aboutissent jamais hors chiffrement** (C6).
//! 5. **Un `QUIT` venu d'AUTHORIZATION n'efface jamais rien** : `CommitAndClose`
//!    n'est rendu que si la boîte a été ouverte.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_pop3::{Limits, MessageNumber};
use ams_sasl::Credentials;
use ams_session::Authenticator;
use ams_session::pop3::{Action, Error, Mailbox, Session};

/// Le seul compte que ce harnais connaisse.
const COMPTE: &[u8] = b"jean";
/// Son mot de passe.
const SECRET: &[u8] = b"ouvre-toi";

struct UnCompte;

impl Authenticator for UnCompte {
    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        credentials.authentication_identity == COMPTE && credentials.password == SECRET
    }
}

/// Une boîte de trois messages.
struct Boite {
    effaces: [bool; 3],
}

impl Boite {
    fn rang(message: MessageNumber) -> Option<usize> {
        let rang = usize::try_from(message.value().saturating_sub(1)).unwrap_or(usize::MAX);
        (rang < 3).then_some(rang)
    }
}

impl Mailbox for Boite {
    fn highest(&self) -> u32 {
        3
    }
    fn size(&self, message: MessageNumber) -> Option<u64> {
        let rang = Self::rang(message)?;
        (!self.effaces[rang]).then_some(100)
    }
    fn uid(&self, message: MessageNumber) -> Option<u32> {
        let rang = Self::rang(message)?;
        (!self.effaces[rang]).then(|| message.value())
    }
    fn mark_deleted(&mut self, message: MessageNumber) -> bool {
        let Some(rang) = Self::rang(message) else {
            return false;
        };
        let neuf = !self.effaces[rang];
        self.effaces[rang] = true;
        neuf
    }
    fn reset_deletions(&mut self) {
        self.effaces = [false; 3];
    }
}

#[derive(Debug, Arbitrary)]
enum Evenement {
    /// Le pair envoie une ligne.
    Ligne(Vec<u8>),
    /// La poignée de main TLS a abouti.
    TlsEtabli,
    /// L'appelant a ouvert — ou non — la boîte.
    Ouverture(bool),
    /// Le pair envoie des octets de message (émission en cours).
    Corps(Vec<u8>),
}

#[derive(Debug, Arbitrary)]
struct Entree {
    stls: bool,
    evenements: Vec<Evenement>,
}

/// Toute réponse doit appartenir à ce vocabulaire.
fn verifier(reponse: &[u8]) {
    assert!(
        reponse.starts_with(b"+OK") || reponse.starts_with(b"-ERR"),
        "réponse hors vocabulaire : {:?}",
        String::from_utf8_lossy(reponse)
    );
    assert!(reponse.ends_with(b"\r\n"), "réponse sans CRLF");
    // Une réponse ne porte JAMAIS deux lignes : la seconde serait lue comme la
    // réponse à autre chose.
    assert_eq!(
        reponse.windows(2).filter(|f| *f == b"\r\n").count(),
        1,
        "réponse à plusieurs lignes"
    );
}

fuzz_target!(|entree: Entree| {
    let mut session: Session<UnCompte, Boite> =
        Session::new(Limits::DEFAULT, entree.stls, UnCompte);
    let mut tampon = [0_u8; 1024];

    let banniere = session.greeting(&mut tampon).expect("tampon suffisant");
    verifier(banniere);

    let mut ouverte = false;
    for evenement in entree.evenements {
        match evenement {
            Evenement::TlsEtabli => {
                session.on_tls_established();
                assert!(session.is_encrypted());
            }
            Evenement::Ouverture(accordee) => {
                let boite = accordee.then_some(Boite {
                    effaces: [false; 3],
                });
                if let Ok(tour) = session.on_mailbox_opened(boite, &mut tampon) {
                    verifier(tour.reply());
                    ouverte = accordee;
                    assert_eq!(session.is_open(), accordee);
                }
            }
            Evenement::Corps(octets) => {
                // Hors émission, la session refuse : c'est prévu.
                if let Ok((lus, emis)) = session.feed_body(&octets, &mut tampon) {
                    assert!(lus <= octets.len());
                    // Le doublement peut DOUBLER la taille, jamais plus.
                    assert!(emis.len() <= lus.saturating_mul(2));
                }
            }
            Evenement::Ligne(ligne) => {
                let tour = match session.handle(&ligne, &mut tampon) {
                    Ok(tour) => tour,
                    // Close, ou en pleine émission : prévu.
                    Err(Error::SessionClosed | Error::NotInCommandPhase) => continue,
                    Err(autre) => panic!("un tampon de 1024 octets suffit toujours : {autre:?}"),
                };
                verifier(tour.reply());

                match tour.action() {
                    // C6 : jamais d'identifiants hors chiffrement. Une ouverture
                    // demandée sans TLS serait la faille.
                    Action::OpenMailbox => {
                        assert!(
                            session.is_encrypted(),
                            "ouverture demandée hors chiffrement"
                        );
                        assert_eq!(session.user(), COMPTE, "un autre compte a ouvert");
                    }
                    Action::StartTls => {
                        assert!(!session.is_encrypted(), "STLS sur session déjà chiffrée");
                    }
                    // L'état UPDATE n'est atteint que depuis TRANSACTION : un
                    // `QUIT` d'AUTHORIZATION n'efface rien, et c'est ce qui
                    // protège le courrier d'une coupure réseau.
                    Action::CommitAndClose => {
                        assert!(ouverte, "effacement demandé sans boîte ouverte");
                    }
                    Action::SendListing => {
                        // Toutes les lignes, jusqu'au terminateur.
                        let mut lignes = 0_u32;
                        while let Ok(Some(ligne)) = session.next_listing(&mut tampon) {
                            assert!(ligne.ends_with(b"\r\n"));
                            lignes = lignes.saturating_add(1);
                            if ligne == b".\r\n" {
                                break;
                            }
                            assert!(lignes < 1000, "listing sans fin");
                        }
                    }
                    Action::SendBody { .. } => {
                        assert!(ouverte, "un message sans boîte ouverte");
                    }
                    Action::Continue | Action::Close => {}
                }
            }
        }
    }
});
