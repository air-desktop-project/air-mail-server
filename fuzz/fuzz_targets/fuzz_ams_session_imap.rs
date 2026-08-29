// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la session IMAP**, nourrie de commandes arbitraires.
//!
//! La grammaire découpe, la session décide. Ce qu'on éprouve ici n'est pas la
//! syntaxe — une autre cible s'en charge — mais **ce que l'état autorise**, et
//! ce que la session écrit en retour.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelle que soit la suite de commandes.
//! 2. **ON NE PEUT PAS ÊTRE AUTHENTIFIÉ SANS ÊTRE CHIFFRÉ.** C'est l'invariant
//!    qui porte tout le reste : un mot de passe ne traverse pas une connexion en
//!    clair, et aucune suite de commandes ne doit pouvoir contourner cela.
//! 3. **Toute réponse est faite de lignes complètes**, chacune terminée par un
//!    `CRLF` — sans quoi le client recollerait deux réponses en une.
//! 4. **UNE RÉPONSE ÉTIQUETÉE NE REPREND QUE LE TAG QU'ON A REÇU.** Le tag est
//!    recopié : s'il en sortait un que le client n'a pas envoyé, ce serait qu'on
//!    l'a fabriqué, ou pire, qu'on a recopié autre chose.
//! 5. **Après `LOGOUT`, la session ne répond plus.**
//! 6. **UN INTERVALLE DE `FETCH` NE DÉSIGNE JAMAIS HORS DU MESSAGE.** La
//!    session annonce une longueur au client, puis rend un intervalle à
//!    l'appelant : si l'intervalle débordait, l'appelant ne pourrait pas tenir
//!    l'annonce, et comblerait — c'est-à-dire mentirait.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_imap::{CommandReader, Flags, Limits, Need, StoreMode};
use ams_sasl::Credentials;
use ams_session::Authenticator;
use ams_session::imap::{Action, FetchChunk, Mailbox, Mailboxes, MessageInfo, Session, State};

/// Le seul compte que la politique connaisse.
struct UnCompte;

impl Authenticator for UnCompte {
    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        credentials.authentication_identity == b"jean" && credentials.password == b"ouvre-toi"
    }
}

/// Deux messages, et rien de plus : c'est la session qu'on éprouve, pas Maildir.
const TAILLES: [u64; 2] = [64, 4096];

/// La boîte d'épreuve.
struct Boite;

impl Mailbox for Boite {
    fn exists(&self) -> u32 {
        2
    }
    fn uid_validity(&self) -> u32 {
        7
    }
    fn uid_next(&self) -> u32 {
        3
    }
    fn info(&self, sequence: u32) -> Option<MessageInfo> {
        let taille = *TAILLES.get(usize::try_from(sequence).ok()?.checked_sub(1)?)?;
        Some(MessageInfo {
            uid: sequence,
            size: taille,
            flags: Flags::NONE,
            internal_date: 1_787_987_311,
        })
    }
    fn header_octets(&self, sequence: u32) -> u64 {
        // Un tiers du message, de quoi distinguer les trois sections.
        self.info(sequence).map_or(0, |info| info.size / 3)
    }
    fn permanent_flags(&self) -> Flags {
        Flags::SEEN.with(Flags::FLAGGED)
    }
    fn read(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        let Some(info) = self.info(sequence) else {
            return 0;
        };
        let reste = info.size.saturating_sub(offset);
        let voulu = usize::try_from(reste).unwrap_or(usize::MAX).min(out.len());
        let place = out.get_mut(..voulu).unwrap_or_default();
        place.fill(b'x');
        place.len()
    }
    fn store_flags(&mut self, sequence: u32, mode: StoreMode, flags: Flags) -> Option<Flags> {
        // La boîte d'épreuve ne retient rien ; ce qu'on éprouve ici est la
        // session, pas la persistance. Le message hors de portée disparaît, ce
        // qui exerce le chemin « §6.4.6 : ne pas en faire une erreur ».
        self.info(sequence)?;
        Some(match mode {
            StoreMode::Replace => flags,
            StoreMode::Add => Flags::SEEN.with(flags),
            StoreMode::Remove => Flags::SEEN.without(flags),
        })
    }
}

/// Le magasin : une seule boîte, `INBOX`.
struct Boites;

impl Mailboxes for Boites {
    type Open = Boite;
    fn name(&self, _user: &[u8], index: usize) -> Option<&[u8]> {
        (index == 0).then_some(&b"INBOX"[..])
    }
    fn open(&self, _user: &[u8], name: &[u8]) -> Option<Boite> {
        (name == b"INBOX").then_some(Boite)
    }
}

/// Vérifie qu'une réponse est faite de lignes complètes, et qu'une ligne
/// étiquetée ne porte que le tag reçu (propriétés 3 et 4).
fn verifier(reponse: &[u8], commande: &[u8]) {
    assert!(
        reponse.is_empty() || reponse.ends_with(b"\r\n"),
        "une réponse ne se termine pas par un CRLF"
    );
    for ligne in reponse.split(|octet| *octet == b'\n') {
        let ligne = ligne.strip_suffix(b"\r").unwrap_or(ligne);
        if ligne.is_empty() || ligne.starts_with(b"* ") || ligne.starts_with(b"+ ") {
            continue;
        }
        let tag = ligne
            .split(|octet| *octet == b' ')
            .next()
            .expect("un premier mot");
        let envoye = commande
            .split(|octet| matches!(*octet, b' ' | b'\r'))
            .next()
            .expect("un premier mot");
        assert_eq!(
            tag, envoye,
            "une réponse étiquetée porte un tag qu'on n'a pas reçu"
        );
    }
}

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Ce que le client envoie, bout à bout.
    flux: &'a [u8],
    /// La session sait-elle chiffrer ?
    starttls: bool,
    /// Part-on d'une connexion déjà chiffrée ?
    chiffree: bool,
}

fuzz_target!(|entree: Entree<'_>| {
    let bornes = Limits::DEFAULT;
    let mut session = Session::new(bornes, entree.starttls, UnCompte, Boites);
    if entree.chiffree {
        session.on_tls_established();
    }

    let mut sortie = vec![0_u8; 16384];
    let mut banniere = vec![0_u8; 512];
    let _ = session.greeting(&mut banniere);

    let mut lecteur = CommandReader::new();
    let mut reste = entree.flux;
    let mut close = false;
    // Une commande par tour, et pas plus de cent : ce qui n'a pas conclu en cent
    // commandes ne conclura pas.
    for _ in 0..100_u32 {
        let Ok(besoin) = lecteur.poll(reste, &bornes) else {
            break;
        };
        let longueur = match besoin {
            Need::Complete(longueur) => longueur,
            // On sert la continuation comme la boucle le ferait, et l'on
            // continue : le tampon ne grandit pas ici, donc la commande ne
            // s'achèvera pas — on s'arrête.
            Need::Continuation | Need::More => break,
        };
        let commande = &reste[..longueur];
        let issue = session.handle(commande, &mut sortie);

        // PROPRIÉTÉ 5 : après `LOGOUT`, plus rien.
        if close {
            assert!(
                issue.is_err(),
                "une session close a répondu à une commande de plus"
            );
            break;
        }
        let Ok(tour) = issue else {
            break;
        };
        // PROPRIÉTÉS 3 et 4.
        verifier(tour.reply(), commande);

        match tour.action() {
            Action::StartTls => session.on_tls_established(),
            Action::ReadAuthResponse => {
                // La boucle lirait une ligne de plus ; on lui en donne une qui
                // ne prouve rien, pour voir la session s'en sortir.
                let _ = session.on_auth_response(b"AGplYW4Ab3V2cmUtdG9p", &mut sortie);
            }
            Action::Close => close = true,
            // On écoule l'émission comme la boucle le ferait. La conclusion
            // étiquetée EN FAIT PARTIE : elle est le dernier morceau, et la
            // propriété 4 doit donc la voir passer ici.
            Action::SendFetch => {
                let mut morceaux = 0_u32;
                // Deux morceaux par message rendu, plus la conclusion ; la
                // boîte en a deux, et l'ensemble est borné par la grammaire.
                while morceaux < 4096 {
                    morceaux = morceaux.saturating_add(1);
                    let Ok(Some(morceau)) = session.next_fetch(&mut sortie) else {
                        break;
                    };
                    match morceau {
                        FetchChunk::Bytes(octets) => verifier(octets, commande),
                        FetchChunk::Message {
                            sequence,
                            offset,
                            length,
                        } => {
                            // PROPRIÉTÉ 6 : l'intervalle tient dans le message.
                            let taille = TAILLES
                                .get(usize::try_from(sequence).unwrap_or(0).saturating_sub(1))
                                .copied()
                                .unwrap_or(0);
                            assert!(
                                offset.saturating_add(length) <= taille,
                                "un intervalle déborde du message {sequence} : \
                                 {offset}+{length} > {taille}"
                            );
                        }
                    }
                }
            }
            Action::Continue => {}
        }

        // PROPRIÉTÉ 2 : l'invariant qui porte tout le reste.
        assert!(
            session.state() == State::NotAuthenticated || session.is_encrypted(),
            "authentifié sans chiffrement"
        );

        reste = &reste[longueur..];
        lecteur.reset();
    }
});
