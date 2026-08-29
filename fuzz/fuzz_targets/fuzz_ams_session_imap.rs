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

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_imap::{CommandReader, Limits, Need};
use ams_sasl::Credentials;
use ams_session::Authenticator;
use ams_session::imap::{Action, Session, State};

/// Le seul compte que la politique connaisse.
struct UnCompte;

impl Authenticator for UnCompte {
    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        credentials.authentication_identity == b"jean" && credentials.password == b"ouvre-toi"
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
    let mut session = Session::new(bornes, entree.starttls, UnCompte);
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
        let reponse = tour.reply();

        // PROPRIÉTÉ 3 : des lignes complètes, et rien d'autre.
        assert!(
            reponse.is_empty() || reponse.ends_with(b"\r\n"),
            "une réponse ne se termine pas par un CRLF"
        );
        // PROPRIÉTÉ 4 : le tag rendu est celui qu'on a reçu, ou aucun.
        for ligne in reponse.split(|octet| *octet == b'\n') {
            let ligne = ligne.strip_suffix(b"\r").unwrap_or(ligne);
            if ligne.is_empty() {
                continue;
            }
            if ligne.starts_with(b"* ") || ligne.starts_with(b"+ ") {
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

        match tour.action() {
            Action::StartTls => session.on_tls_established(),
            Action::ReadAuthResponse => {
                // La boucle lirait une ligne de plus ; on lui en donne une qui
                // ne prouve rien, pour voir la session s'en sortir.
                let _ = session.on_auth_response(b"AGplYW4Ab3V2cmUtdG9p", &mut sortie);
            }
            Action::Close => close = true,
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
