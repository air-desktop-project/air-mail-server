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
//! 7. **UNE ÉMISSION S'ARRÊTE.** Un `EXPUNGE` n'avance pas le rang courant :
//!    ce qui suivait descend à sa place. La boucle ne se termine donc que parce
//!    que la boîte rétrécit, et la boîte d'épreuve rétrécit VRAIMENT. Le
//!    drainage est borné, et le franchir est une faute — un itérateur qui
//!    n'avance pas a déjà tué cette machine une fois.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;
use std::rc::Rc;

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

/// Ce que porte un message d'épreuve : sa taille et ses drapeaux.
type Message = (u64, Flags);

/// Deux messages au départ, et rien de plus : c'est la session qu'on éprouve,
/// pas Maildir.
fn depart() -> Vec<Message> {
    vec![(64, Flags::NONE), (4096, Flags::NONE)]
}

/// La boîte d'épreuve.
///
/// **Elle RETIENT ce qu'on lui écrit, et elle RÉTRÉCIT quand on efface.** Une
/// boîte qui n'oublierait rien ne ferait jamais tourner la boucle d'`EXPUNGE`,
/// et la propriété d'arrêt ne prouverait rien. L'état est partagé avec le corps
/// de la cible, qui a besoin de connaître la taille d'un message pour vérifier
/// qu'un intervalle ne déborde pas.
#[derive(Clone)]
struct Boite {
    messages: Rc<RefCell<Vec<Message>>>,
}

impl Mailbox for Boite {
    fn exists(&self) -> u32 {
        u32::try_from(self.messages.borrow().len()).unwrap_or(u32::MAX)
    }
    fn uid_validity(&self) -> u32 {
        7
    }
    fn uid_next(&self) -> u32 {
        3
    }
    fn info(&self, sequence: u32) -> Option<MessageInfo> {
        let rang = usize::try_from(sequence.checked_sub(1)?).ok()?;
        let (taille, drapeaux) = *self.messages.borrow().get(rang)?;
        Some(MessageInfo {
            uid: sequence,
            size: taille,
            flags: drapeaux,
            internal_date: 1_787_987_311,
        })
    }
    fn header_octets(&self, sequence: u32) -> u64 {
        // Un tiers du message, de quoi distinguer les trois sections.
        self.info(sequence).map_or(0, |info| info.size / 3)
    }
    fn permanent_flags(&self) -> Flags {
        Flags::SEEN.with(Flags::FLAGGED).with(Flags::DELETED)
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
    fn copy_to(&mut self, sequence: u32, mailbox: &[u8]) -> Option<u32> {
        // La copie va dans la boîte elle-même : c'est la seule qui existe, et
        // c'est ce qui fait GRANDIR la boîte — de quoi éprouver qu'une commande
        // qui agrandit ce qu'elle parcourt s'arrête quand même.
        if !mailbox.eq_ignore_ascii_case(b"INBOX") {
            return None;
        }
        let info = self.info(sequence)?;
        let mut messages = self.messages.borrow_mut();
        let uid = u32::try_from(messages.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        messages.push((info.size, info.flags));
        Some(uid)
    }

    fn undo_copies(&mut self, _mailbox: &[u8], premier: u32, dernier: u32) {
        let combien =
            usize::try_from(dernier.saturating_sub(premier).saturating_add(1)).unwrap_or(0);
        let mut messages = self.messages.borrow_mut();
        for _ in 0..combien {
            messages.pop();
        }
    }

    fn remove(&mut self, sequence: u32) -> bool {
        self.expunge(sequence)
    }

    fn expunge(&mut self, sequence: u32) -> bool {
        let Ok(rang) = usize::try_from(sequence.saturating_sub(1)) else {
            return false;
        };
        let mut messages = self.messages.borrow_mut();
        if rang >= messages.len() {
            return false;
        }
        messages.remove(rang);
        true
    }
    fn store_flags(&mut self, sequence: u32, mode: StoreMode, flags: Flags) -> Option<Flags> {
        let rang = usize::try_from(sequence.checked_sub(1)?).ok()?;
        let mut messages = self.messages.borrow_mut();
        let message = messages.get_mut(rang)?;
        message.1 = match mode {
            StoreMode::Replace => flags,
            StoreMode::Add => message.1.with(flags),
            StoreMode::Remove => message.1.without(flags),
        };
        Some(message.1)
    }
}

/// Le magasin : une seule boîte, `INBOX`.
struct Boites {
    messages: Rc<RefCell<Vec<Message>>>,
}

/// Un dépôt d'épreuve : il compte, et il rend un UID.
struct Depot {
    messages: Rc<RefCell<Vec<Message>>>,
    recus: u64,
}

impl ams_session::imap::Deposit for Depot {
    fn write(&mut self, chunk: &[u8]) -> bool {
        self.recus = self
            .recus
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        true
    }

    fn commit(self, flags: Flags, _date: Option<u64>) -> Option<u32> {
        let mut messages = self.messages.borrow_mut();
        messages.push((self.recus, flags));
        u32::try_from(messages.len()).ok()
    }

    fn abort(self) {}
}

impl Mailboxes for Boites {
    type Open = Boite;
    type Deposit = Depot;

    fn append(&self, _user: &[u8], name: &[u8]) -> Option<Depot> {
        (name == b"INBOX").then(|| Depot {
            messages: Rc::clone(&self.messages),
            recus: 0,
        })
    }

    fn name<'n>(
        &self,
        _user: &[u8],
        index: usize,
        out: &'n mut [u8],
    ) -> Option<ams_session::imap::Listing<'n>> {
        if index != 0 {
            return None;
        }
        let nom: &[u8] = b"INBOX";
        for (place, octet) in out.iter_mut().zip(nom) {
            *place = *octet;
        }
        Some(ams_session::imap::Listing {
            name: out.get(..nom.len().min(out.len()))?,
            selectable: true,
        })
    }

    fn rename(&self, _user: &[u8], _from: &[u8], _to: &[u8]) -> ams_session::imap::Renaming {
        // La boîte d'épreuve ne renomme rien : ce qu'on éprouve est la session.
        ams_session::imap::Renaming::Absente
    }

    fn delete(&self, _user: &[u8], _name: &[u8]) -> ams_session::imap::Deletion {
        // La boîte d'épreuve n'efface rien : ce qu'on éprouve est la session.
        ams_session::imap::Deletion::Absente
    }

    fn create(&self, _user: &[u8], _name: &[u8]) -> ams_session::imap::Creation {
        // La boîte d'épreuve ne crée rien : ce qu'on éprouve est la session.
        ams_session::imap::Creation::Refusee
    }
    fn open(&self, _user: &[u8], name: &[u8]) -> Option<Boite> {
        (name == b"INBOX").then_some(Boite {
            messages: Rc::clone(&self.messages),
        })
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
    let messages = Rc::new(RefCell::new(depart()));
    let mut session = Session::new(
        bornes,
        entree.starttls,
        UnCompte,
        Boites {
            messages: Rc::clone(&messages),
        },
    );
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
                // PROPRIÉTÉ 7 : l'émission s'arrête. La borne est large — deux
                // morceaux par message rendu, plus la conclusion, sur une boîte
                // de deux — et la franchir n'est pas « on s'arrête là » mais une
                // faute : c'est le signe d'une boucle qui ne tourne pas.
                let mut morceaux = 0_u32;
                let mut conclue = false;
                while morceaux < 4096 {
                    morceaux = morceaux.saturating_add(1);
                    let Ok(Some(morceau)) = session.next_fetch(&mut sortie) else {
                        conclue = true;
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
                            let taille = messages
                                .borrow()
                                .get(usize::try_from(sequence).unwrap_or(0).saturating_sub(1))
                                .map_or(0, |message| message.0);
                            assert!(
                                offset.saturating_add(length) <= taille,
                                "un intervalle déborde du message {sequence} : \
                                 {offset}+{length} > {taille}"
                            );
                        }
                    }
                }
                assert!(
                    conclue,
                    "l'émission n'a pas conclu en {morceaux} morceaux : la boucle n'avance pas"
                );
            }
            // Un `APPEND` ne passe pas par le découpage ordinaire : la cible ne
            // le produit donc jamais. Le nommer quand même évite qu'un ajout à
            // l'énumération passe inaperçu.
            Action::ReadAppend => {}
            Action::Continue => {}
        }

        // PROPRIÉTÉ 2 : l'invariant qui porte tout le reste.
        //
        // CE QU'IL FAUT EXCLURE, CE SONT LES ÉTATS QUI DONNENT ACCÈS AU
        // COURRIER. La première écriture de cette propriété disait « non
        // authentifié OU chiffré », et se trompait : `LOGOUT` mène à l'état
        // `Logout`, qui n'est ni l'un ni l'autre et ne donne accès à rien. La
        // propriété tombait donc sur un `LOGOUT` en clair, sans qu'il y eût quoi
        // que ce soit à corriger dans la session. Une propriété mal dite ne
        // trouve pas de défaut : elle en invente.
        assert!(
            !matches!(session.state(), State::Authenticated | State::Selected)
                || session.is_encrypted(),
            "authentifié sans chiffrement"
        );

        reste = &reste[longueur..];
        lecteur.reset();
    }
});
