// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les représentations des ressources** — ce que l'API rend.
//!
//! # Pourquoi celle-ci
//!
//! Ces représentations portent ce qu'un inconnu a écrit. Un sujet, un nom
//! d'expéditeur, un nom de boîte : aucun des trois n'a été choisi par nous, et
//! tous les trois se retrouvent dans un document que le client croira de nous.
//!
//! C'est la même surface que celle du JSON, vue d'un cran plus haut : ici l'on
//! ne vérifie plus que l'écrivain échappe, mais que **rien de ce qui traverse ce
//! module ne peut casser la structure** — quelles que soient les chaînes.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelles que soient les valeurs.
//! 2. **CE QUI EST ÉCRIT SE RELIT.** Chaque représentation est un document JSON
//!    que notre propre lecteur accepte — et il refuse tout ce sur quoi les
//!    analyseurs divergent, donc l'accepter veut dire quelque chose.
//! 3. **RIEN N'ÉCHAPPE À L'ÉCHAPPEMENT** : aucun octet de contrôle, aucun `<`,
//!    `>` ni `&` ne sort nu, même venu d'un sujet hostile.
//! 4. **CE QU'ON DIT EST CE QU'ON A REÇU** : l'UID, la taille et l'instant se
//!    relisent identiques. Un nombre qui changerait en route ferait agir le
//!    client sur un autre message.
//! 5. **L'`uidvalidity` EST TOUJOURS LÀ** dès qu'un UID l'est (§2.3.1.1 de
//!    RFC 9051) : sans lui, un client agit sur des identifiants caducs.
//! 6. **UNE MODIFICATION DE DRAPEAUX ACCEPTÉE NE POSE ET N'ÔTE JAMAIS LE MÊME
//!    DRAPEAU**, et ne demande jamais rien.
//! 7. **CHAQUE TAILLE DE TAMPON INSUFFISANTE SE DIT**, plutôt que d'écrire à
//!    moitié.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_api::{Event, Reader};
use ams_proto_imap::Flags;
use ams_session::http::render::{
    MailboxRow, MessageRow, read_flag_patch, write_mailbox, write_mailboxes, write_message,
    write_messages, write_metrics,
};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Le nom d'une boîte, tel qu'un client l'a choisi.
    boite: &'a str,
    messages: u32,
    unseen: u32,
    uid_next: u32,
    uid_validity: u32,
    /// Deux messages, tels qu'ils viennent de la boîte.
    uid: [u32; 2],
    taille: [u64; 2],
    drapeaux: [u16; 2],
    instant: [u64; 2],
    /// Un sujet et un expéditeur, venus d'un inconnu.
    sujet: Option<&'a str>,
    expediteur: Option<&'a str>,
    /// Le curseur de la page suivante.
    suivant: Option<u32>,
    /// Un corps de modification de drapeaux.
    patch: &'a [u8],
    /// Des noms de compteurs.
    compteurs: [&'a str; 2],
    valeurs: [u64; 2],
}

/// La place d'écriture.
const PLACE: usize = 64 * 1024;

fuzz_target!(|entree: Entree| {
    let boite = MailboxRow {
        name: entree.boite,
        messages: entree.messages,
        unseen: entree.unseen,
        uid_next: entree.uid_next,
        uid_validity: entree.uid_validity,
    };
    let messages = [
        MessageRow {
            uid: entree.uid[0],
            size: entree.taille[0],
            flags: drapeaux(entree.drapeaux[0]),
            received: entree.instant[0],
            subject: entree.sujet,
            from: entree.expediteur,
        },
        MessageRow {
            uid: entree.uid[1],
            size: entree.taille[1],
            flags: drapeaux(entree.drapeaux[1]),
            received: entree.instant[1],
            subject: entree.expediteur,
            from: entree.sujet,
        },
    ];

    let mut place = [0_u8; PLACE];
    // PROPRIÉTÉS 2, 3 et 5 : chaque représentation se relit, sans rien de nu.
    for ecrit in [
        write_mailboxes(&[boite], &mut place).map(<[u8]>::to_vec),
        write_mailbox(&boite, &mut [0_u8; PLACE]).map(<[u8]>::to_vec),
        write_message(&messages[0], entree.uid_validity, &mut [0_u8; PLACE]).map(<[u8]>::to_vec),
        write_metrics(
            &[
                (entree.compteurs[0], entree.valeurs[0]),
                (entree.compteurs[1], entree.valeurs[1]),
            ],
            &mut [0_u8; PLACE],
        )
        .map(<[u8]>::to_vec),
    ] {
        let Ok(document) = ecrit else {
            continue;
        };
        verifier(&document);
    }

    // PROPRIÉTÉ 4 : une page se relit, nombre pour nombre.
    let mut place = [0_u8; PLACE];
    if let Ok(document) = write_messages(&messages, entree.uid_validity, entree.suivant, &mut place)
    {
        let document = document.to_vec();
        verifier(&document);
        relire_une_page(&document, &messages, entree.uid_validity, entree.suivant);
    }

    // PROPRIÉTÉ 6 : une modification acceptée est cohérente.
    if let Ok(patch) = read_flag_patch(entree.patch) {
        assert_ne!(
            (patch.add, patch.remove),
            (Flags::NONE, Flags::NONE),
            "une modification acceptée ne demande rien"
        );
        for bit in TOUS {
            assert!(
                !(patch.add.contains(bit) && patch.remove.contains(bit)),
                "une modification pose et ôte le même drapeau"
            );
        }
    }

    // PROPRIÉTÉ 7 : chaque taille insuffisante se dit.
    let entier = {
        let mut place = [0_u8; PLACE];
        write_mailbox(&boite, &mut place).map(<[u8]>::len)
    };
    if let Ok(entier) = entier {
        for taille in [0_usize, entier / 2, entier.saturating_sub(1)] {
            let mut petit = std::vec![0_u8; taille];
            assert!(
                write_mailbox(&boite, &mut petit).is_err(),
                "une écriture a tenu dans {taille} octets pour {entier}"
            );
        }
    }
});

/// Les dix drapeaux qu'on sait écrire.
const TOUS: [Flags; 10] = [
    Flags::SEEN,
    Flags::ANSWERED,
    Flags::FLAGGED,
    Flags::DELETED,
    Flags::DRAFT,
    Flags::MDN_SENT,
    Flags::FORWARDED,
    Flags::JUNK,
    Flags::NON_JUNK,
    Flags::PHISHING,
];

/// Les drapeaux que ces bits désignent.
fn drapeaux(bits: u16) -> Flags {
    let mut flags = Flags::NONE;
    for (rang, bit) in TOUS.into_iter().enumerate() {
        if bits & (1_u16 << rang) != 0 {
            flags = flags.with(bit);
        }
    }
    flags
}

/// Ce document est-il ce qu'on promet ?
fn verifier(document: &[u8]) {
    // PROPRIÉTÉ 3 : rien de nu.
    assert!(
        !document
            .iter()
            .any(|octet| *octet < 0x20 || matches!(octet, b'<' | b'>' | b'&')),
        "un octet qui aurait dû être échappé est écrit tel quel"
    );
    // PROPRIÉTÉ 2 : notre propre lecteur l'accepte.
    let mut lecteur = Reader::new(document);
    let mut tours = 0_usize;
    loop {
        match lecteur.read() {
            Err(faute) => panic!("une représentation ne se relit pas : {faute:?}"),
            Ok(None) => return,
            Ok(Some(_)) => {
                tours = tours.saturating_add(1);
                assert!(tours <= document.len(), "le lecteur n'avance pas");
            }
        }
    }
}

/// Relit une page, et compare ce qu'elle dit à ce qu'on a écrit.
fn relire_une_page(
    document: &[u8],
    messages: &[MessageRow<'_>],
    uid_validity: u32,
    suivant: Option<u32>,
) {
    let mut lecteur = Reader::new(document);
    let mut attendu = None;
    let mut uids = std::vec::Vec::new();
    let mut tailles = std::vec::Vec::new();
    let mut instants = std::vec::Vec::new();
    let mut validites = std::vec::Vec::new();
    let mut curseurs = std::vec::Vec::new();
    let mut vu_next = false;
    while let Ok(Some(evenement)) = lecteur.read() {
        match evenement {
            Event::Key(clef) => {
                attendu = clef.as_plain();
                if clef.is("next") {
                    vu_next = true;
                }
            }
            Event::Number(nombre) => match attendu {
                Some("uid") => uids.push(nombre.as_u64()),
                Some("size") => tailles.push(nombre.as_u64()),
                Some("received") => instants.push(nombre.as_u64()),
                Some("uidValidity") => validites.push(nombre.as_u64()),
                Some("next") => curseurs.push(nombre.as_u64()),
                _ => {}
            },
            _ => {}
        }
    }
    // PROPRIÉTÉ 4 : ce qu'on dit est ce qu'on a reçu.
    let voulus: std::vec::Vec<_> = messages.iter().map(|m| Some(u64::from(m.uid))).collect();
    assert_eq!(uids, voulus, "un UID a changé à l'écriture");
    let voulues: std::vec::Vec<_> = messages.iter().map(|m| Some(m.size)).collect();
    assert_eq!(tailles, voulues, "une taille a changé à l'écriture");
    let voulus: std::vec::Vec<_> = messages.iter().map(|m| Some(m.received)).collect();
    assert_eq!(instants, voulus, "un instant a changé à l'écriture");
    // PROPRIÉTÉ 5 : l'`uidvalidity` est là, et c'est le bon.
    assert_eq!(
        validites,
        std::vec![Some(u64::from(uid_validity))],
        "l'`uidvalidity` manque ou a changé"
    );
    assert!(vu_next, "le curseur de page manque");
    let voulu: std::vec::Vec<_> = suivant
        .map(|uid| Some(u64::from(uid)))
        .into_iter()
        .collect();
    assert_eq!(curseurs, voulu, "le curseur a changé");
}
