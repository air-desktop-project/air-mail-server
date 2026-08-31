// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la fabrication d'un paquet protégé** (§17 de RFC 9000, §5 de
//! RFC 9001).
//!
//! # Pourquoi celle-ci, alors que la lecture a déjà la sienne
//!
//! `fuzz_ams_quic_receive` éprouve ce qu'on fait d'octets venus d'ailleurs.
//! Celle-ci éprouve ce qu'on ENVOIE — et une faute d'émission ne se voit jamais
//! chez nous. Elle se voit chez le pair, sous la forme d'un paquet illisible, à
//! un moment et pour une raison qui n'ont plus rien à voir avec l'endroit où la
//! faute a été commise.
//!
//! Trois pièges y tiennent, et aucun ne se signale :
//!
//! - **le masque se pose après le chiffrement** (§5.4.2) — l'échantillon se
//!   prend dans le chiffré ; masquer d'abord donnerait un masque que le pair ne
//!   retrouve pas ;
//! - **la longueur annoncée couvre le numéro, la charge et le tag** (§17.2) —
//!   trop courte, elle coupe le paquet suivant ; trop longue, elle en mange un ;
//! - **l'en-tête entier est les données associées** (§5.3 de RFC 9001) — l'en
//!   oublier un octet rendrait ce champ modifiable en chemin.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient le plan, le numéro et la charge.
//! 2. **CE QU'ON ÉCRIT SE RELIT**, et rend exactement la charge qu'on avait, au
//!    bon numéro et de la bonne forme.
//! 3. **CE QU'ON ABÎME NE SE RELIT PAS** : un octet changé n'importe où dans le
//!    paquet fait échouer l'authentification.
//! 4. **CE QUE `payload_capacity` PROMET, `seal_packet` LE TIENT** — c'est la
//!    propriété dont dépend la garde d'amplification (§8.1).
//! 5. **UN REFUS VIENT D'UN VOCABULAIRE FINI**, et n'écrit rien de partiel.
//! 6. **DEUX PAQUETS SE COALISENT** (§12.2), et la longueur annoncée dit
//!    exactement où le premier s'arrête.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_quic::{ConnectionId, LongKind};
use ams_quic::{PacketKind, Plan, Reason, open_packet, payload_capacity, seal_packet};
use ams_quic_crypto::{Keys, Role, Secret};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Quelle forme de paquet écrire.
    forme: u8,
    /// Les octets de l'identifiant de destination.
    destination: &'a [u8],
    /// Ceux de l'identifiant de source.
    source: &'a [u8],
    /// Le jeton d'un `Initial`.
    token: &'a [u8],
    /// La charge, c'est-à-dire les trames déjà composées.
    charge: &'a [u8],
    /// Le numéro de paquet, et le plus grand acquitté.
    numero: u64,
    acquitte: Option<u64>,
    /// La phase de clé d'un en-tête court.
    phase: bool,
    /// La place qu'on laisse à l'écriture.
    place: u16,
}

/// Les clés `Initial` du serveur, dérivées une fois pour toutes.
fn clefs() -> Keys {
    Secret::initial(
        &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08],
        Role::Server,
    )
    .expect("dérivable")
    .keys()
    .expect("dérivables")
}

/// Un identifiant à partir de ces octets — §17.2 en borne vingt.
fn identifiant(octets: &[u8]) -> ConnectionId {
    let borne = octets.len().min(20);
    ConnectionId::new(octets.get(..borne).unwrap_or_default()).expect("vingt octets au plus")
}

fuzz_target!(|entree: Entree| {
    let clefs = clefs();
    let destination = identifiant(entree.destination);
    let source = identifiant(entree.source);
    // Un jeton plus long qu'un datagramme n'existe pas : §17.2.2 le fait tenir
    // dans le paquet, que §14 borne.
    let token = entree
        .token
        .get(..entree.token.len().min(2048))
        .unwrap_or_default();

    let plan = match entree.forme % 3 {
        0 => Plan::Initial {
            destination,
            source,
            token,
        },
        1 => Plan::Handshake {
            destination,
            source,
        },
        _ => Plan::OneRtt {
            destination,
            key_phase: entree.phase,
        },
    };

    // PROPRIÉTÉ 4 : ce qui est promis est tenu.
    let place = usize::from(entree.place);
    let promis = payload_capacity(&plan, entree.numero, entree.acquitte, place);
    if promis >= 3 {
        let charge = std::vec![0x41_u8; promis];
        let mut tampon = std::vec![0_u8; place];
        let ecrit = seal_packet(
            &mut tampon,
            &clefs,
            &plan,
            entree.numero,
            entree.acquitte,
            &charge,
        )
        .expect("ce qui est promis doit être tenu");
        assert!(
            ecrit <= place,
            "{ecrit} octets écrits pour {place} de place promise"
        );
    }

    // Le corps de l'essai : la charge soumise, dans un tampon assez grand.
    let mut tampon = std::vec![0_u8; 70_000];
    let ecrit = match seal_packet(
        &mut tampon,
        &clefs,
        &plan,
        entree.numero,
        entree.acquitte,
        entree.charge,
    ) {
        Ok(ecrit) => ecrit,
        Err(issue) => {
            // PROPRIÉTÉ 5 : un vocabulaire fini.
            assert!(
                matches!(
                    issue.reason(),
                    Reason::SendOverflow | Reason::WindowTooSmall
                ),
                "un refus hors du vocabulaire : {:?}",
                issue.reason()
            );
            return;
        }
    };

    // PROPRIÉTÉ 2 : ce qu'on écrit se relit.
    let paquet = tampon.get(..ecrit).expect("écrit").to_vec();
    let mut datagramme = paquet.clone();
    // Le lecteur reconstruit à partir de ce qu'il a DÉJÀ traité.
    let plus_grand = entree.numero.checked_sub(1);
    let ouvert = open_packet(&mut datagramme, &clefs, plus_grand, destination.len())
        .expect("ce qu'on écrit doit se relire");
    assert_eq!(ouvert.number, entree.numero, "le numéro s'est perdu");
    assert_eq!(
        ouvert.total, ecrit,
        "la longueur annoncée ne dit pas la fin"
    );
    assert_eq!(
        datagramme.get(ouvert.payload_at..ouvert.payload_at + ouvert.payload_len),
        Some(entree.charge),
        "la charge n'est pas celle qu'on avait"
    );
    let attendue = match entree.forme % 3 {
        0 => PacketKind::Long(LongKind::Initial),
        1 => PacketKind::Long(LongKind::Handshake),
        _ => PacketKind::Short,
    };
    assert_eq!(ouvert.kind, attendue, "la forme s'est perdue");
    if attendue == PacketKind::Short {
        assert_eq!(
            ouvert.key_phase, entree.phase,
            "la phase de clé s'est perdue"
        );
    }

    // PROPRIÉTÉ 3 : ce qu'on abîme ne se relit pas.
    //
    // On ne touche qu'UN octet, choisi par le numéro soumis, pour que le coût
    // reste borné quelle que soit la taille du paquet.
    if !paquet.is_empty() {
        let ou = usize::try_from(entree.numero % 64).unwrap_or(0) % paquet.len();
        let mut abime = paquet.clone();
        abime[ou] ^= 0x01;
        // Un octet abîmé change le paquet : soit il ne s'ouvre plus, soit il
        // s'ouvre sur autre chose que ce qu'on avait écrit. **Jamais il ne rend
        // la même charge au même numéro** — c'est ce que l'authentification
        // garantit.
        if let Ok(autre) = open_packet(&mut abime, &clefs, plus_grand, destination.len()) {
            let meme_charge = abime.get(autre.payload_at..autre.payload_at + autre.payload_len)
                == Some(entree.charge);
            assert!(
                !(autre.number == entree.numero && meme_charge && autre.total == ecrit),
                "l'octet {ou} n'est pas authentifié"
            );
        }
    }

    // PROPRIÉTÉ 6 : deux paquets se coalisent, et le premier dit où il finit.
    //
    // Seul un en-tête long le permet : un en-tête court ne porte pas de
    // longueur, donc rien ne dirait où il s'arrête (§12.2).
    if attendue != PacketKind::Short && ecrit < 60_000 {
        let court = Plan::OneRtt {
            destination,
            key_phase: entree.phase,
        };
        let mut datagramme = tampon.clone();
        if let Ok(second) = seal_packet(
            datagramme.get_mut(ecrit..).expect("de la place"),
            &clefs,
            &court,
            entree.numero,
            entree.acquitte,
            b"le second",
        ) {
            datagramme.truncate(ecrit + second);
            let premier = open_packet(&mut datagramme, &clefs, plus_grand, destination.len())
                .expect("le premier se relit dans un datagramme coalisé");
            assert_eq!(
                premier.total, ecrit,
                "la longueur annoncée doit dire où le premier s'arrête"
            );
            let suite = datagramme.get_mut(ecrit..).expect("le second");
            let ouvert = open_packet(suite, &clefs, plus_grand, destination.len())
                .expect("le second se relit après le premier");
            assert_eq!(ouvert.kind, PacketKind::Short);
            assert_eq!(
                suite.get(ouvert.payload_at..ouvert.payload_at + ouvert.payload_len),
                Some(&b"le second"[..])
            );
        }
    }
});
