// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le journal voit, ce qu'il rend, et ce qu'il refuse de relire.

use super::{
    Delta, Disparu, Journal, Perime, Present, VANISHED_MAX, decode_journal, encode_journal,
};
use crate::ams_journal_capnp::journal;
use alloc::vec;
use alloc::vec::Vec;

const UV: u32 = 1_756_900_000;
const DEPART: u64 = 1_790_000_000_000;
const LU: u16 = 1;
const RIEN: u16 = 0;

/// Un journal de trois messages, tenu depuis `DEPART`.
fn trois() -> Journal {
    Journal::initial(UV, DEPART, &[(3, RIEN), (1, LU), (2, RIEN)])
}

#[test]
fn un_journal_initial_range_tout_au_point_de_depart() {
    let journal = trois();
    assert_eq!(journal.modseq, DEPART);
    assert_eq!(journal.floor, DEPART);
    let uids: Vec<u32> = journal.messages.iter().map(|p| p.uid).collect();
    assert_eq!(uids, [1, 2, 3], "par UID croissant");
    assert!(journal.messages.iter().all(|p| p.modseq == DEPART));
    // Depuis le départ : rien n'est « arrivé ».
    assert_eq!(
        journal.since(DEPART, 50, 50),
        Ok(Delta {
            changed: Vec::new(),
            vanished: Vec::new(),
            modseq: DEPART,
            more: false,
        })
    );
}

/// **UN CURSEUR QUI NE VIENT PAS DE CE JOURNAL EST PÉRIMÉ** — plus ancien que
/// son plancher, ou plus récent que son dernier point.
#[test]
fn un_curseur_hors_du_journal_est_perime() {
    let journal = trois();
    assert_eq!(journal.since(DEPART - 1, 50, 50), Err(Perime));
    assert_eq!(journal.since(0, 50, 50), Err(Perime));
    assert_eq!(journal.since(DEPART + 1, 50, 50), Err(Perime));
}

/// **CHAQUE CHANGEMENT A SON POINT**, et le delta les rend dans leur ordre.
#[test]
fn arrivees_drapeaux_et_disparitions_se_voient() {
    let mut journal = trois();
    // 1 disparaît, 2 est lu, 3 ne bouge pas, 4 et 5 arrivent — donnés en
    // désordre, avec un doublon.
    assert!(journal.reconcile(UV, 0, &[(5, RIEN), (2, LU), (3, RIEN), (4, LU), (5, RIEN)]));
    assert_eq!(
        journal.modseq,
        DEPART + 4,
        "quatre changements, quatre points"
    );
    let delta = journal.since(DEPART, 50, 50).expect("servi");
    assert_eq!(delta.changed, [2, 4, 5]);
    assert_eq!(delta.vanished, [1]);
    assert_eq!(delta.modseq, DEPART + 4);
    assert!(!delta.more);
    // Le message qui n'a pas bougé garde son point.
    let trois = journal.messages.iter().find(|p| p.uid == 3).expect("3");
    assert_eq!(trois.modseq, DEPART);

    // Depuis le deuxième point : seulement ce qui l'a suivi.
    let delta = journal.since(DEPART + 2, 50, 50).expect("servi");
    assert_eq!(delta.changed.len() + delta.vanished.len(), 2);

    // Rien de neuf : la comparaison le dit, et le point ne bouge pas.
    let avant = journal.clone();
    assert!(!journal.reconcile(UV, 0, &[(2, LU), (3, RIEN), (4, LU), (5, RIEN)]));
    assert_eq!(journal, avant);
}

/// Les derniers messages disparaissent, puis tout, puis la boîte se remplit à
/// nouveau : les trois fins de parcours de la comparaison.
#[test]
fn les_bords_de_la_comparaison() {
    let mut journal = trois();
    // Le dernier connu disparaît : plus rien à voir après lui.
    assert!(journal.reconcile(UV, 0, &[(1, LU), (2, RIEN)]));
    assert_eq!(journal.since(DEPART, 50, 50).expect("servi").vanished, [3]);
    // Tout disparaît.
    assert!(journal.reconcile(UV, 0, &[]));
    assert!(journal.messages.is_empty());
    // Tout arrive dans un journal vide.
    assert!(journal.reconcile(UV, 0, &[(9, RIEN), (8, RIEN)]));
    let uids: Vec<u32> = journal.messages.iter().map(|p| p.uid).collect();
    assert_eq!(uids, [8, 9]);
}

/// **UN UID PLUS PETIT QU'UN CONNU PEUT APPARAÎTRE** — un message restauré
/// d'une sauvegarde, par exemple : il est arrivé, et se voit comme tel.
#[test]
fn un_uid_restaure_sous_les_connus_est_une_arrivee() {
    let mut journal = Journal::initial(UV, DEPART, &[(5, RIEN)]);
    assert!(journal.reconcile(UV, 0, &[(3, RIEN), (5, RIEN)]));
    assert_eq!(journal.since(DEPART, 50, 50).expect("servi").changed, [3]);
}

/// **UN AUTRE UIDVALIDITY REMET LE JOURNAL À ZÉRO**, plus haut que tout ce
/// qu'il avait attribué : les curseurs d'avant deviennent périmés.
#[test]
fn un_autre_uidvalidity_perime_tous_les_curseurs() {
    let mut journal = trois();
    assert!(journal.reconcile(UV, 0, &[(1, LU)]));
    let ancien = journal.modseq;
    // Le départ proposé est plus petit que le dernier point : on le dépasse.
    assert!(journal.reconcile(UV + 1, 5, &[(1, RIEN), (2, RIEN)]));
    assert_eq!(journal.uid_validity, UV + 1);
    assert!(journal.floor > ancien);
    assert_eq!(journal.since(ancien, 50, 50), Err(Perime));
    assert!(journal.vanished.is_empty());
    // Et un départ proposé plus grand est pris tel quel.
    let plus_tard = journal.modseq + 1_000;
    assert!(journal.reconcile(UV + 2, plus_tard, &[]));
    assert_eq!(journal.floor, plus_tard);
}

/// **LES PAGES SE SUIVENT PAR LE CURSEUR**, et ne perdent ni ne répètent rien.
#[test]
fn le_delta_se_pagine() {
    let mut journal = Journal::initial(UV, DEPART, &[(1, RIEN), (2, RIEN), (3, RIEN)]);
    assert!(journal.reconcile(UV, 0, &[(2, LU), (3, LU), (4, RIEN), (5, RIEN)]));
    // Cinq événements : 1 disparu, 2 et 3 lus, 4 et 5 arrivés.
    let mut curseur = DEPART;
    let (mut changes, mut disparus, mut pages) = (Vec::new(), Vec::new(), 0);
    loop {
        let delta = journal.since(curseur, 2, 50).expect("servi");
        pages += 1;
        changes.extend(delta.changed.iter().copied());
        disparus.extend(delta.vanished.iter().copied());
        curseur = delta.modseq;
        if !delta.more {
            break;
        }
    }
    assert_eq!(changes, [2, 3, 4, 5]);
    assert_eq!(disparus, [1]);
    assert_eq!(curseur, journal.modseq);
    assert!(pages > 1);

    // La borne des disparitions pagine aussi ; une borne nulle vaut un.
    assert!(journal.reconcile(UV, 0, &[]));
    let delta = journal.since(DEPART + 5, 50, 0).expect("servi");
    assert_eq!(delta.vanished.len(), 1);
    assert!(delta.more);
}

/// **LES DISPARITIONS SONT BORNÉES**, et le plancher monte d'autant : un
/// curseur d'avant les oubliées est périmé, un curseur d'après est servi.
#[test]
fn les_disparitions_s_oublient_au_dela_de_la_borne() {
    let tous: Vec<(u32, u16)> = (1..=u32::try_from(VANISHED_MAX + 5).expect("tient"))
        .map(|uid| (uid, RIEN))
        .collect();
    let mut journal = Journal::initial(UV, DEPART, &tous);
    assert!(journal.reconcile(UV, 0, &[]));
    assert_eq!(journal.vanished.len(), VANISHED_MAX);
    assert_eq!(
        journal.floor,
        DEPART + 5,
        "les cinq plus anciennes sont oubliées"
    );
    assert_eq!(journal.since(DEPART, 50, 50), Err(Perime));
    assert!(journal.since(DEPART + 5, 50, 50).is_ok());
}

// ── LE FICHIER ──────────────────────────────────────────────────────────────

#[test]
fn un_journal_ecrit_se_relit_a_l_identique() {
    let mut journal = trois();
    assert!(journal.reconcile(UV, 0, &[(2, LU), (4, RIEN)]));
    let octets = encode_journal(&journal).expect("encodable");
    assert_eq!(decode_journal(&octets).expect("relisible"), journal);
    let vide = Journal::new(UV, DEPART);
    assert_eq!(
        decode_journal(&encode_journal(&vide).expect("encodable")).expect("relisible"),
        vide
    );
}

/// Écrit un journal BRUT, pour fabriquer ce que l'encodeur n'écrirait pas.
fn brut(modseq: u64, floor: u64, messages: &[(u32, u64)], disparus: &[(u32, u64)]) -> Vec<u8> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut ecrit = message.init_root::<journal::Builder<'_>>();
        ecrit.set_uid_validity(UV);
        ecrit.set_modseq(modseq);
        ecrit.set_floor(floor);
        let mut liste = ecrit
            .reborrow()
            .init_messages(u32::try_from(messages.len()).expect("tient"));
        for (rang, (uid, point)) in messages.iter().enumerate() {
            let mut case = liste.reborrow().get(u32::try_from(rang).expect("tient"));
            case.set_uid(*uid);
            case.set_modseq(*point);
        }
        let mut liste = ecrit.init_vanished(u32::try_from(disparus.len()).expect("tient"));
        for (rang, (uid, point)) in disparus.iter().enumerate() {
            let mut case = liste.reborrow().get(u32::try_from(rang).expect("tient"));
            case.set_uid(*uid);
            case.set_modseq(*point);
        }
    }
    capnp::serialize::write_message_to_words(&message)
}

/// **CE QU'UN JOURNAL TENU NE PEUT PAS ÊTRE EST REFUSÉ** — et le serveur en
/// recrée alors un, au prix d'une resynchronisation.
#[test]
fn ce_qu_un_journal_tenu_ne_peut_pas_etre_est_refuse() {
    // Le témoin passe : les refus qui suivent tiennent à leur seule faute.
    assert!(decode_journal(&brut(10, 5, &[(1, 5), (2, 7)], &[(3, 8)])).is_ok());
    for (quoi, octets) in [
        ("plancher au-dessus", brut(4, 5, &[], &[])),
        ("UID en désordre", brut(10, 5, &[(2, 6), (1, 7)], &[])),
        ("UID en double", brut(10, 5, &[(2, 6), (2, 7)], &[])),
        ("point sous le plancher", brut(10, 5, &[(1, 4)], &[])),
        ("point au-delà du dernier", brut(10, 5, &[(1, 11)], &[])),
        (
            "disparitions en désordre",
            brut(10, 5, &[], &[(1, 8), (2, 7)]),
        ),
        ("disparition au plancher", brut(10, 5, &[], &[(1, 5)])),
        ("disparition au-delà", brut(10, 5, &[], &[(1, 11)])),
    ] {
        assert!(decode_journal(&octets).is_err(), "{quoi} a été accepté");
    }
    assert!(decode_journal(b"ceci n'est pas un journal").is_err());
    assert!(decode_journal(&[]).is_err());
}

/// **TROP DE DISPARITIONS DANS UN FICHIER** : refusé, un journal tenu n'en
/// garde jamais autant.
#[test]
fn trop_de_disparitions_sont_refusees() {
    let disparus: Vec<(u32, u64)> = (1..=u64::try_from(VANISHED_MAX + 1).expect("tient"))
        .map(|rang| (u32::try_from(rang).expect("tient"), 5 + rang))
        .collect();
    let dernier = 5 + u64::try_from(VANISHED_MAX + 1).expect("tient");
    assert!(decode_journal(&brut(dernier, 5, &[], &disparus)).is_err());
}

/// **UN FICHIER CORROMPU NE FAIT JAMAIS PANIQUER** — et le balayage traverse
/// aussi le chemin nominal.
#[test]
fn un_journal_corrompu_ne_fait_jamais_paniquer() {
    let mut journal = trois();
    assert!(journal.reconcile(UV, 0, &[(2, LU)]));
    let sain = encode_journal(&journal).expect("encodable");
    let (mut refuses, mut acceptes) = (0_u32, 0_u32);
    for position in 0..sain.len() {
        for masque in [0xFF_u8, 0x01, 0x80] {
            let mut corrompu = sain.clone();
            corrompu[position] ^= masque;
            match decode_journal(&corrompu) {
                Ok(_) => acceptes += 1,
                Err(_) => refuses += 1,
            }
        }
    }
    assert!(refuses > 0 && acceptes > 0);
}

#[test]
fn les_types_se_comparent_et_se_deboguent() {
    let present = Present {
        uid: 1,
        flags: LU,
        modseq: 2,
    };
    let disparu = Disparu { uid: 1, modseq: 3 };
    assert_eq!(present, present.clone());
    assert_eq!(disparu, disparu.clone());
    assert_eq!(Perime, Perime.clone());
    let delta = Delta {
        changed: vec![1],
        vanished: Vec::new(),
        modseq: 2,
        more: false,
    };
    assert_eq!(delta.clone(), delta);
    for trace in [
        alloc::format!("{present:?}"),
        alloc::format!("{disparu:?}"),
        alloc::format!("{Perime:?}"),
        alloc::format!("{delta:?}"),
        alloc::format!("{:?}", trois()),
    ] {
        assert!(!trace.is_empty());
    }
}
