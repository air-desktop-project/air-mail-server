// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le rapport de non-remise** — ce qu'un serveur inconnu a répondu
//! finit dans la boîte d'un de nos comptes.
//!
//! # L'ENTRÉE HOSTILE EST LE DIAGNOSTIC
//!
//! Un `Diagnostic-Code` porte le texte de refus d'un serveur qu'on n'a pas
//! choisi — c'est le destinataire qui a désigné son `MX`. Un `CRLF` glissé
//! dedans écrirait des champs de statut à notre place, dans un message que nous
//! composons, que nous remettons nous-mêmes, et que le client de notre
//! utilisateur lira comme un rapport officiel. `Action: delivered` inséré là
//! ferait croire à une remise qui n'a pas eu lieu.
//!
//! Les en-têtes du message perdu viennent, eux, du déposant.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelles que soient les valeurs.
//! 2. **RIEN N'EST ÉCRIT AU-DELÀ DU TAMPON** : ce qui borde ne bouge pas.
//! 3. **TOUT CE QUI SORT EST ÉMETTABLE** : de l'ASCII imprimable, des
//!    tabulations, et des fins de ligne COMPLÈTES. Un `CR` ou un `LF` isolé est
//!    la faille de contrebande SMTP de 2023, dans un message que nous composons.
//! 4. **AUCUNE VALEUR NE PEUT AJOUTER UN CHAMP DE STATUT** : autant de
//!    `Final-Recipient` et d'`Action` que d'échecs donnés, pas un de plus. C'est
//!    la propriété qui vise le diagnostic du pair — un `Action: delivered`
//!    glissé là ferait croire à une remise qui n'a pas eu lieu.
//! 5. **LE CHEMIN DE RETOUR EST NUL** — un rapport ne rebondit pas — et le
//!    message se ferme sur son délimiteur de clôture.
//!
//! # LA PROPRIÉTÉ QUI N'EN ÉTAIT PAS UNE
//!
//! On a d'abord exigé que le délimiteur ne figure QUE là où on le pose. Le fuzz
//! a montré que c'est faux, et que le code a raison : avec un délimiteur d'un
//! seul caractère, il se retrouve dans `Content-Type`, dans `Return-Path`, dans
//! n'importe quel mot qu'on écrit. Ce que `write_bounce` garantit est plus
//! étroit — le délimiteur est absent des DEUX parties libres — et c'est éprouvé
//! là où cela se prouve, dans les essais unitaires.
//!
//! Pour la même raison, la propriété 4 ne s'exige que lorsque les parties libres
//! ne portent pas elles-mêmes l'aiguille : ce qu'un déposant écrit dans ses
//! propres en-têtes n'est pas une injection, c'est son texte.

#![no_main]

use ams_mime::{Action, Bounce, Failure, bounce_max, write_bounce};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Ce qui borde le tampon, pour voir si l'on écrit au-delà.
const GARDE: u8 = 0xa5;

#[derive(Debug, Arbitrary)]
struct Echec {
    destinataire: Vec<u8>,
    statut: Vec<u8>,
    diagnostic: Vec<u8>,
    /// L'adresse d'origine que le déposant a écrite (RFC 3461 §4.2).
    ///
    /// **ELLE VIENT DE LUI**, et ressort dans un en-tête que nous composons :
    /// c'est une entrée hostile au même titre que le diagnostic.
    origine: Vec<u8>,
    /// Ce que ce serveur a fait du message (RFC 3464 §2.3.3).
    ///
    /// Le retard porte SON ÉCHÉANCE : `Will-Retry-Until` (§2.3.9) n'a de sens
    /// que là, et c'est le type qui l'exige. Une date arbitraire y passe, jusqu'à
    /// la fin de l'époque — l'écriture d'une date ne doit pas déborder pour un
    /// message qu'on aurait déposé loin dans l'avenir.
    quoi: Sort,
}

/// Ce que le serveur a fait du message, tiré au sort.
#[derive(Debug, Arbitrary)]
enum Sort {
    Echoue,
    Remis,
    Relaye,
    Retarde { jusqu_a: u64 },
}

impl Sort {
    fn en_action(&self) -> Action {
        match *self {
            Self::Echoue => Action::Failed,
            Self::Remis => Action::Delivered,
            Self::Relaye => Action::Relayed,
            Self::Retarde { jusqu_a } => Action::Delayed {
                retry_until: jusqu_a,
            },
        }
    }
}

#[derive(Debug, Arbitrary)]
struct Entree {
    de: Vec<u8>,
    a: Vec<u8>,
    mta: Vec<u8>,
    sujet: Vec<u8>,
    identifiant: Vec<u8>,
    date: u64,
    arrivee: u64,
    delimiteur: Vec<u8>,
    texte: Vec<u8>,
    entetes: Vec<u8>,
    /// L'identifiant d'enveloppe du déposant (RFC 3461 §4.4), lui aussi.
    envid: Vec<u8>,
    echecs: Vec<Echec>,
}

fuzz_target!(|entree: Entree| {
    let echecs: Vec<Failure<'_>> = entree
        .echecs
        .iter()
        .map(|un| Failure {
            recipient: &un.destinataire,
            status: &un.statut,
            diagnostic: &un.diagnostic,
            action: un.quoi.en_action(),
            original: &un.origine,
        })
        .collect();
    let rapport = Bounce {
        from: &entree.de,
        to: &entree.a,
        reporting_mta: &entree.mta,
        subject: &entree.sujet,
        message_id: &entree.identifiant,
        date: entree.date,
        arrival: entree.arrivee,
        envelope_id: &entree.envid,
        boundary: &entree.delimiteur,
        text: &entree.texte,
        failures: &echecs,
        original_headers: &entree.entetes,
    };

    // Le tampon annoncé, plus une bordure qu'on relira.
    let taille = bounce_max(&rapport);
    let mut tampon = vec![GARDE; taille.saturating_add(64)];
    let issue = {
        let place = &mut tampon[..taille];
        write_bounce(place, &rapport).map(<[u8]>::len)
    };

    // 2. RIEN N'EST ÉCRIT AU-DELÀ.
    assert!(
        tampon[taille..].iter().all(|octet| *octet == GARDE),
        "écrit au-delà du tampon annoncé"
    );

    let Ok(combien) = issue else {
        return;
    };
    let ecrit = &tampon[..combien];

    // 5. LE CHEMIN DE RETOUR EST NUL, ET LE MESSAGE SE FERME.
    assert!(
        ecrit.starts_with(b"Return-Path: <>\r\n"),
        "le rebond rebondirait"
    );
    assert!(ecrit.ends_with(b"--\r\n"), "le message ne se ferme pas");

    // 3. TOUT CE QUI SORT EST ÉMETTABLE.
    assert!(
        emettable(ecrit),
        "un octet qu'on ne peut pas mettre sur le fil"
    );

    // 4. AUCUNE VALEUR N'AJOUTE UN CHAMP DE STATUT, NI UN `Original-Recipient`.
    //
    // Les deux parties LIBRES — le texte et les en-têtes d'origine — ont le
    // droit de porter n'importe quoi, y compris ce qu'on cherche. On ne compte
    // donc que lorsqu'elles ne le portent pas : sinon on éprouverait la liberté
    // du déposant, pas la nôtre.
    //
    // `Action:` se compte SANS son mot : depuis RFC 3461, un rapport peut dire
    // `delivered` aussi bien que `failed`, et compter le mot ferait dépendre la
    // propriété de ce que le déposant avait demandé.
    for aiguille in [&b"\r\nFinal-Recipient: rfc822; "[..], b"\r\nAction: "] {
        let libre = compter(&entree.texte, aiguille) > 0 || compter(&entree.entetes, aiguille) > 0;
        if !libre {
            assert_eq!(
                compter(ecrit, aiguille),
                echecs.len(),
                "un champ de statut est apparu ou a disparu"
            );
        }
    }
});

/// Ces octets peuvent-ils passer sur le fil tels quels ?
///
/// De l'ASCII imprimable, des tabulations, et des fins de ligne COMPLÈTES.
fn emettable(octets: &[u8]) -> bool {
    let mut attend_lf = false;
    for octet in octets {
        if attend_lf {
            if *octet != b'\n' {
                return false;
            }
            attend_lf = false;
            continue;
        }
        match *octet {
            b'\r' => attend_lf = true,
            b'\n' => return false,
            b'\t' => {}
            autre if autre.is_ascii_graphic() || autre == b' ' => {}
            _ => return false,
        }
    }
    !attend_lf
}

/// Combien de fois `aiguille` figure dans `botte`, sans recouvrement.
fn compter(botte: &[u8], aiguille: &[u8]) -> usize {
    if aiguille.is_empty() || aiguille.len() > botte.len() {
        return 0;
    }
    let mut combien = 0_usize;
    let mut rang = 0_usize;
    while let Some(fenetre) = botte.get(rang..rang.saturating_add(aiguille.len())) {
        if fenetre == aiguille {
            combien = combien.saturating_add(1);
            rang = rang.saturating_add(aiguille.len());
        } else {
            rang = rang.saturating_add(1);
        }
    }
    combien
}
