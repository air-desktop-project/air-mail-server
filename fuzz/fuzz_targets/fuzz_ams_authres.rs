// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : l'en-tête `Authentication-Results` (RFC 8601)** — le seul champ que
//! ce serveur écrit EN TÊTE du message d'un pair.
//!
//! # L'ENTRÉE HOSTILE EST LE DOMAINE DU PAIR
//!
//! Tout ce qui entre dans ce champ vient d'en face : le domaine du `From:`, le
//! `d=` et le `s=` de chaque signature DKIM, le domaine que SPF a jugé. Un
//! `CRLF` glissé dans l'un d'eux écrirait un en-tête à notre place, dans un
//! message que nous remettons nous-mêmes — c'est-à-dire un champ que le client
//! du destinataire lira comme venant de nous. Un `;` y couperait le champ en
//! deux résultats, dont l'un serait celui que le pair a choisi.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelles que soient les valeurs.
//! 2. **RIEN N'EST ÉCRIT AU-DELÀ DU TAMPON** : ce qui borde ne bouge pas.
//! 3. **TOUT CE QUI SORT EST ÉMETTABLE** : de l'ASCII imprimable, des
//!    tabulations, et des fins de ligne COMPLÈTES. Un `CR` ou un `LF` isolé est
//!    la faille de contrebande de 2023, ici dans un en-tête que nous composons.
//! 4. **IL N'Y A QU'UN CHAMP** : une seule ligne qui ne commence pas par un
//!    blanc, et c'est la première. Toute autre serait un en-tête que le pair
//!    aurait écrit à travers nous.
//! 5. **LE REMPLISSAGE OCCUPE EXACTEMENT LA PLACE**, ni plus ni moins : un octet
//!    de trop écraserait le premier en-tête du pair, un de moins laisserait un
//!    trou au milieu du message.
//! 6. **AUCUNE VALEUR N'AJOUTE UN RÉSULTAT** : autant de `;` que de résultats
//!    annoncés, pas un de plus. Sur le champ NU seulement — le rembourrage
//!    abandonne les signatures qui ne tiennent pas, et leur nombre ne se déduit
//!    pas de l'entrée.

#![no_main]

use ams_mime::{
    Authentication, DkimResult, DkimSeen, DmarcResult, SpfIdentity, SpfResult, authres_max,
    write_authres, write_authres_padded,
};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Ce qui borde le tampon, pour voir si l'on écrit au-delà.
const GARDE: u8 = 0xa5;

#[derive(Debug, Arbitrary)]
struct Signature {
    resultat: u8,
    domaine: Vec<u8>,
    selecteur: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
struct Entree {
    serveur: Vec<u8>,
    spf: Option<(u8, bool, Vec<u8>)>,
    dkim: Vec<Signature>,
    dmarc: Option<(u8, Vec<u8>)>,
    place: u16,
}

/// Un résultat SPF, depuis un octet quelconque.
fn spf(brut: u8) -> SpfResult {
    match brut % 7 {
        0 => SpfResult::None,
        1 => SpfResult::Neutral,
        2 => SpfResult::Pass,
        3 => SpfResult::Fail,
        4 => SpfResult::SoftFail,
        5 => SpfResult::TempError,
        _ => SpfResult::PermError,
    }
}

/// Un résultat DKIM, depuis un octet quelconque.
fn dkim(brut: u8) -> DkimResult {
    match brut % 7 {
        0 => DkimResult::None,
        1 => DkimResult::Pass,
        2 => DkimResult::Fail,
        3 => DkimResult::Policy,
        4 => DkimResult::Neutral,
        5 => DkimResult::TempError,
        _ => DkimResult::PermError,
    }
}

/// Un résultat DMARC, depuis un octet quelconque.
fn dmarc(brut: u8) -> DmarcResult {
    match brut % 5 {
        0 => DmarcResult::None,
        1 => DmarcResult::Pass,
        2 => DmarcResult::Fail,
        3 => DmarcResult::TempError,
        _ => DmarcResult::PermError,
    }
}

fuzz_target!(|entree: Entree| {
    let signatures: Vec<DkimSeen<'_>> = entree
        .dkim
        .iter()
        .map(|une| DkimSeen {
            result: dkim(une.resultat),
            domain: &une.domaine,
            selector: &une.selecteur,
        })
        .collect();
    let authentification = Authentication {
        serv_id: &entree.serveur,
        spf: entree.spf.as_ref().map(|(brut, helo, domaine)| {
            (
                spf(*brut),
                if *helo {
                    SpfIdentity::Helo
                } else {
                    SpfIdentity::MailFrom
                },
                &domaine[..],
            )
        }),
        dkim: &signatures,
        dmarc: entree
            .dmarc
            .as_ref()
            .map(|(brut, domaine)| (dmarc(*brut), &domaine[..])),
    };

    // ── LE CHAMP NU, DANS LE TAMPON QU'IL ANNONCE ───────────────────────────
    let taille = authres_max(&authentification);
    let mut tampon = vec![GARDE; taille.saturating_add(64)];
    let issue = {
        let place = &mut tampon[..taille];
        write_authres(place, &authentification).map(<[u8]>::len)
    };

    // 2. RIEN N'EST ÉCRIT AU-DELÀ.
    assert!(
        tampon[taille..].iter().all(|octet| *octet == GARDE),
        "écrit au-delà de la taille annoncée"
    );

    if let Ok(combien) = issue {
        let ecrit = &tampon[..combien];
        let annonces = signatures.len()
            + usize::from(entree.spf.is_some())
            + usize::from(entree.dmarc.is_some());
        verifier(ecrit, (annonces > 0).then_some(annonces));
    }

    // ── LE CHAMP REMBOURRÉ, DANS UNE PLACE FIXE ─────────────────────────────
    //
    // C'est la forme que la remise emploie : la place est réservée avant que le
    // message n'arrive, et le champ doit l'occuper EXACTEMENT.
    let place = usize::from(entree.place % 2048);
    let mut fixe = vec![GARDE; place.saturating_add(64)];
    let issue = {
        let dedans = &mut fixe[..place];
        write_authres_padded(dedans, &authentification).map(<[u8]>::len)
    };
    assert!(
        fixe[place..].iter().all(|octet| *octet == GARDE),
        "le rembourrage écrit au-delà de la place réservée"
    );
    let Ok(combien) = issue else {
        return;
    };

    // 5. LE REMPLISSAGE OCCUPE EXACTEMENT LA PLACE.
    assert_eq!(combien, place, "la place réservée n'est pas remplie");
    let ecrit = &fixe[..combien];
    assert!(ecrit.ends_with(b"\r\n"), "le champ ne se termine pas");
    // **LE COMPTE DES RÉSULTATS NE S'EXIGE PAS ICI**, et le fuzz l'a rappelé :
    // le rembourrage abandonne les signatures qui ne tiennent pas dans la place
    // réservée, et leur nombre n'est pas prévisible depuis l'entrée. La
    // propriété 6 s'éprouve donc sur le champ nu, plus haut, où rien n'est
    // abandonné.
    verifier(ecrit, None);
});

/// Les propriétés que les deux formes partagent.
fn verifier(ecrit: &[u8], annonces: Option<usize>) {
    // 3. TOUT CE QUI SORT EST ÉMETTABLE.
    assert!(
        emettable(ecrit),
        "un octet qu'on ne peut pas mettre sur le fil"
    );

    // 4. IL N'Y A QU'UN CHAMP.
    for (rang, ligne) in ecrit.split(|octet| *octet == b'\n').enumerate() {
        let ligne = ligne.strip_suffix(b"\r").unwrap_or(ligne);
        if ligne.is_empty() {
            continue;
        }
        assert!(
            rang == 0 || matches!(ligne.first(), Some(b' ' | b'\t')),
            "une seconde ligne d'en-tête est apparue"
        );
    }
    assert!(
        ecrit.starts_with(b"Authentication-Results: "),
        "le champ n'est pas celui qu'on annonce"
    );

    // 6. AUCUNE VALEUR N'AJOUTE UN RÉSULTAT.
    //
    // Un `;` sépare l'identifiant du serveur du premier résultat, puis chaque
    // résultat du suivant : il y en a donc exactement autant que de résultats.
    if let Some(annonces) = annonces {
        assert_eq!(
            ecrit.iter().filter(|octet| **octet == b';').count(),
            annonces,
            "un résultat est apparu ou a disparu"
        );
    }
}

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
