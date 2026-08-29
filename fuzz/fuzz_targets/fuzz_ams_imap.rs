// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le découpage d'une commande IMAP**, et son tag.
//!
//! # IMAP n'est pas un protocole de lignes
//!
//! Une commande peut porter un littéral — `{42}` puis quarante-deux octets
//! bruts, `CRLF` compris — et continuer après. Chercher le premier `CRLF` pour
//! découper une commande IMAP, c'est offrir à un client de faire lire n'importe
//! quoi comme une commande. C'est **avant toute authentification** que cette
//! surface est exposée.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UNE COMMANDE COMPLÈTE TIENT DANS CE QU'ON A DONNÉ** : la longueur
//!    rendue ne dépasse jamais le tampon, et elle se termine par un `CRLF`.
//! 3. **LE DÉCOUPAGE NE DÉPEND PAS DE L'ARRIVÉE DES OCTETS** : couper le flux
//!    n'importe où donne la même commande. Sans cela, un client choisirait où
//!    l'on découpe rien qu'en fragmentant ses paquets. On conduit les deux
//!    lecteurs jusqu'à leur terme avant de les comparer — une demande de
//!    continuation est un ÉVÉNEMENT, pas un état, et deux lecteurs qui n'en
//!    sont pas au même instant de la conversation ne se comparent pas.
//! 4. **Un tag accepté est recopiable dans une réponse** : il ne porte aucun
//!    octet qui pourrait en écrire une seconde.
//! 5. **Une réponse encodée tient sur une ligne**, et une seule.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_imap::{
    CommandReader, Error, Limits, Line, Need, Status, encode_continuation, encode_tagged,
    encode_untagged,
};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Ce que le client envoie, bout à bout.
    flux: &'a [u8],
    /// Où le couper, pour éprouver l'indépendance au découpage.
    coupure: u16,
    /// Un texte de réponse — souvent un nom de boîte, donc du client.
    texte: &'a [u8],
}

/// Conduit un lecteur jusqu'à son terme, en lui servant d'abord un préfixe.
///
/// Les demandes de continuation sont consommées : elles ne concluent rien.
fn conduire(flux: &[u8], coupure: usize, bornes: &Limits) -> Result<Need, Error> {
    let mut lecteur = CommandReader::new();
    let (avant, _) = flux.split_at(coupure);
    let mut issue = lecteur.poll(avant, bornes);
    // Au plus un tour par littéral possible, plus un.
    for _ in 0..=bornes.max_literals {
        if !matches!(issue, Ok(Need::Continuation)) {
            break;
        }
        issue = lecteur.poll(avant, bornes);
    }
    if !matches!(issue, Ok(Need::Complete(_)) | Err(_)) {
        issue = lecteur.poll(flux, bornes);
        for _ in 0..=bornes.max_literals {
            if !matches!(issue, Ok(Need::Continuation)) {
                break;
            }
            issue = lecteur.poll(flux, bornes);
        }
    }
    issue
}

fuzz_target!(|entree: Entree<'_>| {
    let bornes = Limits::DEFAULT;

    // ── Le découpage, d'un seul tenant ──────────────────────────────────────
    let mut lecteur = CommandReader::new();
    let entier = lecteur.poll(entree.flux, &bornes);

    if let Ok(Need::Complete(longueur)) = entier {
        // PROPRIÉTÉ 2 : ce qui est rendu tient dans ce qu'on a donné.
        assert!(longueur <= entree.flux.len());
        let commande = &entree.flux[..longueur];
        assert!(
            commande.ends_with(b"\r\n"),
            "une commande complète se termine par un CRLF"
        );

        // PROPRIÉTÉ 4 : un tag accepté se recopie sans danger.
        if let Ok(lue) = Line::parse(commande, &bornes) {
            let tag = lue.tag.as_bytes();
            assert!(!tag.is_empty() && tag.len() <= bornes.max_tag_octets);
            assert!(
                tag.iter().all(|octet| octet.is_ascii_graphic()
                    && !matches!(
                        *octet,
                        b'(' | b')' | b'{' | b'%' | b'*' | b'"' | b'\\' | b'+'
                    )),
                "un tag accepté porte un octet qu'on ne peut pas recopier"
            );
            let mut sortie = vec![0_u8; 16384];
            if let Ok(reponse) = encode_tagged(&mut sortie, lue.tag, Status::Ok, b"done", &bornes) {
                // PROPRIÉTÉ 5 : une réponse, une ligne.
                assert!(reponse.ends_with(b"\r\n"));
                assert_eq!(
                    reponse.windows(2).filter(|f| *f == b"\r\n").count(),
                    1,
                    "une réponse encodée porte plus d'une fin de ligne"
                );
            }
        }
    }

    // ── PROPRIÉTÉ 3 : le même flux, coupé en deux ───────────────────────────
    //
    // `Continuation` est un ÉVÉNEMENT, pas un état : il se dit une fois par
    // littéral synchronisant, et le lecteur qui l'a déjà dit ne le redit pas.
    // Comparer deux lecteurs sur un seul appel comparerait donc des instants
    // différents de la même conversation. On les conduit chacun jusqu'à leur
    // terme, et c'est là qu'ils doivent se rejoindre.
    let coupure = usize::from(entree.coupure).min(entree.flux.len());
    assert_eq!(
        conduire(entree.flux, coupure, &bornes),
        conduire(entree.flux, entree.flux.len(), &bornes),
        "le découpage a changé la conclusion"
    );

    // ── Les réponses, dont le texte vient d'ailleurs ────────────────────────
    let mut sortie = vec![0_u8; 32768];
    for forme in [0_u8, 1] {
        let encodee = if forme == 0 {
            encode_untagged(&mut sortie, entree.texte, &bornes)
        } else {
            encode_continuation(&mut sortie, entree.texte, &bornes)
        };
        let Ok(ligne) = encodee else { continue };
        assert!(ligne.ends_with(b"\r\n"));
        assert_eq!(
            ligne.windows(2).filter(|f| *f == b"\r\n").count(),
            1,
            "un texte a écrit une réponse de plus"
        );
    }
});
