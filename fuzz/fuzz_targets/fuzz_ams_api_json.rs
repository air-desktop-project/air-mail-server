// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les représentations JSON de l'API** — l'écriture et la lecture.
//!
//! # Pourquoi celle-ci
//!
//! C'est la seule cible de ce dépôt où l'écriture et la lecture d'un même format
//! se font face. Cela permet une propriété qu'aucune des deux ne pourrait
//! prouver seule : **ce que l'écrivain produit, le lecteur le relit à
//! l'identique.** Si l'un échappe mal, ou si l'autre décode mal, l'aller-retour
//! s'en aperçoit — et il s'en aperçoit sur des chaînes qu'on n'a pas choisies.
//!
//! L'échappement est l'enjeu : presque tout ce que cette API rend vient
//! d'ailleurs, et un guillemet non échappé ferme la chaîne. Ce qui suit devient
//! alors de la structure, dans un document que le client croira de nous.
//!
//! Et la lecture est la surface la plus dangereuse de la crate : elle lit ce
//! qu'un inconnu a envoyé, et un analyseur JSON est l'endroit classique où l'on
//! trouve un débordement de pile sur des crochets imbriqués.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, ni à l'écriture ni à la lecture, quels que soient les
//!    octets.
//! 2. **CE QU'ON ÉCRIT SE RELIT À L'IDENTIQUE**, chaîne par chaîne et nombre par
//!    nombre. C'est la propriété qui vaut pour les deux moitiés à la fois.
//! 3. **RIEN DE CE QU'ON ÉCRIT NE PORTE UN OCTET DE CONTRÔLE NU**, ni un `<`, ni
//!    un `>`, ni un `&`. Un document JSON finit parfois dans une page HTML.
//! 4. **UN DOCUMENT ACCEPTÉ EST ÉQUILIBRÉ ET FINI** : autant de fermetures que
//!    d'ouvertures, une seule valeur racine, et jamais plus profond que la borne.
//! 5. **AUCUNE CLÉ N'EST RÉPÉTÉE DANS UN OBJET ACCEPTÉ**, et aucune ne porte
//!    d'échappement.
//! 6. **CHAQUE TRONCATURE D'UN DOCUMENT ACCEPTÉ SE REFUSE** : un corps coupé en
//!    route ne doit jamais se lire comme un corps complet mais plus court.
//! 7. **LE LECTEUR AVANCE TOUJOURS** : un corps de `n` octets rend au plus `n`
//!    événements, donc la boucle de l'appelant se termine.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_api::{BODY_DEPTH_MAX, DEPTH_MAX, Event, Json, Reader};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Des octets bruts, tels qu'un client les enverrait.
    corps: &'a [u8],
    /// Des chaînes à écrire puis relire.
    textes: [&'a str; 4],
    /// Des nombres à écrire puis relire.
    nombres: [u64; 4],
    /// Des noms de champ.
    clefs: [&'a str; 2],
}

/// Combien d'événements au plus on lit d'un corps.
const EVENEMENTS_MAX: usize = 100_000;

fuzz_target!(|entree: Entree| {
    lire(entree.corps);

    // PROPRIÉTÉS 2 et 3 : l'aller-retour.
    let mut place = [0_u8; 65_536];
    let mut json = Json::new(&mut place);
    let ecrit = (|| {
        json.begin_object()?;
        json.key("t")?;
        json.begin_array()?;
        for texte in entree.textes {
            json.string(texte)?;
        }
        json.end_array()?;
        json.key("n")?;
        json.begin_array()?;
        for nombre in entree.nombres {
            json.number(nombre)?;
        }
        json.end_array()?;
        json.end_object()?;
        Ok::<(), ams_api::Error>(())
    })();
    if ecrit.is_err() {
        return;
    }
    let Ok(document) = json.finish() else {
        return;
    };
    let document = document.to_vec();

    // PROPRIÉTÉ 3 : rien de nu là-dedans.
    assert!(
        !document
            .iter()
            .any(|octet| *octet < 0x20 || matches!(octet, b'<' | b'>' | b'&')),
        "un octet qui aurait dû être échappé est écrit tel quel"
    );

    // PROPRIÉTÉ 2 : le lecteur retrouve exactement ce qu'on a écrit.
    let mut lecteur = Reader::new(&document);
    let mut textes = entree.textes.iter();
    let mut nombres = entree.nombres.iter();
    let mut tampon = [0_u8; 65_536];
    let mut tours = 0_usize;
    while let Ok(Some(evenement)) = lecteur.read() {
        tours = tours.saturating_add(1);
        assert!(tours < EVENEMENTS_MAX, "le lecteur n'avance pas");
        match evenement {
            Event::Text(texte) => {
                let attendu = textes.next().expect("plus de chaînes que d'écrites");
                let lu = match texte.as_plain() {
                    Some(clair) => clair,
                    None => texte.unescape(&mut tampon).expect("assez de place"),
                };
                assert_eq!(lu, *attendu, "une chaîne a changé à l'aller-retour");
            }
            Event::Number(nombre) => {
                let attendu = nombres.next().expect("plus de nombres que d'écrits");
                assert_eq!(
                    nombre.as_u64(),
                    Some(*attendu),
                    "un nombre a changé à l'aller-retour"
                );
            }
            _ => {}
        }
    }
    assert!(
        textes.next().is_none() && nombres.next().is_none(),
        "le lecteur n'a pas tout rendu"
    );

    // PROPRIÉTÉ 6 : chaque troncature se refuse.
    for coupe in 0..document.len() {
        let tronque = document.get(..coupe).unwrap_or_default();
        assert!(
            !accepte(tronque),
            "la troncature à {coupe} octets s'est lue comme un document"
        );
    }

    // Une clé écrite deux fois se relit-elle ? Elle ne doit pas.
    let mut place = [0_u8; 4_096];
    let mut json = Json::new(&mut place);
    let double = (|| {
        json.begin_object()?;
        json.field_u64(entree.clefs[0], 1)?;
        json.field_u64(entree.clefs[1], 2)?;
        json.end_object()?;
        Ok::<(), ams_api::Error>(())
    })();
    if double.is_ok() {
        if let Ok(ecrit) = json.finish() {
            // **UN OBJET À DEUX CLÉS IDENTIQUES NE SE RELIT PAS**, et c'est
            // exactement ce que le lecteur promet de refuser.
            //
            // L'inverse ne se dit pas : deux clés différentes peuvent tout de
            // même se voir refuser, si l'écrivain a dû les échapper — le lecteur
            // n'accepte aucune clé échappée.
            if entree.clefs[0] == entree.clefs[1] {
                assert!(!accepte(ecrit), "deux clés identiques se sont relues");
            }
        }
    }
});

/// Lit un corps jusqu'au bout, et vérifie ce que la lecture promet.
fn lire(corps: &[u8]) {
    let mut lecteur = Reader::new(corps);
    let mut tours = 0_usize;
    let mut profondeur = 0_i64;
    let mut ouvertures = 0_usize;
    let mut fermetures = 0_usize;
    loop {
        match lecteur.read() {
            Err(_) => return,
            Ok(None) => break,
            Ok(Some(evenement)) => {
                tours = tours.saturating_add(1);
                // PROPRIÉTÉ 7 : un corps de `n` octets rend au plus `n`
                // événements — sans quoi la boucle de l'appelant ne finirait pas.
                assert!(
                    tours <= corps.len(),
                    "{tours} événements pour {} octets",
                    corps.len()
                );
                match evenement {
                    Event::ObjectStart | Event::ArrayStart => {
                        profondeur = profondeur.saturating_add(1);
                        ouvertures = ouvertures.saturating_add(1);
                    }
                    Event::ObjectEnd | Event::ArrayEnd => {
                        profondeur = profondeur.saturating_sub(1);
                        fermetures = fermetures.saturating_add(1);
                    }
                    // **AUCUNE CLÉ N'EST ÉCHAPPÉE** dans un corps accepté.
                    Event::Key(clef) => {
                        assert!(clef.as_plain().is_some(), "une clé échappée est passée");
                    }
                    _ => {}
                }
                // PROPRIÉTÉ 4 : jamais plus profond que la borne, jamais négatif.
                assert!(
                    (0..=i64::try_from(BODY_DEPTH_MAX).unwrap_or(0)).contains(&profondeur),
                    "une profondeur impossible : {profondeur}"
                );
            }
        }
    }
    // PROPRIÉTÉ 4 : un document accepté est équilibré.
    assert_eq!(
        ouvertures, fermetures,
        "un document accepté n'est pas équilibré"
    );
    assert_eq!(profondeur, 0, "un document accepté reste ouvert");
    // La borne d'écriture et celle de lecture sont la même idée.
    assert!(BODY_DEPTH_MAX == DEPTH_MAX, "les deux bornes ont divergé");
}

/// Ce corps se lit-il en entier ?
fn accepte(corps: &[u8]) -> bool {
    let mut lecteur = Reader::new(corps);
    let mut tours = 0_usize;
    loop {
        match lecteur.read() {
            Err(_) => return false,
            Ok(None) => return true,
            Ok(Some(_)) => {
                tours = tours.saturating_add(1);
                if tours > EVENEMENTS_MAX {
                    return false;
                }
            }
        }
    }
}
