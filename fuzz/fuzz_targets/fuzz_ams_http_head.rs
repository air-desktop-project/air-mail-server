// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la liste de champs d'une requête HTTP**, telle qu'un décompresseur
//! HPACK ou QPACK la rend.
//!
//! # Pourquoi celle-ci
//!
//! C'est la frontière où s'arrête la contrebande de requête. Le décompresseur ne
//! juge rien — il rend les octets qu'on lui a donnés à comprimer —, et tout ce
//! qui décide qu'une liste est recevable vit dans `HeadBuilder`. Une liste
//! acceptée ici sera routée ; une liste acceptée à tort est une requête que
//! personne n'a envoyée.
//!
//! Les paires viennent d'`Arbitrary` plutôt que d'un flux d'octets : ce qu'on
//! éprouve est la RÈGLE, pas le découpage — le découpage a ses propres cibles.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelles que soient les paires.
//! 2. **UNE REQUÊTE ACCEPTÉE PORTE UNE AUTORITÉ NON VIDE.** Sans elle, un
//!    serveur qui en héberge plusieurs ne sait pas lequel on lui demande.
//! 3. **SA CIBLE COMMENCE PAR `/`, OU VAUT `*` POUR `OPTIONS`.** Une cible en
//!    forme absolue serait une requête de mandataire.
//! 4. **AUCUN CHAMP RETENU N'EST PROPRE À LA CONNEXION**, et tous ont un nom en
//!    minuscules. C'est la propriété qui ferme la contrebande : `transfer-encoding`
//!    ne doit jamais ressortir d'ici.
//! 5. **AUCUNE VALEUR RETENUE NE PORTE DE `CR`, DE `LF` NI DE `NUL`.** Un
//!    intermédiaire qui réécrirait la requête en HTTP/1.1 en ferait une coupure
//!    de ligne.
//! 6. **LE NOMBRE DE CHAMPS EST BORNÉ**, quoi qu'annonce la configuration.
//! 7. **`content-length` ACCEPTÉ SE RELIT PAREIL** : ce qu'on a lu est ce que la
//!    valeur dit, et non ce qu'un second analyseur y verrait.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_http::{
    FIELDS_MAX, HeadBuilder, Limits, Method, field_name_is_valid, field_value_is_valid,
    is_connection_specific,
};

/// Ce qu'on soumet : des paires, dans l'ordre.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Les champs, nom et valeur.
    champs: Vec<(&'a [u8], &'a [u8])>,
}

fuzz_target!(|entree: Entree<'_>| {
    let bornes = Limits::DEFAULT;
    let mut accumule = HeadBuilder::new(&bornes);
    for (nom, valeur) in &entree.champs {
        // UNE FAUTE ARRÊTE LA LECTURE, comme l'appelant le fera : continuer
        // après un refus éprouverait un état que personne n'atteint.
        if accumule.field(nom, valeur).is_err() {
            return;
        }
    }
    let Ok(requete) = accumule.finish() else {
        return;
    };

    // PROPRIÉTÉ 2.
    assert!(
        !requete.authority().is_empty(),
        "une requête acceptée sans autorité"
    );

    // PROPRIÉTÉ 3.
    let cible = requete.path();
    assert!(
        cible.first() == Some(&b'/') || (cible == b"*" && requete.method() == Method::Options),
        "une cible qu'on ne saurait pas router : {cible:?}"
    );

    // PROPRIÉTÉ 6.
    let champs = requete.fields();
    assert!(
        champs.len() <= bornes.max_fields.min(FIELDS_MAX),
        "{} champs retenus",
        champs.len()
    );

    for (nom, valeur) in champs {
        // PROPRIÉTÉ 4.
        assert!(field_name_is_valid(nom), "un nom retenu est mal formé");
        assert!(
            !is_connection_specific(nom),
            "un champ propre à la connexion est ressorti : {nom:?}"
        );
        // PROPRIÉTÉ 5.
        assert!(
            field_value_is_valid(valeur),
            "une valeur retenue est mal formée"
        );
        assert!(
            !valeur
                .iter()
                .any(|octet| matches!(*octet, 0x00 | b'\r' | b'\n')),
            "un octet de structure a traversé"
        );
    }

    // PROPRIÉTÉ 7.
    if let Some(longueur) = requete.content_length() {
        let ecrit = requete
            .field(b"content-length")
            .expect("une longueur lue vient d'un champ");
        let relu = core::str::from_utf8(ecrit)
            .ok()
            .and_then(|texte| texte.parse::<u64>().ok())
            .expect("une longueur acceptée est un nombre");
        assert_eq!(relu, longueur, "la longueur lue n'est pas celle qui est là");
    }
});
