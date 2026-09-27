// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le client HTTP/2**, face à ce qu'un service de push renverrait.
//!
//! Les octets viennent d'un serveur étranger — Apple, Google, ou l'URL qu'un
//! abonné a donnée. C'est la seule entrée de ce client, et elle n'est pas de
//! notre ressort.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **CE QUI EST CONSOMMÉ TIENT DANS CE QUI EST DONNÉ**, et ce qui est écrit
//!    dans la sortie.
//! 3. **LE CORPS DE LA RÉPONSE TIENT DANS SON TAMPON.**
//! 4. **UNE RÉPONSE FINIE A UN STATUT FINAL** : de 200 à 599 (§15 de RFC
//!    9110). Le fuzz a trouvé qu'un `:status` à `0` passait pour une réponse.
//! 5. **LE DÉCOUPAGE NE CHANGE RIEN** : les mêmes octets, livrés en deux
//!    morceaux, mènent au même verdict.

#![no_main]

use libfuzzer_sys::fuzz_target;

use ams_proto_h2::{Client, Request, START_OCTETS_MAX};

const REQUETE: Request<'static> = Request {
    method: b"POST",
    authority: b"push.example.com",
    path: b"/p",
    fields: &[(b"ttl", b"60")],
    body: b"corps",
};

/// Joue les octets, en morceaux de `taille`, et rend (fini, statut, corps).
fn jouer(octets: &[u8], taille: usize) -> Option<(bool, Option<u16>, Vec<u8>)> {
    let mut client = Box::new(Client::new());
    let mut sortie = vec![0_u8; START_OCTETS_MAX];
    client
        .start(&REQUETE, &mut sortie)
        .expect("le début s'écrit toujours");
    let mut reponse = vec![0_u8; 256];
    let mut sortie = vec![0_u8; 128 * 1024];
    let mut recu: Vec<u8> = Vec::new();
    for morceau in octets.chunks(taille.max(1)) {
        recu.extend_from_slice(morceau);
        let progres = client
            .receive(&recu, REQUETE.body, &mut sortie, &mut reponse)
            .ok()?;
        // PROPRIÉTÉ 2.
        assert!(progres.consumed <= recu.len());
        assert!(progres.written <= sortie.len());
        recu.drain(..progres.consumed);
        // PROPRIÉTÉ 3.
        assert!(client.body_len() <= reponse.len());
        if progres.done {
            // PROPRIÉTÉ 4.
            let statut = client.status().expect("une réponse finie a un statut");
            assert!(
                (200..600).contains(&statut),
                "une réponse finale est de 200 à 599"
            );
            return Some((true, Some(statut), reponse[..client.body_len()].to_vec()));
        }
    }
    Some((
        false,
        client.status(),
        reponse[..client.body_len()].to_vec(),
    ))
}

fuzz_target!(|octets: &[u8]| {
    let entier = jouer(octets, octets.len());
    // PROPRIÉTÉ 5 : livrés en deux fois, les mêmes octets disent la même chose
    // quand la réponse s'est finie d'un coup.
    if let Some((true, statut, corps)) = entier {
        let moitie = jouer(octets, octets.len() / 2);
        assert_eq!(
            moitie,
            Some((true, statut, corps)),
            "le découpage a changé le verdict"
        );
    }
});
