// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la part de clé du pair, des DEUX côtés de la poignée de main.**
//!
//! Ces octets-là sont ceux d'un inconnu, arrivés avant toute authentification :
//! la part `key_share` d'un `ClientHello` ou d'un `ServerHello`, lue au tout
//! début du handshake. C'est la surface d'attaque la plus précoce du serveur, et
//! la seule de `ams-tls` qui soit atteignable sans rien prouver d'abord.
//!
//! Ce qu'on cherche : une panique. Un découpage qui déborde, une conversion de
//! tranche vers tableau qui suppose une longueur, une primitive qui panique sur
//! une entrée mal formée. La réponse correcte à n'importe quels octets est un
//! `Err(PeerMisbehaved)` — jamais un abandon (C3).
//!
//! On fuzze **les deux rôles** : `start_and_complete` (serveur, qui reçoit la
//! part du client) et `complete` (client, qui reçoit celle du serveur). Le second
//! coûte une génération de clé par exécution, et ce coût est assumé : c'est la
//! seule façon d'atteindre la décapsulation avec un chiffré choisi par l'attaquant.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustls::crypto::SupportedKxGroup;

fn groupe() -> ams_tls::X25519MlKem768 {
    // La source d'aléa se prend sur NOTRE fournisseur, pas sur une source
    // inventée pour l'occasion : c'est exactement le code qui sera livré qu'on
    // veut fuzzer, y compris son alimentation en aléa.
    ams_tls::X25519MlKem768::new(ams_tls::provider().secure_random)
}

fuzz_target!(|data: &[u8]| {
    // Rôle serveur : la part vient du ClientHello.
    let _ = groupe().start_and_complete(data);

    // Rôle client : la part vient du ServerHello, et `data` joue le chiffré.
    if let Ok(en_cours) = groupe().start() {
        let _ = en_cours.complete(data);
    }
});
