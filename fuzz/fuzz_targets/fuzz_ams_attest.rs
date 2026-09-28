// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : l'attestation de clef d'Android** — une chaîne quelconque, telle
//! qu'un téléphone l'enverrait à l'enrôlement.
//!
//! Les graines sont les chaînes synthétiques d'`ams-attest` : le fuzz part de
//! chaînes qui se vérifient, et les altère.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UNE ATTESTATION ACCEPTÉE L'EST SOUS UNE RACINE ADMISE** : sans racine
//!    admise, tout est refusé — une chaîne ne s'accepte jamais « par défaut ».

#![no_main]

use libfuzzer_sys::fuzz_target;

const RACINE: &[u8] = include_bytes!("../../crates/ams-attest/src/vecteurs/synthese/racine.spki");
const APPAREIL: &[u8] =
    include_bytes!("../../crates/ams-attest/src/vecteurs/synthese/appareil.sec1");
const DEFI: &[u8] = include_bytes!("../../crates/ams-attest/src/vecteurs/synthese/defi.bin");
const EMPREINTE: &[u8] =
    include_bytes!("../../crates/ams-attest/src/vecteurs/synthese/empreinte.bin");
/// 2026-09-28 à minuit UTC.
const MAINTENANT: i64 = 1_790_553_600;

fuzz_target!(|chaine: &[u8]| {
    let Ok(appareil) = <[u8; 65]>::try_from(APPAREIL) else {
        return;
    };
    let Ok(empreinte) = <[u8; 32]>::try_from(EMPREINTE) else {
        return;
    };
    let signataires = [empreinte];
    let racines = [RACINE];
    let politique = ams_attest::Policy {
        roots: &racines,
        package: b"org.airdesktop.mail",
        signers: &signataires,
    };
    let _ = ams_attest::verify(chaine, &appareil, DEFI, &politique, MAINTENANT);

    let sans_racine = ams_attest::Policy {
        roots: &[],
        ..politique
    };
    assert!(
        ams_attest::verify(chaine, &appareil, DEFI, &sans_racine, MAINTENANT).is_err(),
        "une chaîne acceptée sans aucune racine admise"
    );
});
