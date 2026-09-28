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
//! 3. **LA LISTE DE RÉVOCATION SE LIT SANS PANIQUE**, et dit combien elle a lu
//!    — autant que d'appels.
//! 4. **UN OBJET APP ATTEST SE LIT SANS PANIQUE** (0.2.43), et sans racine
//!    admise rien n'est accepté.

#![no_main]

use libfuzzer_sys::fuzz_target;

const RACINE: &[u8] = include_bytes!("../../crates/ams-attest/src/vecteurs/synthese/racine.spki");
const APPAREIL: &[u8] =
    include_bytes!("../../crates/ams-attest/src/vecteurs/synthese/appareil.sec1");
const DEFI: &[u8] = include_bytes!("../../crates/ams-attest/src/vecteurs/synthese/defi.bin");
const EMPREINTE: &[u8] =
    include_bytes!("../../crates/ams-attest/src/vecteurs/synthese/empreinte.bin");
const APPLE_ESSAI: &[u8] =
    include_bytes!("../../crates/ams-attest/src/vecteurs/apple/synthese/racine.spki");
const CLIENT: &[u8] =
    include_bytes!("../../crates/ams-attest/src/vecteurs/apple/synthese/client.bin");
/// 2026-09-28 à minuit UTC.
const MAINTENANT: i64 = 1_790_553_600;

fuzz_target!(|chaine: &[u8]| {
    let mut vus = 0_usize;
    if let Ok(combien) = ams_attest::read_status_list(chaine, &mut |_| vus += 1) {
        assert_eq!(combien, vus, "la liste dit autre chose que ce qu'elle a lu");
    }

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
        revoked: &[],
    };
    let _ = ams_attest::verify(chaine, &appareil, DEFI, &politique, MAINTENANT);

    // App Attest : l'objet d'essai, sous sa racine d'essai et celle d'Apple.
    let racines_apple = [APPLE_ESSAI, ams_attest::APPLE_ROOTS[0]];
    let apple = ams_attest::ApplePolicy {
        roots: &racines_apple,
        app_id: b"TEAM123456.org.airdesktop.mail",
        environment: ams_attest::AppleEnvironment::Production,
    };
    let _ = ams_attest::verify_app_attest(chaine, CLIENT, &apple, MAINTENANT);
    let apple_sans_racine = ams_attest::ApplePolicy {
        roots: &[],
        ..apple
    };
    assert!(
        ams_attest::verify_app_attest(chaine, CLIENT, &apple_sans_racine, MAINTENANT).is_err(),
        "un objet App Attest accepté sans aucune racine admise"
    );

    let sans_racine = ams_attest::Policy {
        roots: &[],
        ..politique
    };
    assert!(
        ams_attest::verify(chaine, &appareil, DEFI, &sans_racine, MAINTENANT).is_err(),
        "une chaîne acceptée sans aucune racine admise"
    );
});
