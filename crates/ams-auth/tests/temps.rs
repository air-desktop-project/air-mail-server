// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Le temps qu'un refus prend ne doit pas dire POURQUOI il refuse.**
//!
//! # Pourquoi cet essai vit ici, et non dans `src/store.rs`
//!
//! Deux raisons, et la seconde est une contrainte du projet :
//!
//! 1. `ams-auth` est `no_std`. `std::time::Instant` n'y est pas.
//! 2. `check-etages` interdit à toute crate du périmètre de LIRE L'HEURE dans
//!    son `src/` — c'est C1. Un essai d'intégration vit hors de `src/`, et
//!    n'entame donc pas cette propriété : c'est le harnais qui chronomètre, pas
//!    le produit.
//!
//! # Ce qu'il ajoute à ce que `store.rs` éprouve déjà
//!
//! Les essais unitaires vérifient que `DUMMY_HASH` porte les paramètres du
//! produit et que personne ne peut l'ouvrir. C'est une garantie STRUCTURELLE :
//! mêmes paramètres, donc même travail. Celui-ci l'OBSERVE, ce qui est autre
//! chose — un jour, la garantie structurelle tiendra encore pendant qu'un
//! court-circuit ajouté en amont rendra la main sans rien calculer.
//!
//! # Pourquoi il ne flotte pas
//!
//! Le défaut qu'il attrape n'est pas de dix pour cent, c'est d'un facteur mille :
//! sans `DUMMY_HASH`, un compte inconnu rend la main en microsecondes quand un
//! compte connu coûte des dizaines de millisecondes. Le seuil peut donc être
//! grossier, et il l'est délibérément.
//!
//! Trois précautions, tout de même : les mesures sont ENTRELACÉES, pour que la
//! charge de la machine dérive également sur les deux ; on prend la MÉDIANE, que
//! deux ordonnancements malheureux ne déplacent pas ; et une chauffe précède
//! tout, parce que la première vérification paie dix-neuf mébioctets de défauts
//! de page que les suivantes ne paient plus.

use std::time::{Duration, Instant};

use ams_auth::{Account, authenticate, hash_password};
use ams_sasl::Credentials;

/// Combien de mesures par côté. Impair, pour que la médiane soit un élément.
const MESURES: usize = 9;

/// Le compte qui existe.
const CONNU: &str = "marie";
/// Un nom qui n'est dans aucun magasin.
const INCONNU: &str = "personne-de-ce-nom";

/// Le temps d'une vérification de ce nom, avec un mot de passe TOUJOURS FAUX.
///
/// Faux des deux côtés : c'est le refus qu'on chronomètre, et un succès ne
/// s'obtiendrait pas pour le nom inconnu.
fn mesurer(comptes: &[Account], nom: &str) -> Duration {
    let identifiants = Credentials {
        authorization_identity: b"",
        authentication_identity: nom.as_bytes(),
        password: b"ce-mot-de-passe-est-faux",
    };
    let debut = Instant::now();
    let ouvre = authenticate(comptes, &identifiants);
    let pris = debut.elapsed();
    assert!(
        !ouvre,
        "`{nom}` ne doit pas ouvrir avec un mot de passe faux"
    );
    pris
}

/// La médiane, qui ne bouge pas parce qu'une mesure a été préemptée.
fn mediane(mut prises: Vec<Duration>) -> Duration {
    prises.sort_unstable();
    *prises.get(prises.len() / 2).expect("au moins une mesure")
}

#[test]
fn un_compte_inconnu_coute_le_meme_temps_qu_un_compte_connu() {
    let comptes = std::vec![Account {
        login: String::from(CONNU),
        hash: hash_password(b"le-vrai-secret", b"seize octets ici").expect("hachable"),
        addresses: std::vec::Vec::new(),
    }];

    // ── LA CHAUFFE ──────────────────────────────────────────────────────────
    // La première vérification touche dix-neuf mébioctets qu'elle vient de
    // demander au noyau, et paie un défaut de page par page. La compter fausse
    // la mesure de celui des deux qui passe en premier.
    for _ in 0..2 {
        let _ = mesurer(&comptes, CONNU);
        let _ = mesurer(&comptes, INCONNU);
    }

    // ── LES MESURES, ENTRELACÉES ────────────────────────────────────────────
    //
    // **ET L'ORDRE ALTERNE DANS LA PAIRE.** Mesurer toujours le même en premier
    // lui fait payer ce que la paire coûte à démarrer — un tampon que
    // l'allocateur vient de rendre, une page qu'il faut toucher. La première
    // écriture de cet essai le faisait, et rendait 1,86 s contre 1,15 s pour
    // deux chemins qui font le même travail : un biais de mesure qu'on aurait
    // pu lire comme une fuite.
    let mut connu = Vec::with_capacity(MESURES);
    let mut inconnu = Vec::with_capacity(MESURES);
    for tour in 0..MESURES {
        if tour % 2 == 0 {
            connu.push(mesurer(&comptes, CONNU));
            inconnu.push(mesurer(&comptes, INCONNU));
        } else {
            inconnu.push(mesurer(&comptes, INCONNU));
            connu.push(mesurer(&comptes, CONNU));
        }
    }
    let (connu, inconnu) = (mediane(connu), mediane(inconnu));
    std::eprintln!("connu : {connu:?} — inconnu : {inconnu:?}");

    // ── LE PLANCHER ABSOLU ──────────────────────────────────────────────────
    //
    // C'est lui qui attrape la régression franche : sans `DUMMY_HASH`, un nom
    // absent ne calcule RIEN et rend la main en microsecondes. Une milliseconde
    // est mille fois trop pour ce chemin-là, et vingt fois trop peu pour un
    // Argon2id réel, même sur une machine très rapide.
    assert!(
        inconnu >= Duration::from_millis(1),
        "un compte inconnu a rendu la main en {inconnu:?} : il ne calcule plus rien, \
         et le magasin de comptes redevient énumérable sans un seul mot de passe"
    );

    // ── ET LE RAPPORT ───────────────────────────────────────────────────────
    //
    // Le tiers est délibérément généreux : on ne mesure pas une fuite de dix
    // pour cent — celle-là, aucun essai stable ne l'attraperait —, on garde la
    // propriété « les deux chemins font le même travail ».
    assert!(
        inconnu.saturating_mul(3) >= connu,
        "inconnu {inconnu:?} contre connu {connu:?} : l'écart se mesure, se répète, \
         et rend le fichier de comptes énumérable"
    );

    // **ET DANS L'AUTRE SENS AUSSI.** Un compte connu qui deviendrait beaucoup
    // plus lent que le leurre dirait « ce nom existe » tout aussi bien.
    assert!(
        connu.saturating_mul(3) >= inconnu,
        "connu {connu:?} contre inconnu {inconnu:?} : l'écart parle dans les deux sens"
    );
}
