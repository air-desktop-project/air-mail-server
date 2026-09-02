// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la file de réémission** — un nom de fichier ne fait pas sortir du
//! répertoire, et une enveloppe ne s'invente pas de destinataire.
//!
//! # CE QUI EST HOSTILE ICI, ET QUI NE SAUTE PAS AUX YEUX
//!
//! Ces deux fichiers, c'est NOUS qui les écrivons. Mais ce qu'on y met vient
//! d'ailleurs : le destinataire vient d'un `RCPT TO:`, et le chemin de retour
//! d'un `MAIL FROM:`. Un `LF` glissé dans une adresse ajouterait une ligne à
//! l'enveloppe — c'est-à-dire un destinataire — et la reprise suivante y
//! remettrait le message. Un `/` dans un identifiant écrirait la file ailleurs.
//!
//! Et la relecture est l'autre moitié : un répertoire de file survit aux
//! redémarrages, aux copies de sauvegarde et aux doigts qui glissent. Ce qu'on y
//! trouve n'est pas forcément ce qu'on y a mis.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN NOM ÉCRIT SE RELIT À L'IDENTIQUE.** Sans cela, la file oublierait des
//!    essais, ou reprendrait au mauvais moment.
//! 3. **UN NOM ÉCRIT NE SORT PAS DU RÉPERTOIRE** : ni `/`, ni `..`, ni point en
//!    tête.
//! 4. **UNE ENVELOPPE ÉCRITE SE RELIT AVEC LES MÊMES ADRESSES, DANS L'ORDRE.**
//!    Un destinataire qui apparaîtrait, disparaîtrait ou changerait de place
//!    serait du courrier remis à quelqu'un d'autre.
//! 5. **LA REPRISE NE REND JAMAIS UN ESSAI APRÈS LA PÉREMPTION**, et ne fait
//!    jamais reculer le temps.

#![no_main]

use core::time::Duration;

use ams_queue::{
    Backoff, Decision, Entry, Envelope, NAME_MAX, Report, envelope_max, parse_envelope, parse_name,
    write_envelope, write_name,
};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Entree {
    /// Des octets arbitraires, à faire relire aux deux décodeurs.
    nom: String,
    fichier: String,
    /// De quoi composer un nom.
    due: u64,
    depot: u64,
    essais: u32,
    identifiant: String,
    /// De quoi composer une enveloppe.
    retour: String,
    destinataires: Vec<String>,
    /// De quoi composer une reprise.
    premiere: u32,
    plafond: u32,
    peremption: u32,
    maintenant: u64,
}

fuzz_target!(|entree: Entree| {
    // ── 1. Relire n'importe quoi ne panique jamais ──────────────────────────
    let _ = parse_name(&entree.nom);
    let mut cases = [""; 128];
    let mut rapports = [Report::default(); 128];
    let _ = parse_envelope(&entree.fichier, &mut cases, &mut rapports);

    // ── 2. UN NOM ÉCRIT SE RELIT À L'IDENTIQUE, ET NE SORT PAS ──────────────
    let voulu = Entry {
        due: entree.due,
        deposited: entree.depot,
        attempts: entree.essais,
        id: &entree.identifiant,
    };
    let mut place = [0_u8; NAME_MAX];
    if let Ok(ecrit) = write_name(&voulu, &mut place) {
        assert_eq!(
            parse_name(ecrit),
            Some(voulu),
            "« {ecrit} » ne se relit pas"
        );
        assert!(
            !ecrit.contains('/'),
            "« {ecrit} » désigne un autre répertoire"
        );
        assert!(!ecrit.starts_with('.'), "« {ecrit} » se cacherait");
        assert!(ecrit.ends_with(".eml"), "« {ecrit} » n'est pas une entrée");
        assert!(ecrit.is_ascii(), "« {ecrit} » n'est pas de l'ASCII");
    }

    // ── 3. UNE ENVELOPPE SE RELIT AVEC LES MÊMES ADRESSES, DANS L'ORDRE ─────
    let destinataires: Vec<&str> = entree.destinataires.iter().map(String::as_str).collect();
    let enveloppe = Envelope {
        return_path: &entree.retour,
        recipients: &destinataires,
        envelope_id: "",
        reports: &[],
    };
    let mut tampon = vec![0_u8; envelope_max(&enveloppe)];
    if let Ok(ecrite) = write_envelope(&enveloppe, &mut tampon) {
        let mut relues = vec![""; destinataires.len()];
        let mut rapports_relus = [Report::default(); 128];
        let relue = parse_envelope(ecrite, &mut relues, &mut rapports_relus)
            .expect("ce qu'on écrit se relit");
        assert_eq!(relue.return_path, entree.retour);
        assert_eq!(relue.recipients, destinataires.as_slice());
    }

    // ── 4. LA REPRISE NE DÉBORDE JAMAIS LA PÉREMPTION ───────────────────────
    let reprise = Backoff {
        first: Duration::from_secs(u64::from(entree.premiere)),
        ceiling: Duration::from_secs(u64::from(entree.plafond)),
        expiry: Duration::from_secs(u64::from(entree.peremption)),
    };
    let echeance = reprise.deadline(entree.depot);
    for essais in [1_u32, 2, 7, entree.essais] {
        match reprise.after_failure(entree.depot, essais, entree.maintenant) {
            Decision::Retry { at } => {
                // LE TEMPS NE RECULE PAS : un essai placé dans le passé serait
                // repris aussitôt, en boucle, aussi vite que le disque tourne.
                assert!(at >= entree.maintenant, "l'essai recule");
                assert!(at <= echeance, "l'essai dépasse la péremption");
            }
            // On ne renonce qu'une fois l'échéance atteinte.
            Decision::GiveUp => assert!(entree.maintenant >= echeance),
        }
    }
});
