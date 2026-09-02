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
//! 6. **CE QU'UN DESTINATAIRE A DEMANDÉ SE RELIT À L'IDENTIQUE** (RFC 3461) :
//!    les quatre drapeaux et l'adresse d'origine, pour CHAQUE destinataire.
//! 7. **ON NE PRÉVIENT PAS D'UN RETARD AVANT LE SEUIL**, et l'on ne cesse pas
//!    d'en prévenir une fois passé : le jugement est monotone dans le temps.
//!
//! # POURQUOI LA SIXIÈME PROPRIÉTÉ TIENT DU COURRIER
//!
//! Un drapeau qui se perdrait à la relecture n'est pas une gêne. `never` perdu,
//! c'est un rapport envoyé à qui avait demandé le silence ; « déjà prévenu »
//! perdu, c'est un avis de retard à CHAQUE reprise, vers un chemin de retour que
//! personne n'a authentifié. Les deux fautes sont silencieuses, et elles ne se
//! voient que dans la boîte de quelqu'un d'autre.

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
    /// Ce que chacun a demandé du sort de son message (RFC 3461).
    demandes: Vec<Demande>,
    /// De quoi composer une reprise.
    premiere: u32,
    plafond: u32,
    peremption: u32,
    avertissement: u32,
    maintenant: u64,
}

/// Ce qu'un destinataire demande, tel que le déposant l'a écrit.
#[derive(Debug, Arbitrary)]
struct Demande {
    never: bool,
    on_success: bool,
    on_delay: bool,
    delay_sent: bool,
    /// L'adresse d'origine (§4.2). **ELLE VIENT DU DÉPOSANT.**
    origine: String,
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

    // ── 3 et 6. UNE ENVELOPPE SE RELIT AVEC LES MÊMES ADRESSES ET LES MÊMES
    //           DEMANDES, DANS L'ORDRE ────────────────────────────────────────
    let destinataires: Vec<&str> = entree.destinataires.iter().map(String::as_str).collect();
    // **AUTANT DE DEMANDES QUE DE DESTINATAIRES**, quitte à compléter par le
    // défaut de §4.1 : c'est ce que la file écrit, et un tableau plus court
    // ferait éprouver un cas que la file ne produit pas.
    let demandes: Vec<Report<'_>> = destinataires
        .iter()
        .enumerate()
        .map(|(rang, _)| {
            entree
                .demandes
                .get(rang)
                .map_or_else(Report::default, |une| Report {
                    never: une.never,
                    on_success: une.on_success,
                    on_delay: une.on_delay,
                    delay_sent: une.delay_sent,
                    original: &une.origine,
                })
        })
        .collect();
    let enveloppe = Envelope {
        return_path: &entree.retour,
        recipients: &destinataires,
        envelope_id: "",
        reports: &demandes,
    };
    let mut tampon = vec![0_u8; envelope_max(&enveloppe)];
    if let Ok(ecrite) = write_envelope(&enveloppe, &mut tampon) {
        let mut relues = vec![""; destinataires.len()];
        let mut rapports_relus = vec![Report::default(); destinataires.len()];
        let relue = parse_envelope(ecrite, &mut relues, &mut rapports_relus)
            .expect("ce qu'on écrit se relit");
        assert_eq!(relue.return_path, entree.retour);
        assert_eq!(relue.recipients, destinataires.as_slice());
        assert_eq!(
            relue.reports,
            demandes.as_slice(),
            "une demande a changé en traversant le fichier"
        );
    }

    // ── 4. LA REPRISE NE DÉBORDE JAMAIS LA PÉREMPTION ───────────────────────
    let reprise = Backoff {
        first: Duration::from_secs(u64::from(entree.premiere)),
        ceiling: Duration::from_secs(u64::from(entree.plafond)),
        expiry: Duration::from_secs(u64::from(entree.peremption)),
        warning: Duration::from_secs(u64::from(entree.avertissement)),
    };
    let echeance = reprise.deadline(entree.depot);

    // ── 7. ON NE PRÉVIENT PAS AVANT LE SEUIL, ET ON N'ARRÊTE PAS APRÈS ──────
    //
    // Un jugement qui basculerait dans les deux sens ferait partir un second
    // avis pour un message qui n'a fait qu'attendre.
    let seuil = entree.depot.saturating_add(u64::from(entree.avertissement));
    assert_eq!(
        reprise.is_late(entree.depot, entree.maintenant),
        entree.maintenant >= seuil,
        "le seuil d'avertissement ne dit pas ce qu'il annonce"
    );
    if reprise.is_late(entree.depot, entree.maintenant) {
        assert!(
            reprise.is_late(entree.depot, u64::MAX),
            "on a cessé de prévenir en attendant plus longtemps"
        );
    }
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
