//! Fuzz : le garde — **un bannissement ne s'oublie jamais tant qu'il court**.
//!
//! # La propriété qui vise l'attaque
//!
//! La table du garde est bornée : c'est ce qui l'empêche d'être un épuisement de
//! mémoire. Mais une table bornée doit oublier, et **ce qu'elle oublie est
//! précisément ce qu'un attaquant veut choisir**. Inonder depuis mille sources
//! pour faire disparaître son propre bannissement est l'attaque évidente.
//!
//! Cette cible la joue : elle bannit une source, puis laisse un flot d'événements
//! arbitraires — d'autres sources, d'autres instants, d'autres événements —
//! marteler la table, et exige que le banni le reste tant que sa peine court.
//!
//! Une seconde propriété tient le reste : le garde ne rend jamais un
//! bannissement dont l'échéance est déjà passée.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use core::time::Duration;

use ams_guard::{Event, Guard, Instant, Key, Slot, Source, Thresholds, Verdict};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Un événement soumis au garde.
#[derive(Debug, Arbitrary)]
struct Coup {
    v6: bool,
    adresse: [u8; 16],
    evenement: u8,
    /// L'avance du temps depuis le coup précédent, en millisecondes.
    avance: u32,
}

#[derive(Debug, Arbitrary)]
struct Entree {
    capacite: u8,
    invalid_frames_per_minute: u8,
    refused_recipients_per_minute: u8,
    connections_per_minute: u8,
    commands_per_minute: u8,
    ban_secondes: u16,
    ipv4_prefix_bits: u8,
    ipv6_prefix_bits: u8,
    coups: Vec<Coup>,
}

fn evenement(choix: u8) -> Event {
    match choix % 4 {
        0 => Event::Connection,
        1 => Event::Command,
        2 => Event::InvalidFrame,
        // Un destinataire refusé n'est PAS une faute, mais il compte à part :
        // le mélanger au flot vérifie que son compteur ne peut ni libérer un
        // banni, ni rendre une peine déjà échue.
        _ => Event::RefusedRecipient,
    }
}

fn source(coup: &Coup) -> Source {
    if coup.v6 {
        Source::V6(coup.adresse)
    } else {
        Source::V4([
            coup.adresse[0],
            coup.adresse[1],
            coup.adresse[2],
            coup.adresse[3],
        ])
    }
}

/// Le verdict est-il un bannissement, et jusqu'à quand ?
fn echeance(verdict: Verdict) -> Option<Instant> {
    match verdict {
        Verdict::Banned { until } => Some(until),
        Verdict::Allow | Verdict::Throttled => None,
    }
}

fuzz_target!(|entree: Entree| {
    let seuils = Thresholds {
        connections_per_minute: u32::from(entree.connections_per_minute),
        commands_per_minute: u32::from(entree.commands_per_minute),
        invalid_frames_per_minute: u32::from(entree.invalid_frames_per_minute),
        refused_recipients_per_minute: u32::from(entree.refused_recipients_per_minute),
        ban_duration: Duration::from_secs(u64::from(entree.ban_secondes)),
        ipv4_prefix_bits: entree.ipv4_prefix_bits,
        ipv6_prefix_bits: entree.ipv6_prefix_bits,
    };
    // La capacité est bornée pour que la table se remplisse VITE : c'est plein
    // que l'éviction se joue, et vide qu'elle ne prouve rien.
    let capacite = usize::from(entree.capacite % 17);
    let mut table = vec![Slot::EMPTY; capacite];
    let mut garde = Guard::new(&mut table, seuils);

    // On bannit une victime désignée, en la martelant de trames invalides.
    let victime = Source::V4([203, 0, 113, 7]);
    let t0 = Instant::from_millis(0);
    let mut fin_de_peine: Option<Instant> = None;
    for _ in 0..=u32::from(entree.invalid_frames_per_minute).min(300) {
        if let Some(until) = echeance(garde.observe(victime, Event::InvalidFrame, t0)) {
            fin_de_peine = Some(until);
            break;
        }
    }

    let mut horloge = 0_u64;
    for coup in &entree.coups {
        // L'HORLOGE NE RECULE JAMAIS : le garde l'exige, et un pair qui
        // contrôlerait un recul y verrait un moyen de ne jamais franchir un seuil.
        horloge = horloge.saturating_add(u64::from(coup.avance));
        let maintenant = Instant::from_millis(horloge);

        let verdict = garde.observe(source(coup), evenement(coup.evenement), maintenant);

        // 1. UN BANNISSEMENT RENDU N'EST JAMAIS DÉJÀ ÉCHU.
        if let Some(until) = echeance(verdict) {
            assert!(
                until.as_millis() > maintenant.as_millis(),
                "bannissement rendu alors qu'il est échu"
            );
        }

        // 2. LA TABLE NE DÉBORDE JAMAIS DE SA CAPACITÉ.
        assert!(garde.tracked() <= garde.capacity(), "la table a débordé");
        assert_eq!(garde.capacity(), capacite);

        // 3. LE BANNI LE RESTE TANT QUE SA PEINE COURT — l'attaque visée.
        //
        // Elle ne vaut que si le pair qui frappe n'est pas la victime SOUS SA
        // CLÉ : avec un préfixe court — `/0` met tout le monde dans le même sac —
        // une autre adresse tombe sur le même préfixe, et le garde a alors
        // parfaitement le droit de la recompter. Comparer les ADRESSES au lieu des
        // clés faisait échouer cette cible sur un comportement correct.
        let cle =
            |source| Key::from_source(source, entree.ipv4_prefix_bits, entree.ipv6_prefix_bits);
        if let Some(fin) = fin_de_peine
            && horloge < fin.as_millis()
            && cle(source(coup)) != cle(victime)
        {
            let vu = garde.verdict(victime, maintenant);
            assert!(
                echeance(vu).is_some(),
                "le bannissement a été évincé par un flot d'autres sources"
            );
        }
    }
});
