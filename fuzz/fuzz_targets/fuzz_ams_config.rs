//! Fuzz : la configuration binaire — **un serveur ne panique pas en se lisant**.
//!
//! # Pourquoi cette cible existe alors que le fichier n'est pas hostile
//!
//! Une configuration est écrite par l'administrateur, pas par un pair : ce n'est
//! pas une entrée hostile au sens de C3. Mais un disque vieillit, une copie
//! s'interrompt, un octet se retourne — et **un serveur qui panique en lisant sa
//! propre configuration ne démarre pas, et ne dit pas pourquoi**.
//!
//! La seconde propriété est celle qui compte pour C12 : ce qu'`air-mail-admin`
//! écrit, `air-mail-server` doit le lire à l'identique. Un écart y serait un
//! serveur réglé autrement que ce que l'administrateur croit avoir demandé.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use core::time::Duration;

use ams_config::{Configuration, Timeouts, Tls, decode, encode};
use ams_guard::Thresholds;
use ams_proto_smtp::Limits;
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Entree {
    /// Des octets arbitraires, à faire lire au décodeur.
    octets: Vec<u8>,
    /// Une configuration à faire traverser l'aller-retour.
    domain: String,
    listen: String,
    maildir: String,
    hosted: Vec<String>,
    max_recipients: u32,
    max_message_octets: u64,
    max_connections: u32,
    tracked_sources: u32,
    bornes: [u32; 7],
    garde: [u32; 4],
    prefixes: [u8; 2],
    delais: [u32; 2],
    /// Les deux chemins TLS, LIBREMENT INCOHÉRENTS : le fuzzer doit pouvoir
    /// composer « un seul des deux », qui est justement le cas que le décodeur
    /// refuse. Les lier ici cacherait ce refus au lieu de l'éprouver.
    tls: [String; 2],
}

fuzz_target!(|entree: Entree| {
    // ── 1. Lire n'importe quoi ne panique jamais ────────────────────────────
    let _ = decode(&entree.octets);

    // ── 2. L'ALLER-RETOUR : ce que l'admin écrit, le serveur le relit ───────
    //
    // Le domaine doit franchir la grammaire pour que la relecture aboutisse ;
    // hors de là, `decode` refuse, et c'est ce qu'on veut.
    let original = Configuration {
        domain: entree.domain.clone(),
        listen: entree.listen.clone(),
        maildir: entree.maildir.clone(),
        hosted: entree.hosted.clone(),
        max_recipients: entree.max_recipients,
        max_message_octets: entree.max_message_octets,
        max_connections: entree.max_connections,
        limits: Limits {
            max_command_octets: entree.bornes[0] as usize,
            max_local_part_octets: entree.bornes[1] as usize,
            max_domain_octets: entree.bornes[2] as usize,
            max_path_octets: entree.bornes[3] as usize,
            max_reply_octets: entree.bornes[4] as usize,
            max_text_line_octets: entree.bornes[5] as usize,
            max_parameters: entree.bornes[6] as usize,
        },
        guard: Thresholds {
            connections_per_minute: entree.garde[0],
            commands_per_minute: entree.garde[1],
            invalid_frames_per_minute: entree.garde[2],
            ban_duration: Duration::from_secs(u64::from(entree.garde[3])),
            ipv4_prefix_bits: entree.prefixes[0],
            ipv6_prefix_bits: entree.prefixes[1],
        },
        tracked_sources: entree.tracked_sources,
        timeouts: Timeouts {
            command_seconds: entree.delais[0],
            data_seconds: entree.delais[1],
        },
        tls: Tls {
            certificate_chain_path: entree.tls[0].clone(),
            private_key_path: entree.tls[1].clone(),
        },
    };

    let Ok(ecrit) = encode(&original) else {
        return;
    };
    let Ok(relue) = decode(&ecrit) else {
        // Refusée : domaine invalide, champ vide, texte non conforme, ou un
        // seul des deux chemins TLS. C'est le décodeur qui fait son travail,
        // pas un défaut.
        return;
    };
    assert_eq!(relue, original, "l'aller-retour a changé la configuration");

    // ── 3. Réécrire ce qui a été relu rend les mêmes octets ─────────────────
    let refait = encode(&relue).expect("une configuration relue se réécrit");
    assert_eq!(refait, ecrit, "l'écriture n'est pas stable");

    // ── 4. CORROMPRE UN OCTET NE FAIT JAMAIS PANIQUER ───────────────────────
    //
    // Un disque qui vieillit, une copie interrompue : le serveur doit rendre une
    // erreur, pas s'arrêter brutalement.
    if let Some(&position) = entree.octets.first() {
        let rang = usize::from(position) % ecrit.len().max(1);
        let mut corrompu = ecrit.clone();
        if let Some(octet) = corrompu.get_mut(rang) {
            *octet ^= 0xFF;
        }
        let _ = decode(&corrompu);
    }
});
