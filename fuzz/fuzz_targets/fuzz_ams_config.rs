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

use ams_auth::{Account, DUMMY_HASH};
use ams_config::{
    Configuration, Dkim, Dmarc, Enforcement, Spf, Timeouts, Tls, decode, decode_accounts,
    decode_index, encode, encode_accounts, encode_index,
};
use ams_guard::Thresholds;
use ams_index::{MailboxState, Uid, UidValidity};
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
    garde: [u32; 5],
    prefixes: [u8; 2],
    delais: [u32; 2],
    /// Les deux écoutes de l'API — TCP et UDP — et le secret de scellement des
    /// jetons, eux aussi libres : l'un sans l'autre est un cas que le SERVEUR
    /// refuse, et le décodeur, lui, doit les rendre tels quels.
    http: [String; 3],
    /// Les deux chemins TLS, LIBREMENT INCOHÉRENTS : le fuzzer doit pouvoir
    /// composer « un seul des deux », qui est justement le cas que le décodeur
    /// refuse. Les lier ici cacherait ce refus au lieu de l'éprouver.
    tls: [String; 2],
    /// Le sélecteur DKIM et le chemin de sa clé.
    dkim: [String; 2],
    /// Le chemin du magasin de comptes.
    comptes: String,
    /// L'adresse d'écoute POP3 — libre, y compris absurde : cette crate ne
    /// l'interprète pas, et c'est l'appelant qui la lit.
    ecoute_pop3: String,
    /// L'adresse d'écoute IMAP — libre elle aussi, et pour la même raison.
    ecoute_imap: String,
    /// Des comptes — noms et adresses LIBRES : vides, en double, invalides comme
    /// noms de répertoire. Ce sont exactement les cas que le décodeur refuse, et
    /// les contraindre ici cacherait ces refus au lieu de les éprouver.
    logins: Vec<(String, Vec<String>)>,
    /// Les deux nombres de l'index, ZÉRO COMPRIS : c'est justement ce que le
    /// décodeur refuse, et le lui interdire ici cacherait ce refus.
    index: [u32; 2],
    /// Les résolveurs SPF — DES CHAÎNES LIBRES : cette crate ne les interprète
    /// pas, et lui donner des adresses bien formées cacherait qu'elle n'a pas à
    /// s'en soucier.
    resolveurs: Vec<String>,
    /// Refuse-t-on un `fail` ?
    applique: bool,
    /// Le dossier des rapports, le nom de l'organisation et l'adresse de
    /// contact — TROIS CHAÎNES LIBRES, y compris incohérentes entre elles.
    /// Cette crate les transporte ; c'est ailleurs qu'on refuse ce qui n'est pas
    /// un nom, et le lui faire faire ici cacherait ce partage.
    rapports: [String; 3],
    /// L'intervalle entre deux vidanges, ZÉRO COMPRIS : c'est la valeur qui vaut
    /// « le défaut », et elle doit traverser le format comme les autres.
    intervalle: u32,
    /// Remet-on les rapports ? Un booléen traverse le format comme le reste.
    remet: bool,
    /// En compose-t-on d'échec ? Idem.
    echecs: bool,
    /// Le délai d'une question DNS.
    delai_dns: u32,
    /// Le chemin de la liste des suffixes publics — UNE CHAÎNE LIBRE : cette
    /// crate ne l'ouvre pas, et lui donner un chemin plausible cacherait
    /// qu'elle n'a pas à s'en soucier.
    suffixes: String,
    /// Oppose-t-on un `p=reject` ?
    aligne: bool,
    /// Émet-on pour ses comptes, et les trois durées de la reprise.
    ///
    /// **ZÉRO COMPRIS**, et c'est justement la valeur qui veut dire « le
    /// défaut » : elle doit traverser le format comme les autres.
    emet: bool,
    /// Le dossier de la file — UNE CHAÎNE LIBRE, y compris vide. Le SERVEUR
    /// refuse le cas « émettre sans dossier » ; cette crate le transporte.
    file: String,
    reprises: [u32; 3],
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
        listen_http: entree.http[0].clone(),
        listen_h3: entree.http[2].clone(),
        token_key: entree.http[1].clone(),
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
            refused_recipients_per_minute: entree.garde[4],
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
        dkim: Dkim {
            selector: entree.dkim[0].clone(),
            private_key_path: entree.dkim[1].clone(),
        },
        spf: Spf {
            resolvers: entree.resolveurs.clone(),
            enforcement: if entree.applique {
                Enforcement::Enforce
            } else {
                Enforcement::Observe
            },
            timeout_millis: entree.delai_dns,
        },
        dmarc: Dmarc {
            public_suffix_list: entree.suffixes.clone(),
            enforcement: if entree.aligne {
                Enforcement::Enforce
            } else {
                Enforcement::Observe
            },
            report_directory: entree.rapports[0].clone(),
            report_org_name: entree.rapports[1].clone(),
            report_email: entree.rapports[2].clone(),
            report_interval_seconds: entree.intervalle,
            send_reports: entree.remet,
            failure_reports: entree.echecs,
        },
        relay: ams_config::Relay {
            enabled: entree.emet,
            spool: entree.file.clone(),
            retry_seconds: entree.reprises[0],
            max_retry_seconds: entree.reprises[1],
            expire_seconds: entree.reprises[2],
        },
        accounts: entree.comptes.clone(),
        listen_pop3: entree.ecoute_pop3.clone(),
        listen_imap: entree.ecoute_imap.clone(),
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

    // ── 5. LE MAGASIN DE COMPTES ────────────────────────────────────────────
    //
    // Un fichier de comptes est écrit par l'administrateur, jamais par un pair.
    // Mais un serveur qui panique en lisant SON magasin ne démarre pas, et le
    // symptôme n'a rien à voir avec la cause.
    let _ = decode_accounts(&entree.octets);

    // L'aller-retour, avec l'empreinte de personne : elle a les vrais
    // paramètres du produit, donc elle franchit `check_stored`, et le hachage
    // réel coûterait des secondes par exécution.
    let magasin: Vec<Account> = entree
        .logins
        .iter()
        .map(|(login, adresses)| Account {
            login: login.clone(),
            hash: DUMMY_HASH.to_string(),
            addresses: adresses.clone(),
        })
        .collect();
    if let Ok(ecrit) = encode_accounts(&magasin) {
        match decode_accounts(&ecrit) {
            Ok(relu) => {
                assert_eq!(relu, magasin, "l'aller-retour a changé le magasin");
                // ET LES NOMS SONT UNIQUES : le décodeur refuse les doublons,
                // donc tout magasin qu'il accepte en est exempt.
                for (rang, compte) in relu.iter().enumerate() {
                    assert!(
                        !relu[..rang].iter().any(|autre| autre.login == compte.login),
                        "un doublon de NOM a traversé le décodeur"
                    );
                    // LES ADRESSES AUSSI, et à la casse près : deux boîtes pour
                    // une adresse enverraient la moitié du courrier au mauvais
                    // endroit.
                    for adresse in &compte.addresses {
                        let ailleurs = relu
                            .iter()
                            .enumerate()
                            .filter(|(autre, _)| *autre != rang)
                            .flat_map(|(_, autre)| autre.addresses.iter())
                            .chain(
                                compte
                                    .addresses
                                    .iter()
                                    .filter(|autre| !core::ptr::eq(*autre, adresse)),
                            );
                        assert!(
                            !ailleurs
                                .into_iter()
                                .any(|autre| autre.eq_ignore_ascii_case(adresse)),
                            "un doublon d'ADRESSE a traversé le décodeur"
                        );
                    }
                }
            }
            // Refusé : nom vide, ou nom en double. C'est le décodeur qui fait
            // son travail.
            Err(_) => {}
        }
    }

    // ── 6. L'INDEX DE LA BOÎTE ──────────────────────────────────────────────
    //
    // Deux nombres, et un serveur qui panique en les relisant n'ouvre pas sa
    // boîte. Le stockage traite une erreur comme une ABSENCE d'index — il
    // reconstruit — mais une panique, elle, ne se rattrape pas.
    let _ = decode_index(&entree.octets);

    if let (Some(validite), Some(filigrane)) =
        (UidValidity::new(entree.index[0]), Uid::new(entree.index[1]))
    {
        let original = MailboxState {
            uid_validity: validite,
            uid_next: filigrane,
        };
        let ecrit = encode_index(&original).expect("un état non nul s'encode toujours");
        assert_eq!(
            decode_index(&ecrit),
            Ok(original),
            "l'aller-retour a changé l'index"
        );
    }
});
