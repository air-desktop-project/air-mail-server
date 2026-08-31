// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le pont entre `rustls::quic` et notre protection de paquet.**
//!
//! # Pourquoi celle-ci, alors que `fuzz_ams_quic_crypto` existe déjà
//!
//! Cette cible-là éprouve le CALCUL. Celle-ci éprouve le BRANCHEMENT — et c'est
//! une autre chose. `rustls` remet le tag à part quand `ams-quic-crypto`
//! l'écrit à la suite du clair ; `rustls` remet un `Iv` quand nous attendons
//! douze octets ; `rustls` promet une clé de la longueur que nous avons
//! annoncée. Chacune de ces trois conversions est une occasion de se tromper
//! d'un octet, **et aucune ne se verrait dans un aller-retour qui se parle à
//! lui-même**.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **CE QUE LE PONT CHIFFRE, LE PONT LE RELIT**, et rend exactement le clair
//!    qu'on avait.
//! 3. **LE PONT CHIFFRE COMME LA CRATE EN DESSOUS.** Si les deux divergeaient,
//!    aucune poignée de main QUIC n'aboutirait — et la faute serait dans le
//!    déplacement du tag, que rien d'autre ne surveille.
//! 4. **CE QU'ON ABÎME NE SE DÉCHIFFRE PAS**, ni la charge, ni l'en-tête, ni le
//!    numéro de paquet.
//! 5. **LA PROTECTION D'EN-TÊTE FAIT UN ALLER-RETOUR** et laisse le bit de forme
//!    en clair — sans lui, le pair ne saurait pas combien de bits démasquer.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_quic_crypto::{PACKET_OCTETS_MAX, Role, Secret};
use rustls::quic::{Keys, Version};
use rustls::{Side, SupportedCipherSuite, Tls13CipherSuite};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// L'identifiant de destination, tel qu'un client le choisirait.
    destination: &'a [u8],
    /// Un clair quelconque.
    clair: &'a [u8],
    /// Les données associées, c'est-à-dire l'en-tête.
    entete: &'a [u8],
    /// Deux numéros de paquet.
    numero: u64,
    autre: u64,
    /// De quel côté l'on se place.
    du_serveur: bool,
    /// Un échantillon de protection d'en-tête.
    echantillon: &'a [u8],
    /// Le premier octet d'un en-tête, et son numéro de paquet tronqué.
    premier: u8,
    tronque: &'a [u8],
}

/// La suite AES-128 du fournisseur QUIC — celle que §5.1 de RFC 9001 impose.
///
/// **RIEN N'EST ALLOUÉ NI RETENU** : les suites capables de QUIC sont des
/// constantes du binaire, donc `tls13()` rend une référence qui survit au
/// fournisseur qu'on jette. C'est `LeakSanitizer` qui a imposé cette forme :
/// la première version fuitait un fournisseur par appel, et il l'a compté.
fn suite() -> &'static Tls13CipherSuite {
    ams_tls::provider_quic()
        .cipher_suites
        .iter()
        .filter_map(SupportedCipherSuite::tls13)
        .find(|suite| suite.common.suite == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        .expect("AES-128-GCM est la suite obligatoire de QUIC")
}

fuzz_target!(|entree: Entree| {
    // Un identifiant de plus de vingt octets n'existe pas : la grammaire l'a
    // déjà refusé, et le chiffrement n'a pas à s'en soucier.
    let Some(destination) = entree.destination.get(..20.min(entree.destination.len())) else {
        return;
    };
    // Une charge plus grande qu'un datagramme est hors du domaine : le pont la
    // refuse, et c'est éprouvé ailleurs.
    if entree.clair.len() > PACKET_OCTETS_MAX {
        return;
    }

    let suite = suite();
    let Some(quic) = suite.quic else {
        return;
    };
    let (cote, role) = match entree.du_serveur {
        true => (Side::Server, Role::Server),
        false => (Side::Client, Role::Client),
    };
    let clefs = Keys::initial(Version::V1, suite, quic, destination, cote);

    // Ce que notre dérivation à nous produit, pour le même identifiant. Le rôle
    // doit suivre le côté : `local` chiffre ce que ce côté-ci émet.
    let Ok(secret) = Secret::initial(destination, role) else {
        return;
    };
    let Ok(nous) = secret.keys() else {
        return;
    };

    // ── PROPRIÉTÉ 2 et 3 ────────────────────────────────────────────────────
    let mut par_le_pont = entree.clair.to_vec();
    let Ok(tag) =
        clefs
            .local
            .packet
            .encrypt_in_place(entree.numero, entree.entete, &mut par_le_pont)
    else {
        return;
    };
    assert_eq!(
        tag.as_ref().len(),
        clefs.local.packet.tag_len(),
        "le tag n'a pas la longueur annoncée"
    );
    par_le_pont.extend_from_slice(tag.as_ref());

    let mut par_dessous = entree.clair.to_vec();
    par_dessous.resize(entree.clair.len() + 16, 0);
    nous.seal(
        entree.numero,
        entree.entete,
        &mut par_dessous,
        entree.clair.len(),
    )
    .expect("ce que le pont a su chiffrer, la crate en dessous le sait aussi");
    assert_eq!(
        par_le_pont, par_dessous,
        "le pont et la crate en dessous doivent chiffrer à l'identique"
    );

    let mut relu = par_le_pont.clone();
    let clair = clefs
        .local
        .packet
        .decrypt_in_place(entree.numero, entree.entete, &mut relu)
        .expect("ce que le pont chiffre, le pont le relit");
    assert_eq!(clair, entree.clair, "l'aller-retour a changé le clair");

    // ── PROPRIÉTÉ 4 ─────────────────────────────────────────────────────────
    //
    // Un octet changé n'importe où fait échouer l'authentification. On éprouve
    // les trois endroits : la charge, l'en-tête, et le numéro de paquet.
    if let Some(premier) = par_le_pont.first().copied() {
        let mut abime = par_le_pont.clone();
        abime[0] = premier ^ 0x01;
        assert!(
            clefs
                .local
                .packet
                .decrypt_in_place(entree.numero, entree.entete, &mut abime)
                .is_err(),
            "une charge abîmée ne doit pas s'authentifier"
        );
    }
    if let Some(premier) = entree.entete.first().copied() {
        let mut autre = entree.entete.to_vec();
        autre[0] = premier ^ 0x01;
        let mut copie = par_le_pont.clone();
        assert!(
            clefs
                .local
                .packet
                .decrypt_in_place(entree.numero, &autre, &mut copie)
                .is_err(),
            "un en-tête modifié ne doit pas s'authentifier"
        );
    }
    if entree.numero != entree.autre {
        let mut copie = par_le_pont.clone();
        assert!(
            clefs
                .local
                .packet
                .decrypt_in_place(entree.autre, entree.entete, &mut copie)
                .is_err(),
            "un paquet doit être lié à son numéro"
        );
    }

    // ── PROPRIÉTÉ 5 ─────────────────────────────────────────────────────────
    let masquant = &clefs.local.header;
    let mut premier = entree.premier;
    let attendu = premier;
    let mut tronque = entree.tronque.to_vec();
    let avant = tronque.clone();
    let echantillon = entree.echantillon;
    match masquant.encrypt_in_place(echantillon, &mut premier, &mut tronque) {
        Ok(()) => {
            // Le bit de forme n'est jamais masqué : sans lui, le pair ne
            // saurait pas si l'en-tête est long ou court, donc combien de bits
            // démasquer.
            assert_eq!(
                premier & 0x80,
                attendu & 0x80,
                "le bit de forme doit rester lisible"
            );
            masquant
                .decrypt_in_place(echantillon, &mut premier, &mut tronque)
                .expect("ce que le masque a fait, le masque le défait");
            assert_eq!(premier, attendu, "l'aller-retour a changé l'octet de tête");
            assert_eq!(tronque, avant, "l'aller-retour a changé le numéro");
        }
        // Un refus n'a que deux causes, et toutes deux sont des longueurs :
        // l'échantillon n'a pas ses seize octets, ou le numéro dépasse quatre.
        Err(_) => assert!(
            echantillon.len() != masquant.sample_len() || tronque.len() > 4,
            "un refus doit avoir une cause de longueur"
        ),
    }
});
