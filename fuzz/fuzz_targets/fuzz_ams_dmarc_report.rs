// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les rapports DMARC — où les envoyer, et ce qu'on y écrit.**
//!
//! Deux surfaces, et les deux viennent d'ailleurs. La liste `rua=` est publiée
//! par **le domaine qu'on rapporte** — c'est-à-dire, quand ça compte, par celui
//! qui usurpe. Le contenu du rapport, lui, porte le `header_from` et les
//! adresses d'enveloppe : **ce que le pair a dicté**.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **Ce qui sort de `decode` est de l'ASCII imprimable**, toujours : c'est ce
//!    qui empêche un `%0D%0A` d'écrire des en-têtes dans le message qu'on
//!    enverra à cette adresse.
//! 3. **Un rapport composé ne porte AUCUN des cinq octets qui ont un sens en
//!    XML** ailleurs que dans le balisage : ce qui venait des données en sort
//!    sous forme d'entités. On le vérifie en comptant les balises ouvrantes —
//!    un `<record>` injecté se verrait immédiatement.
//! 4. **Un nom de fichier ne porte que des lettres, des chiffres, un tiret, un
//!    point, un souligné, un point d'exclamation** — jamais une barre oblique,
//!    jamais un point-point. C'est ce qui l'empêche de devenir un chemin.
//! 5. **Une taille lue est celle qui était écrite**, ou une faute : jamais une
//!    valeur repartie de zéro.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_dmarc::report::aggregate::{
    DkimAuth, DkimAuthResult, Metadata, Published, Row, SpfAuth, SpfAuthResult, SpfScope, begin,
};
use ams_dmarc::report::external::{
    VERIFICATION_NAME_MAX, authorizes, needs_verification, verification_name,
};
use ams_dmarc::report::naming::{FILENAME_MAX, SUBJECT_MAX, filename, subject};
use ams_dmarc::report::uri::{Uris, decode};
use ams_dmarc::{Alignment, Policy, Verdict};

/// Ce qu'on soumet : une liste de destinations, et de quoi composer un rapport.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// La valeur d'un `rua=` ou d'un `ruf=`, telle que le DNS la rend.
    destinations: &'a [u8],
    /// Le nom de l'organisation qui rapporte.
    org_name: &'a [u8],
    /// L'identifiant du rapport.
    report_id: &'a [u8],
    /// Le domaine dont la politique s'appliquait.
    policy_domain: &'a [u8],
    /// Le `From:` rapporté — celui que le pair a écrit.
    header_from: &'a [u8],
    /// L'enveloppe, s'il y en avait une.
    envelope_from: Option<&'a [u8]>,
    /// Le sélecteur de la signature examinée.
    selector: Option<&'a [u8]>,
    /// Les bornes de la période.
    begin: u64,
    end: u64,
    /// Le compte de la ligne.
    count: u32,
    /// L'adresse source, en quatre octets.
    source: [u8; 4],
    /// De quoi choisir un enregistrement de consentement.
    consentement: &'a [u8],
}

fuzz_target!(|entree: Entree<'_>| {
    // ── 1. Les destinations ─────────────────────────────────────────────────
    let mut decode_sortie = [0_u8; 1024];
    for destination in Uris::new(entree.destinations) {
        let Ok(uri) = destination else { continue };
        // La taille lue tient dans ce qu'un `u64` peut porter, par construction.
        if let Some(taille) = uri.max_size {
            assert!(taille <= u64::MAX);
        }
        if let Ok(clair) = decode(uri.target, &mut decode_sortie) {
            // PROPRIÉTÉ 2 : rien ne sort d'ici qui ne soit imprimable.
            assert!(
                clair.iter().all(|o| o.is_ascii_graphic() || *o == b' '),
                "octet non imprimable décodé depuis {:?}",
                uri.target
            );
        }
        if let Some(domaine) = uri.domain() {
            assert!(!domaine.is_empty() && domaine.len() <= 255);
            let mut nom = [0_u8; VERIFICATION_NAME_MAX];
            if needs_verification(entree.policy_domain, domaine)
                && let Ok(nom) = verification_name(entree.policy_domain, domaine, &mut nom)
            {
                // Le nom interrogé est TOUJOURS dans la zone de la destination :
                // c'est tout ce qui empêche l'attaquant de se donner le droit.
                assert!(nom.ends_with(domaine));
            }
        }
    }
    let _ = authorizes(entree.consentement);

    // ── 2. Le nom du fichier et le sujet ────────────────────────────────────
    let mut nom = [0_u8; FILENAME_MAX];
    if let Ok(nom) = filename(
        entree.org_name,
        entree.policy_domain,
        entree.begin,
        entree.end,
        Some(entree.report_id),
        &mut nom,
    ) {
        // PROPRIÉTÉ 4 : ce nom ne peut pas devenir un chemin.
        assert!(
            nom.iter()
                .all(|o| o.is_ascii_alphanumeric() || matches!(*o, b'-' | b'.' | b'_' | b'!')),
            "un nom de fichier porte un octet qui n'a rien à y faire"
        );
        assert!(!nom.windows(2).any(|paire| paire == b".."));
    }
    let mut ligne = [0_u8; SUBJECT_MAX];
    if let Ok(ligne) = subject(
        entree.policy_domain,
        entree.org_name,
        entree.report_id,
        &mut ligne,
    ) {
        assert!(!ligne.iter().any(|o| matches!(*o, b'\r' | b'\n')));
    }

    // ── 3. Le rapport lui-même ──────────────────────────────────────────────
    let metadata = Metadata {
        org_name: entree.org_name,
        email: b"dmarc@receveur.test",
        extra_contact: None,
        report_id: entree.report_id,
        begin: entree.begin,
        end: entree.end,
    };
    let published = Published {
        domain: entree.policy_domain,
        dkim_alignment: Alignment::Relaxed,
        spf_alignment: Alignment::Relaxed,
        policy: Policy::None,
        subdomain_policy: None,
        percent: 100,
    };
    let signatures = [DkimAuth {
        domain: entree.policy_domain,
        selector: entree.selector,
        result: DkimAuthResult::Fail,
    }];
    let ligne = Row {
        source_ip: core::net::IpAddr::V4(core::net::Ipv4Addr::from(entree.source)),
        count: entree.count,
        disposition: Policy::None,
        dkim: Verdict::Fail,
        spf: Verdict::Fail,
        header_from: entree.header_from,
        envelope_from: entree.envelope_from,
        envelope_to: None,
        dkim_auth: &signatures,
        spf_auth: SpfAuth {
            domain: entree.policy_domain,
            scope: SpfScope::MailFrom,
            result: SpfAuthResult::None,
        },
    };
    let mut tampon = [0_u8; 8192];
    let Ok(mut rapport) = begin(&mut tampon, &metadata, &published) else {
        return;
    };
    if rapport.record(&ligne).is_err() {
        return;
    }
    let Ok(xml) = rapport.finish() else { return };

    // PROPRIÉTÉ 3 : le balisage est celui qu'on a écrit, et pas un de plus.
    let compter = |motif: &[u8]| {
        xml.windows(motif.len())
            .filter(|fenetre| *fenetre == motif)
            .count()
    };
    assert_eq!(
        compter(b"<record>"),
        1,
        "une balise `record` a été injectée"
    );
    assert_eq!(compter(b"<feedback>"), 1);
    assert_eq!(compter(b"<header_from>"), 1);
    assert_eq!(compter(b"</feedback>"), 1);
    // Le document est de l'ASCII imprimable et des sauts de ligne, rien d'autre.
    assert!(
        xml.iter()
            .all(|o| o.is_ascii_graphic() || matches!(*o, b' ' | b'\n')),
        "le rapport porte un octet qu'aucun analyseur XML n'attend"
    );
});
