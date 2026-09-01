// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : TLSRPT** — un rapport qu'on compose, et qu'on envoie chez un tiers.
//!
//! # CE QUI EST HOSTILE ICI
//!
//! Deux choses, et l'une est plus grave que l'autre.
//!
//! L'enregistrement `_smtp._tls` vient du domaine qu'on rapporte, et il DÉSIGNE
//! QUI RECEVRA nos messages. Sans borne ni vérification, un domaine ferait
//! bombarder l'adresse de son choix par tous les émetteurs du monde.
//!
//! Et le rapport lui-même porte des valeurs de tiers — le nom d'un serveur `MX`,
//! les lignes d'une politique publiée. Un guillemet glissé dedans écrirait une
//! structure JSON à notre place, dans un fichier qu'on compose et qu'on remet
//! nous-mêmes.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **JAMAIS PLUS DE DESTINATIONS QUE LA BORNE**, quelle que soit la place que
//!    l'appelant offre : c'est la crate qui borne, pas lui.
//! 3. **UNE DESTINATION A TOUJOURS UN DOMAINE.** Sans lui, on ne saurait ni la
//!    vérifier ni la joindre — et une destination qu'on ne peut pas vérifier ne
//!    doit pas exister.
//! 4. **UN DOMAINE NE S'AUTORISE PAS LUI-MÊME PAR HASARD** : la dispense de
//!    vérification ne vaut que pour lui et ses sous-domaines, sur les ÉTIQUETTES.
//! 5. **CE QUI SORT DU COMPOSEUR EST DU JSON ÉMETTABLE** : de l'ASCII
//!    imprimable, et pas un guillemet de plus que ceux qu'on a posés.

#![no_main]

use ams_tlsrpt::{
    Destination, Failure, Policy, PolicyType, RUA_MAX, Report, ResultType, Summary, begin,
    needs_verification, parse_record,
};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Entree {
    /// Un `TXT` arbitraire.
    txt: String,
    /// Deux domaines à confronter.
    rapporte: String,
    destination: String,
    /// De quoi composer un rapport.
    organisation: String,
    contact: String,
    identifiant: String,
    domaine: String,
    serveur: String,
    adresse: String,
    lignes: Vec<String>,
    debut: u64,
    fin: u64,
    reussies: u64,
    echouees: u64,
}

fuzz_target!(|entree: Entree| {
    // ── 1. Lire n'importe quoi ne panique jamais ────────────────────────────
    //
    // La place offerte est DÉLIBÉRÉMENT plus grande que la borne : c'est ainsi
    // qu'on éprouve que la borne est celle de la crate.
    let mut place = [Destination::EMPTY; RUA_MAX * 4];
    if let Ok(destinations) = parse_record(&entree.txt, &mut place) {
        // ── 2. JAMAIS PLUS QUE LA BORNE ─────────────────────────────────────
        assert!(
            destinations.len() <= RUA_MAX,
            "plus de destinations que la borne"
        );
        assert!(
            !destinations.is_empty(),
            "un enregistrement sans destination"
        );

        // ── 3. UNE DESTINATION A TOUJOURS UN DOMAINE ────────────────────────
        for une in destinations {
            let domaine = une
                .domain()
                .expect("une destination sans domaine ne peut ni se vérifier ni se joindre");
            assert!(!domaine.is_empty());
            assert!(!domaine.contains('@'), "une autorité avec utilisateur");
            assert!(!domaine.contains('/'), "une autorité avec chemin");
        }
    }

    // ── 4. UN DOMAINE NE S'AUTORISE PAS LUI-MÊME PAR HASARD ─────────────────
    let dispense = !needs_verification(&entree.rapporte, &entree.destination);
    if dispense {
        // La dispense ne vaut que pour le domaine lui-même, ou un sous-domaine
        // SUR LES ÉTIQUETTES. `mauvaisexample.com` n'en est pas un.
        let lui_meme = entree.destination.eq_ignore_ascii_case(&entree.rapporte);
        let sous_domaine = entree
            .destination
            .len()
            .checked_sub(entree.rapporte.len())
            .and_then(|rang| entree.destination.split_at_checked(rang))
            .is_some_and(|(prefixe, suffixe)| {
                prefixe.ends_with('.') && suffixe.eq_ignore_ascii_case(&entree.rapporte)
            });
        assert!(
            lui_meme || sous_domaine,
            "« {} » a été dispensé de vérifier pour « {} »",
            entree.destination,
            entree.rapporte
        );
    }

    // ── 5. CE QUI SORT EST DU JSON ÉMETTABLE ────────────────────────────────
    let mut tampon = vec![0_u8; 64 * 1024];
    let lignes: Vec<&str> = entree.lignes.iter().map(String::as_str).collect();
    let serveurs = [entree.serveur.as_str()];
    let issue = (|| -> Option<usize> {
        let mut ecriture = begin(
            &mut tampon,
            &Report {
                organization_name: &entree.organisation,
                contact_info: &entree.contact,
                report_id: &entree.identifiant,
                start: entree.debut,
                end: entree.fin,
            },
        )
        .ok()?;
        ecriture
            .policy(
                &Policy {
                    policy_type: PolicyType::Sts,
                    policy_domain: &entree.domaine,
                    policy_strings: &lignes,
                    mx_hosts: &serveurs,
                },
                &Summary {
                    successful: entree.reussies,
                    failed: entree.echouees,
                },
            )
            .ok()?;
        ecriture
            .failure(&Failure {
                result_type: ResultType::ValidationFailure,
                sending_mta_ip: &entree.adresse,
                receiving_mx_hostname: &entree.serveur,
                failed_session_count: entree.echouees,
            })
            .ok()?;
        Some(ecriture.finish().ok()?.len())
    })();

    let Some(combien) = issue else {
        return;
    };
    let ecrit = &tampon[..combien];
    assert!(
        ecrit
            .iter()
            .all(|octet| octet.is_ascii_graphic() || *octet == b' '),
        "un octet qu'on ne peut pas mettre dans un rapport"
    );
    // **PAS UN GUILLEMET DE PLUS QUE CEUX QU'ON A POSÉS.** Chaque chaîne en
    // ouvre un et en ferme un : leur nombre est donc PAIR, et une valeur qui en
    // aurait glissé un le rendrait impair.
    let guillemets = ecrit.iter().filter(|octet| **octet == b'"').count();
    assert!(
        guillemets.is_multiple_of(2),
        "un guillemet impair : {guillemets}"
    );
    // Et le rapport est clos.
    assert!(ecrit.starts_with(b"{\"organization-name\":"));
    assert!(ecrit.ends_with(b"]}]}"), "le rapport ne se ferme pas");
});
