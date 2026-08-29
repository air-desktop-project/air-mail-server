//! Ce que le verdict doit tenir.

use super::{Assessment, Authentication, Verdict, evaluate};
use crate::alignment::PublicSuffix;
use crate::record::{Policy, Record};

/// Une liste de suffixes publics d'épreuve.
struct Suffixes;

impl PublicSuffix for Suffixes {
    fn organizational_domain<'a>(&self, domain: &'a [u8]) -> &'a [u8] {
        for suffixe in [&b".co.uk"[..], b".com", b".net"] {
            let Some(reste) = domain.len().checked_sub(suffixe.len()) else {
                continue;
            };
            if !domain
                .get(reste..)
                .is_some_and(|queue| queue.eq_ignore_ascii_case(suffixe))
            {
                continue;
            }
            let avant = domain.get(..reste).unwrap_or_default();
            let debut = avant
                .iter()
                .rposition(|octet| *octet == b'.')
                .map_or(0, |rang| rang.saturating_add(1));
            return domain.get(debut..).unwrap_or(domain);
        }
        domain
    }
}

fn juger(politique: &[u8], from: &[u8], spf: Option<&[u8]>, dkim: &[&[u8]]) -> Assessment {
    let enregistrement = Record::parse(politique).expect("politique lisible");
    let authentification = Authentication { spf, dkim };
    evaluate(&enregistrement, from, false, &authentification, &Suffixes)
}

// ── UN SEUL MÉCANISME SUFFIT ────────────────────────────────────────────────

#[test]
fn dkim_seul_suffit() {
    // C'est ce qui laisse un message survivre à une redirection : SPF tombe —
    // le relais n'est pas autorisé pour le domaine d'origine — mais la
    // signature, elle, traverse.
    let juge = juger(
        b"v=DMARC1; p=reject",
        b"example.com",
        None,
        &[b"example.com"],
    );
    assert_eq!(juge.verdict, Verdict::Pass);
}

#[test]
fn spf_seul_suffit() {
    // Et c'est ce qui laisse un message survivre à une liste de diffusion, qui
    // casse la signature en ajoutant un pied de page mais réémet depuis un
    // domaine qu'elle contrôle — pour peu qu'il s'aligne.
    let juge = juger(
        b"v=DMARC1; p=reject",
        b"example.com",
        Some(b"example.com"),
        &[],
    );
    assert_eq!(juge.verdict, Verdict::Pass);
}

#[test]
fn aucun_des_deux_ne_suffit_pas() {
    let juge = juger(b"v=DMARC1; p=reject", b"example.com", None, &[]);
    assert_eq!(juge.verdict, Verdict::Fail);
    assert_eq!(juge.policy, Policy::Reject);
}

#[test]
fn une_signature_parmi_d_autres_suffit() {
    // Un message en porte souvent plusieurs — celle de l'auteur, celle du
    // relais. Il suffit qu'UNE s'aligne.
    let juge = juger(
        b"v=DMARC1; p=reject",
        b"example.com",
        None,
        &[b"relais.net", b"example.com", b"autre.net"],
    );
    assert_eq!(juge.verdict, Verdict::Pass);
}

// ── CE QUE L'ALIGNEMENT REFUSE ──────────────────────────────────────────────

#[test]
fn un_mecanisme_qui_reussit_sans_s_aligner_ne_vaut_rien() {
    // C'EST TOUT LE SUJET DE DMARC. L'attaquant émet depuis un domaine qu'il
    // détient, le signe, et écrit ce qu'il veut dans le `From:` : SPF et DKIM
    // disent tous deux « oui », et DMARC dit non.
    let juge = juger(
        b"v=DMARC1; p=reject",
        b"banque.example.com",
        Some(b"attaquant.net"),
        &[b"attaquant.net"],
    );
    assert_eq!(juge.verdict, Verdict::Fail);
}

#[test]
fn le_mode_relache_aligne_les_sous_domaines() {
    let juge = juger(
        b"v=DMARC1; p=reject",
        b"example.com",
        Some(b"envoi.example.com"),
        &[],
    );
    assert_eq!(juge.verdict, Verdict::Pass);
}

#[test]
fn le_mode_strict_ne_les_aligne_pas() {
    // Et les deux modes se règlent séparément : un domaine peut être strict sur
    // ses signatures et relâché sur son enveloppe.
    let strict_partout = juger(
        b"v=DMARC1; p=reject; adkim=s; aspf=s",
        b"example.com",
        Some(b"envoi.example.com"),
        &[b"envoi.example.com"],
    );
    assert_eq!(strict_partout.verdict, Verdict::Fail);

    let strict_sur_dkim = juger(
        b"v=DMARC1; p=reject; adkim=s",
        b"example.com",
        Some(b"envoi.example.com"),
        &[b"envoi.example.com"],
    );
    assert_eq!(
        strict_sur_dkim.verdict,
        Verdict::Pass,
        "SPF, lui, est relâché"
    );
}

// ── CE QUE LE VERDICT PORTE ─────────────────────────────────────────────────

#[test]
fn la_politique_rendue_est_celle_qui_s_applique() {
    let enregistrement = Record::parse(b"v=DMARC1; p=none; sp=reject; pct=25").expect("lisible");
    let rien = Authentication {
        spf: None,
        dkim: &[],
    };

    let du_domaine = evaluate(&enregistrement, b"example.com", false, &rien, &Suffixes);
    assert_eq!(du_domaine.policy, Policy::None);
    assert_eq!(du_domaine.percent, 25);

    let d_un_sous_domaine = evaluate(&enregistrement, b"a.example.com", true, &rien, &Suffixes);
    assert_eq!(d_un_sous_domaine.policy, Policy::Reject);
}

#[test]
fn la_politique_est_rendue_meme_quand_le_verdict_passe() {
    // L'appelant n'a rien à en faire — mais un journal, si : « ce message
    // passe, et ce domaine demande le rejet » se relit mieux que « ce message
    // passe ».
    let juge = juger(
        b"v=DMARC1; p=reject",
        b"example.com",
        Some(b"example.com"),
        &[],
    );
    assert_eq!(juge.verdict, Verdict::Pass);
    assert_eq!(juge.policy, Policy::Reject);
}

#[test]
fn un_from_vide_ne_s_aligne_avec_rien() {
    let juge = juger(
        b"v=DMARC1; p=reject",
        b"",
        Some(b"example.com"),
        &[b"example.com"],
    );
    assert_eq!(juge.verdict, Verdict::Fail);
}

#[test]
fn les_types_se_deboguent_et_se_comparent() {
    let juge = juger(b"v=DMARC1; p=none", b"example.com", None, &[]);
    let copie = juge;
    assert_eq!(copie, juge);
    assert!(!std::format!("{juge:?}").is_empty());
    assert!(!std::format!("{:?}", Verdict::Pass).is_empty());
    assert_ne!(Verdict::Pass, Verdict::Fail);
    let authentification = Authentication {
        spf: None,
        dkim: &[],
    };
    let copie = authentification;
    assert!(copie.dkim.is_empty());
    assert!(!std::format!("{authentification:?}").is_empty());
}
