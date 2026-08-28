//! Fuzz : les noms Maildir — **un nom composé se relit à l'identique**.
//!
//! # Pourquoi l'aller-retour est la propriété qui compte ici
//!
//! L'UID d'un message vit dans son nom de fichier : c'est ce qui rend l'index
//! reconstructible (C13). Si un nom composé ne se relisait pas à l'identique,
//! l'UID changerait au prochain parcours — et un UID qui change force à
//! incrémenter l'`UIDVALIDITY`, ce qui fait **retélécharger la boîte entière à
//! tous les clients**.
//!
//! Un défaut ici ne se voit donc pas au moment où il se produit : il se voit
//! quand mille boîtes se resynchronisent.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use ams_index::{Flags, MessageName, Uid, compose, summarise};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Entree {
    unique: Vec<u8>,
    uid: u32,
    taille: u64,
    drapeaux: Option<u8>,
    /// Des noms arbitraires, pour le repliement.
    noms: Vec<Vec<u8>>,
}

/// Des drapeaux composés de lettres licites.
fn drapeaux(bits: u8) -> Flags {
    let mut flags = Flags::NONE;
    for (rang, drapeau) in [
        Flags::DRAFT,
        Flags::FLAGGED,
        Flags::PASSED,
        Flags::REPLIED,
        Flags::SEEN,
        Flags::TRASHED,
    ]
    .into_iter()
    .enumerate()
    {
        if bits & (1_u8 << rang) != 0 {
            flags = flags.with(drapeau);
        }
    }
    flags
}

fuzz_target!(|entree: Entree| {
    // ── 1. Analyser n'importe quoi ne panique jamais ────────────────────────
    for nom in &entree.noms {
        if let Ok(lu) = MessageName::parse(nom) {
            // Un nom accepté ne porte JAMAIS de séparateur de chemin : c'est ce
            // qui ferme la traversée de répertoire avant le système de fichiers.
            assert!(!nom.contains(&b'/'), "séparateur accepté : {nom:?}");
            // Un UID lu n'est jamais nul (RFC 9051 §2.3.1.1).
            assert!(lu.uid().is_none_or(|uid| uid.value() != 0), "UID nul");
            // La partie unique est un préfixe du nom : elle ne peut pas avoir été
            // inventée.
            assert!(nom.starts_with(lu.unique()), "partie unique inventée");
        }
    }

    // ── 2. Le repliement ne panique pas, et ses comptes se tiennent ─────────
    let resume = summarise(entree.noms.iter().map(Vec::as_slice));
    let total = u64::from(resume.numbered)
        .saturating_add(u64::from(resume.unnumbered))
        .saturating_add(u64::from(resume.unreadable));
    assert_eq!(
        total,
        u64::try_from(entree.noms.len()).unwrap_or(u64::MAX),
        "un nom n'a été compté ni une fois ni l'autre"
    );
    // Le prochain UID est strictement au-dessus de tous ceux qui ont été lus,
    // SAUF quand la boîte est épuisée — auquel cas elle le déclare.
    if !resume.exhausted {
        for nom in &entree.noms {
            if let Ok(lu) = MessageName::parse(nom)
                && let Some(uid) = lu.uid()
            {
                assert!(
                    uid < resume.next_uid,
                    "le prochain UID réattribuerait {}",
                    uid.value()
                );
            }
        }
    }

    // ── 3. L'ALLER-RETOUR : composer puis relire rend l'identique ───────────
    let Some(uid) = Uid::new(entree.uid) else {
        return;
    };
    let flags = entree.drapeaux.map(drapeaux);
    let mut tampon = [0_u8; 1024];
    let Ok(ecrits) = compose(&mut tampon, &entree.unique, uid, entree.taille, flags) else {
        return;
    };
    let nom = tampon.get(..ecrits).unwrap_or_default();

    let relu = MessageName::parse(nom).expect("un nom composé se relit");
    assert_eq!(relu.uid(), Some(uid), "l'UID a changé : {nom:?}");
    assert_eq!(relu.size(), Some(entree.taille), "la taille a changé");
    assert_eq!(
        relu.flags(),
        flags.unwrap_or(Flags::NONE),
        "les drapeaux ont changé"
    );
    assert_eq!(relu.has_info(), flags.is_some());

    // Et recomposer depuis ce qui a été relu rend exactement les mêmes octets.
    let mut encore = [0_u8; 1024];
    let refait = compose(
        &mut encore,
        &entree.unique,
        relu.uid().expect("lu"),
        relu.size().expect("lue"),
        flags,
    )
    .expect("recomposable");
    assert_eq!(
        encore.get(..refait),
        Some(nom),
        "la composition n'est pas stable"
    );
});
