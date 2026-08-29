//! Ce qu'un enregistrement DMARC doit tenir.

use super::{POLICY_NAME_MAX, Policy, Record, policy_name};
use crate::Error;
use crate::alignment::Alignment;

fn lire(txt: &[u8]) -> Result<Record<'_>, Error> {
    Record::parse(txt)
}

#[test]
fn un_enregistrement_ordinaire_se_lit() {
    let lu = lire(b"v=DMARC1; p=reject").expect("lisible");
    assert_eq!(lu.policy, Policy::Reject);
    assert_eq!(lu.subdomain_policy, None);
    assert_eq!(lu.dkim_alignment, Alignment::Relaxed);
    assert_eq!(lu.spf_alignment, Alignment::Relaxed);
    assert_eq!(lu.percent, 100);
    assert_eq!(lu.report_interval, 86_400);
    assert_eq!(lu.aggregate_reports, None);
    assert_eq!(lu.failure_reports, None);
}

#[test]
fn un_enregistrement_complet_se_lit_aussi() {
    let lu = lire(
        b"v=DMARC1; p=quarantine; sp=reject; adkim=s; aspf=s; pct=25; ri=3600; \
          rua=mailto:agrege@example.com; ruf=mailto:echec@example.com; fo=1; rf=afrf",
    )
    .expect("lisible");
    assert_eq!(lu.policy, Policy::Quarantine);
    assert_eq!(lu.subdomain_policy, Some(Policy::Reject));
    assert_eq!(lu.dkim_alignment, Alignment::Strict);
    assert_eq!(lu.spf_alignment, Alignment::Strict);
    assert_eq!(lu.percent, 25);
    assert_eq!(lu.report_interval, 3_600);
    assert_eq!(
        lu.aggregate_reports,
        Some(&b"mailto:agrege@example.com"[..])
    );
    assert_eq!(lu.failure_reports, Some(&b"mailto:echec@example.com"[..]));
}

// ── CE QUI FAIT ÉCARTER L'ENREGISTREMENT ────────────────────────────────────

#[test]
fn la_version_vient_en_premier() {
    // §6.3. C'est ce qui permet de distinguer un enregistrement DMARC d'un
    // `TXT` qui parle d'autre chose SANS lire le reste.
    assert_eq!(lire(b"p=reject; v=DMARC1"), Err(Error::NotDmarc));
    assert_eq!(lire(b"v=DMARC2; p=reject"), Err(Error::NotDmarc));
    assert_eq!(lire(b"v=; p=reject"), Err(Error::NotDmarc));
    assert_eq!(lire(b"p=reject"), Err(Error::NotDmarc));
    assert_eq!(lire(b""), Err(Error::NotDmarc));
    // Un TXT qui parle d'autre chose : refusé comme tous les autres, et c'est à
    // l'appelant de passer au suivant.
    assert_eq!(lire(b"v=spf1 -all"), Err(Error::NotDmarc));
    // La casse, elle, ne compte pas.
    assert!(lire(b"V=dmarc1; p=none").is_ok());
}

#[test]
fn un_enregistrement_sans_politique_est_ecarte() {
    // §6.6.3 : il ne demande rien, et ce qui ne demande rien n'est pas une
    // politique.
    assert_eq!(lire(b"v=DMARC1"), Err(Error::MissingPolicy));
    assert_eq!(lire(b"v=DMARC1; pct=100"), Err(Error::MissingPolicy));
    // `sp=` seule ne suffit pas non plus.
    assert_eq!(lire(b"v=DMARC1; sp=reject"), Err(Error::MissingPolicy));
}

#[test]
fn une_politique_inconnue_ne_se_rabat_pas_sur_none() {
    // Choisir à la place de celui qui l'a écrite est exactement ce que DMARC
    // existe pour éviter.
    assert_eq!(lire(b"v=DMARC1; p=refuse"), Err(Error::UnknownPolicy));
    assert_eq!(lire(b"v=DMARC1; p="), Err(Error::UnknownPolicy));
    assert_eq!(
        lire(b"v=DMARC1; p=none; sp=refuse"),
        Err(Error::UnknownPolicy)
    );
    assert_eq!(Policy::parse(b"REJECT").expect("lisible"), Policy::Reject);
}

#[test]
fn un_alignement_inconnu_est_refuse() {
    assert_eq!(
        lire(b"v=DMARC1; p=none; adkim=x"),
        Err(Error::UnknownAlignment)
    );
    assert_eq!(
        lire(b"v=DMARC1; p=none; aspf=x"),
        Err(Error::UnknownAlignment)
    );
}

#[test]
fn un_pourcentage_hors_bornes_est_refuse() {
    assert_eq!(
        lire(b"v=DMARC1; p=none; pct=101"),
        Err(Error::MalformedPercent)
    );
    assert_eq!(
        lire(b"v=DMARC1; p=none; pct=1000"),
        Err(Error::MalformedPercent)
    );
    assert_eq!(
        lire(b"v=DMARC1; p=none; pct=x"),
        Err(Error::MalformedPercent)
    );
    assert_eq!(
        lire(b"v=DMARC1; p=none; pct="),
        Err(Error::MalformedPercent)
    );
    assert_eq!(
        lire(b"v=DMARC1; p=none; pct=0").expect("lisible").percent,
        0
    );
    assert_eq!(
        lire(b"v=DMARC1; p=none; pct=100").expect("lisible").percent,
        100
    );
}

#[test]
fn un_intervalle_qui_deborde_est_refuse() {
    // Un intervalle qui repartirait de zéro ferait demander des rapports à
    // chaque seconde.
    assert_eq!(
        lire(b"v=DMARC1; p=none; ri=4294967295")
            .expect("lisible")
            .report_interval,
        u32::MAX
    );
    assert_eq!(
        lire(b"v=DMARC1; p=none; ri=4294967296"),
        Err(Error::MalformedInterval)
    );
    assert_eq!(
        lire(b"v=DMARC1; p=none; ri=x"),
        Err(Error::MalformedInterval)
    );
    assert_eq!(
        lire(b"v=DMARC1; p=none; ri="),
        Err(Error::MalformedInterval)
    );
}

#[test]
fn une_etiquette_en_double_est_refusee() {
    for doublon in [
        "p=none", "sp=none", "adkim=r", "aspf=r", "pct=50", "ri=60", "rua=x", "ruf=x",
    ] {
        let txt = std::format!("v=DMARC1; p=none; {doublon}; {doublon}");
        assert_eq!(lire(txt.as_bytes()), Err(Error::DuplicateTag), "{doublon}");
    }
}

#[test]
fn les_etiquettes_inconnues_s_ignorent() {
    // §6.3. `fo=` et `rf=` décrivent la forme des rapports, que ce serveur
    // n'envoie pas ; une étiquette future ne doit pas casser un vérificateur.
    let lu = lire(b"v=DMARC1; p=none; fo=1:d:s; rf=afrf; futur=demain").expect("lisible");
    assert_eq!(lu.policy, Policy::None);
}

#[test]
fn une_liste_mal_formee_remonte_telle_quelle() {
    assert_eq!(lire(b"v=DMARC1;; p=none"), Err(Error::MalformedTagList));
    // Y compris quand c'est la PREMIÈRE étiquette qui est fautive : on ne dit
    // pas « ce n'est pas du DMARC » d'un enregistrement qu'on n'a pas su lire.
    assert_eq!(lire(b"1=x"), Err(Error::MalformedTagName));
    assert_eq!(lire(b";; v=DMARC1"), Err(Error::MalformedTagList));
    assert_eq!(lire(b"v=DMARC1; 1=x"), Err(Error::MalformedTagName));
    assert_eq!(lire(b"v=DMARC1; p=\x01"), Err(Error::MalformedTagValue));
}

// ── LA POLITIQUE QUI S'APPLIQUE ─────────────────────────────────────────────

#[test]
fn un_sous_domaine_suit_sp_quand_il_existe() {
    // Sans cette distinction, un domaine qui protège ses sous-domaines
    // autrement que lui-même ne serait pas entendu.
    let avec = lire(b"v=DMARC1; p=none; sp=reject").expect("lisible");
    assert_eq!(avec.applicable(false), Policy::None);
    assert_eq!(avec.applicable(true), Policy::Reject);

    // Sans `sp=`, les sous-domaines suivent `p=`.
    let sans = lire(b"v=DMARC1; p=quarantine").expect("lisible");
    assert_eq!(sans.applicable(false), Policy::Quarantine);
    assert_eq!(sans.applicable(true), Policy::Quarantine);
}

#[test]
fn chaque_politique_porte_son_mot() {
    assert_eq!(Policy::None.name(), b"none");
    assert_eq!(Policy::Quarantine.name(), b"quarantine");
    assert_eq!(Policy::Reject.name(), b"reject");
    assert_eq!(Policy::default(), Policy::None);
}

// ── LE NOM OÙ CHERCHER ──────────────────────────────────────────────────────

#[test]
fn la_politique_se_cherche_sous_underscore_dmarc() {
    let mut sortie = [0_u8; POLICY_NAME_MAX];
    assert_eq!(
        policy_name(b"example.com", &mut sortie).expect("tient"),
        b"_dmarc.example.com"
    );
    // Un domaine vide donne un nom qui ne désigne rien — c'est à l'appelant de
    // ne pas le demander.
    assert_eq!(policy_name(b"", &mut sortie).expect("tient"), b"_dmarc.");
}

#[test]
fn un_domaine_trop_long_n_a_pas_de_nom_de_politique() {
    let mut sortie = [0_u8; POLICY_NAME_MAX];
    let long = std::vec![b'a'; 256];
    assert_eq!(policy_name(&long, &mut sortie), Err(Error::DomainTooLong));
}

#[test]
fn un_tampon_trop_petit_refuse_plutot_que_de_tronquer() {
    // Un nom tronqué désignerait un AUTRE domaine, et l'interroger rendrait la
    // politique de quelqu'un d'autre.
    for taille in 0..b"_dmarc.example.com".len() {
        let mut sortie = std::vec![0_u8; taille];
        assert_eq!(
            policy_name(b"example.com", &mut sortie),
            Err(Error::BufferTooSmall),
            "taille {taille}"
        );
    }
}

#[test]
fn les_types_se_deboguent_et_se_comparent() {
    let lu = lire(b"v=DMARC1; p=none").expect("lisible");
    let copie = lu;
    assert_eq!(copie, lu);
    assert!(!std::format!("{lu:?}").is_empty());
    assert!(!std::format!("{:?}", Policy::Reject).is_empty());
    assert_ne!(Policy::None, Policy::Reject);
}
