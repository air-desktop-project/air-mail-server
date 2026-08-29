//! Ce qu'un rapport agrégé dit, et ce qu'il refuse de dire.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{
    DkimAuth, DkimAuthResult, Metadata, Published, Row, SpfAuth, SpfAuthResult, SpfScope, begin,
};
use crate::alignment::Alignment;
use crate::record::Policy;
use crate::{Error, Verdict};

/// Les métadonnées les plus simples.
fn metadonnees() -> Metadata<'static> {
    Metadata {
        org_name: b"receveur.test",
        email: b"dmarc@receveur.test",
        extra_contact: None,
        report_id: b"7a3f",
        begin: 1_013_662_812,
        end: 1_013_749_130,
    }
}

/// La politique la plus simple.
fn politique() -> Published<'static> {
    Published {
        domain: b"example.com",
        dkim_alignment: Alignment::Relaxed,
        spf_alignment: Alignment::Relaxed,
        policy: Policy::None,
        subdomain_policy: None,
        percent: 100,
    }
}

/// La ligne la plus simple.
fn ligne() -> Row<'static> {
    Row {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        count: 3,
        disposition: Policy::None,
        dkim: Verdict::Fail,
        spf: Verdict::Pass,
        header_from: b"example.com",
        envelope_from: None,
        envelope_to: None,
        dkim_auth: &[],
        spf_auth: SpfAuth {
            domain: b"example.com",
            scope: SpfScope::MailFrom,
            result: SpfAuthResult::Pass,
        },
    }
}

/// Compose un rapport d'une ligne et rend le texte.
fn composer(
    tampon: &mut [u8],
    metadata: &Metadata<'_>,
    published: &Published<'_>,
    lignes: &[Row<'_>],
) -> Result<std::string::String, Error> {
    let mut rapport = begin(tampon, metadata, published)?;
    for une in lignes {
        rapport.record(une)?;
    }
    let octets = rapport.finish()?;
    Ok(std::string::String::from_utf8(octets.to_vec()).expect("de l'ASCII"))
}

#[test]
fn un_rapport_ordinaire_s_ecrit_comme_l_annexe_c_le_demande() {
    let mut tampon = [0_u8; 4096];
    let texte =
        composer(&mut tampon, &metadonnees(), &politique(), &[ligne()]).expect("composable");
    assert_eq!(
        texte,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <feedback>\n\
         \x20 <version>1.0</version>\n\
         \x20 <report_metadata>\n\
         \x20   <org_name>receveur.test</org_name>\n\
         \x20   <email>dmarc@receveur.test</email>\n\
         \x20   <report_id>7a3f</report_id>\n\
         \x20   <date_range>\n\
         \x20     <begin>1013662812</begin>\n\
         \x20     <end>1013749130</end>\n\
         \x20   </date_range>\n\
         \x20 </report_metadata>\n\
         \x20 <policy_published>\n\
         \x20   <domain>example.com</domain>\n\
         \x20   <adkim>r</adkim>\n\
         \x20   <aspf>r</aspf>\n\
         \x20   <p>none</p>\n\
         \x20   <pct>100</pct>\n\
         \x20 </policy_published>\n\
         \x20 <record>\n\
         \x20   <row>\n\
         \x20     <source_ip>192.0.2.1</source_ip>\n\
         \x20     <count>3</count>\n\
         \x20     <policy_evaluated>\n\
         \x20       <disposition>none</disposition>\n\
         \x20       <dkim>fail</dkim>\n\
         \x20       <spf>pass</spf>\n\
         \x20     </policy_evaluated>\n\
         \x20   </row>\n\
         \x20   <identifiers>\n\
         \x20     <header_from>example.com</header_from>\n\
         \x20   </identifiers>\n\
         \x20   <auth_results>\n\
         \x20     <spf>\n\
         \x20       <domain>example.com</domain>\n\
         \x20       <scope>mfrom</scope>\n\
         \x20       <result>pass</result>\n\
         \x20     </spf>\n\
         \x20   </auth_results>\n\
         \x20 </record>\n\
         </feedback>\n"
    );
}

#[test]
fn tout_ce_qui_est_facultatif_s_ecrit_quand_il_est_la() {
    let mut tampon = [0_u8; 4096];
    let metadata = Metadata {
        extra_contact: Some(b"https://receveur.test/dmarc"),
        ..metadonnees()
    };
    let published = Published {
        dkim_alignment: Alignment::Strict,
        spf_alignment: Alignment::Strict,
        policy: Policy::Reject,
        subdomain_policy: Some(Policy::Quarantine),
        percent: 25,
        ..politique()
    };
    let signatures = [
        DkimAuth {
            domain: b"example.com",
            selector: Some(b"selecteur"),
            result: DkimAuthResult::Pass,
        },
        DkimAuth {
            domain: b"autre.test",
            selector: None,
            result: DkimAuthResult::Fail,
        },
    ];
    let une = Row {
        source_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        disposition: Policy::Quarantine,
        envelope_from: Some(b"rebond.example.com"),
        envelope_to: Some(b"boite@receveur.test"),
        dkim_auth: &signatures,
        ..ligne()
    };
    let texte = composer(&mut tampon, &metadata, &published, &[une]).expect("composable");
    for morceau in [
        "<extra_contact_info>https://receveur.test/dmarc</extra_contact_info>",
        "<adkim>s</adkim>",
        "<aspf>s</aspf>",
        "<p>reject</p>",
        "<sp>quarantine</sp>",
        "<pct>25</pct>",
        "<source_ip>2001:db8::1</source_ip>",
        "<disposition>quarantine</disposition>",
        "<envelope_to>boite@receveur.test</envelope_to>",
        "<envelope_from>rebond.example.com</envelope_from>",
        "<selector>selecteur</selector>",
        "<result>pass</result>",
        "<result>fail</result>",
    ] {
        assert!(texte.contains(morceau), "{morceau} manque dans :\n{texte}");
    }
    // Une signature sans sélecteur n'en invente pas un.
    assert_eq!(texte.matches("<selector>").count(), 1);
}

/// **Ce qui entre ici vient du réseau.** Un `<` bien placé, et celui qu'on
/// rapporte écrirait le rapport.
#[test]
fn c_est_ici_que_l_injection_xml_s_arrete() {
    let mut tampon = [0_u8; 4096];
    let une = Row {
        header_from: b"</header_from><record>&faux;\"'",
        ..ligne()
    };
    let texte = composer(&mut tampon, &metadonnees(), &politique(), &[une]).expect("composable");
    assert!(texte.contains(
        "<header_from>&lt;/header_from&gt;&lt;record&gt;&amp;faux;&quot;&apos;</header_from>"
    ));
    assert_eq!(texte.matches("<record>").count(), 1);
}

/// Pas de remplacement silencieux : un rapport dont on ne sait pas ce qu'il dit
/// ne vaut pas mieux que pas de rapport.
#[test]
fn un_octet_qu_on_ne_sait_pas_ecrire_fait_refuser_le_rapport() {
    let mut tampon = [0_u8; 4096];
    let une = Row {
        header_from: b"exa\xffmple.com",
        ..ligne()
    };
    assert_eq!(
        composer(&mut tampon, &metadonnees(), &politique(), &[une]),
        Err(Error::NotPrintable)
    );
    let metadata = Metadata {
        org_name: b"rece\nveur",
        ..metadonnees()
    };
    assert_eq!(
        composer(&mut tampon, &metadata, &politique(), &[ligne()]),
        Err(Error::NotPrintable)
    );
}

/// L'annexe C exige au moins un `record` : un rapport vide n'est pas « rien à
/// signaler », c'est un document que le destinataire jettera sans le dire.
#[test]
fn un_rapport_sans_ligne_n_est_pas_un_rapport() {
    let mut tampon = [0_u8; 4096];
    assert_eq!(
        composer(&mut tampon, &metadonnees(), &politique(), &[]),
        Err(Error::EmptyReport)
    );
}

#[test]
fn plusieurs_lignes_se_suivent() {
    let mut tampon = [0_u8; 8192];
    let texte = composer(
        &mut tampon,
        &metadonnees(),
        &politique(),
        &[ligne(), ligne(), ligne()],
    )
    .expect("composable");
    assert_eq!(texte.matches("<record>").count(), 3);
}

/// Le tampon est celui de l'appelant, et **il peut céder n'importe où** : à
/// l'ouverture, au milieu d'un nombre, au milieu d'une adresse IPv6, sur une
/// entité XML, à la fermeture.
///
/// On ne choisit donc pas quelques tailles au hasard : on les essaie TOUTES,
/// de zéro à un octet de moins qu'il n'en faut. Chacune doit rendre la même
/// chose — pas un rapport tronqué, pas une panique : `BufferTooSmall`.
#[test]
fn un_tampon_trop_court_le_dit_ou_qu_il_cede() {
    let (metadata, published, signatures) = tout_le_bataclan();
    let une = ligne_complete(&signatures);
    let mut assez = [0_u8; 4096];
    let entier = composer(&mut assez, &metadata, &published, &[une]).expect("composable");
    for taille in 0..entier.len() {
        let mut tampon = std::vec![0_u8; taille];
        assert_eq!(
            composer(&mut tampon, &metadata, &published, &[une]),
            Err(Error::BufferTooSmall),
            "taille {taille}"
        );
    }
    let mut juste = std::vec![0_u8; entier.len()];
    assert_eq!(
        composer(&mut juste, &metadata, &published, &[une]).expect("composable"),
        entier
    );
}

/// Un rapport qui porte tout ce qui est facultatif, et tout ce qui s'échappe.
fn tout_le_bataclan() -> (
    Metadata<'static>,
    Published<'static>,
    [DkimAuth<'static>; 2],
) {
    (
        Metadata {
            extra_contact: Some(b"https://receveur.test/dmarc"),
            ..metadonnees()
        },
        Published {
            subdomain_policy: Some(Policy::Quarantine),
            percent: 25,
            ..politique()
        },
        [
            DkimAuth {
                domain: b"example.com",
                selector: Some(b"selecteur"),
                result: DkimAuthResult::Pass,
            },
            DkimAuth {
                domain: b"autre.test",
                selector: None,
                result: DkimAuthResult::Fail,
            },
        ],
    )
}

/// Une ligne qui porte tout, adresse IPv6 et entités comprises.
fn ligne_complete<'a>(signatures: &'a [DkimAuth<'a>]) -> Row<'a> {
    Row {
        source_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        count: 1234,
        header_from: b"a&b<c>d\"e'f.test",
        envelope_from: Some(b"rebond.example.com"),
        envelope_to: Some(b"boite@receveur.test"),
        dkim_auth: signatures,
        ..ligne()
    }
}

#[test]
fn chaque_resultat_a_son_mot() {
    let mut tampon = [0_u8; 4096];
    for (resultat, mot) in [
        (DkimAuthResult::None, "none"),
        (DkimAuthResult::Pass, "pass"),
        (DkimAuthResult::Fail, "fail"),
        (DkimAuthResult::Policy, "policy"),
        (DkimAuthResult::Neutral, "neutral"),
        (DkimAuthResult::TempError, "temperror"),
        (DkimAuthResult::PermError, "permerror"),
    ] {
        let signatures = [DkimAuth {
            domain: b"x.test",
            selector: None,
            result: resultat,
        }];
        let une = Row {
            dkim_auth: &signatures,
            ..ligne()
        };
        let texte =
            composer(&mut tampon, &metadonnees(), &politique(), &[une]).expect("composable");
        assert!(
            texte.contains(&std::format!("<result>{mot}</result>")),
            "{resultat:?}"
        );
        assert_eq!(resultat, resultat);
    }
    for (resultat, mot) in [
        (SpfAuthResult::None, "none"),
        (SpfAuthResult::Neutral, "neutral"),
        (SpfAuthResult::Pass, "pass"),
        (SpfAuthResult::Fail, "fail"),
        (SpfAuthResult::SoftFail, "softfail"),
        (SpfAuthResult::TempError, "temperror"),
        (SpfAuthResult::PermError, "permerror"),
    ] {
        let une = Row {
            spf_auth: SpfAuth {
                domain: b"x.test",
                scope: SpfScope::Helo,
                result: resultat,
            },
            ..ligne()
        };
        let texte =
            composer(&mut tampon, &metadonnees(), &politique(), &[une]).expect("composable");
        assert!(
            texte.contains(&std::format!("<result>{mot}</result>")),
            "{resultat:?}"
        );
        assert!(texte.contains("<scope>helo</scope>"));
        assert_eq!(resultat, resultat);
    }
}

#[test]
fn ce_qui_se_compose_se_montre() {
    let mut tampon = [0_u8; 4096];
    let rapport = begin(&mut tampon, &metadonnees(), &politique()).expect("ouvrable");
    assert!(!std::format!("{rapport:?}").is_empty());
    assert!(!std::format!("{:?}", metadonnees()).is_empty());
    assert!(!std::format!("{:?}", politique()).is_empty());
    assert!(!std::format!("{:?}", ligne()).is_empty());
    assert!(!std::format!("{:?}", SpfScope::MailFrom).is_empty());
    assert_eq!(SpfScope::MailFrom, SpfScope::MailFrom);
    assert_ne!(SpfScope::MailFrom, SpfScope::Helo);
}
