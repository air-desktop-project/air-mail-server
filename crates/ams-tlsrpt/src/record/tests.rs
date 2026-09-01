//! Ce qu'un `_smtp._tls` demande, et ce qu'on refuse d'y lire.

use super::{Destination, RUA_MAX, Transport, parse_record};
use crate::Error;

/// Les destinations d'un enregistrement, sous une forme qu'un essai lit.
fn lire(txt: &str) -> Result<std::vec::Vec<(Transport, std::string::String)>, Error> {
    let mut place = [Destination::EMPTY; RUA_MAX + 1];
    parse_record(txt, &mut place).map(|vues| {
        vues.iter()
            .map(|une| (une.transport(), std::string::String::from(une.target())))
            .collect()
    })
}

#[test]
fn un_enregistrement_ordinaire_se_lit() {
    let vues = lire("v=TLSRPTv1; rua=mailto:tls@example.com").expect("lisible");
    assert_eq!(vues.len(), 1);
    assert_eq!(vues[0].0, Transport::Mailto);
    assert_eq!(vues[0].1, "tls@example.com");
}

/// §3 : les destinations d'un même `rua` sont séparées par des VIRGULES.
#[test]
fn plusieurs_destinations_se_lisent() {
    let vues =
        lire("v=TLSRPTv1; rua=mailto:a@x.test,https://y.test/v1,mailto:b@z.test").expect("lisible");
    assert_eq!(vues.len(), 3);
    assert_eq!(vues[0].0, Transport::Mailto);
    assert_eq!(vues[1].0, Transport::Https);
    assert_eq!(vues[1].1, "https://y.test/v1");
    assert_eq!(vues[2].1, "b@z.test");
}

/// **§3 : `v=TLSRPTv1` VIENT EN PREMIER.**
#[test]
fn la_version_doit_venir_en_premier() {
    for txt in [
        "rua=mailto:a@x.test; v=TLSRPTv1",
        "v=TLSRPTv2; rua=mailto:a@x.test",
        "v=tlsrptv1; rua=mailto:a@x.test",
        "rua=mailto:a@x.test",
        "",
        // Un `TXT` du domaine qui parle d'autre chose.
        "v=spf1 -all",
    ] {
        assert_eq!(lire(txt), Err(Error::BadRecord), "« {txt} »");
    }
}

#[test]
fn un_enregistrement_sans_destination_est_refuse() {
    for txt in ["v=TLSRPTv1", "v=TLSRPTv1; autre=chose"] {
        assert_eq!(lire(txt), Err(Error::BadRecord), "« {txt} »");
    }
}

/// **UNE DESTINATION QU'ON NE SAIT PAS LIRE FAIT TOUT REFUSER.**
///
/// L'écarter en silence enverrait le rapport à moins de monde que le domaine ne
/// l'a demandé, et rien ne le lui dirait.
#[test]
fn une_destination_illisible_fait_tout_refuser() {
    for mauvaise in [
        // `http://` n'est pas `https://` (§3).
        "http://x.test/v1",
        "ftp://x.test/",
        "x.test",
        "mailto:",
        // Une adresse sans arobase n'en est pas une.
        "mailto:pasunadresse",
        "mailto:a b@x.test",
        // Une URL sans autorité.
        "https://",
        "https:///chemin",
        // Une autorité avec utilisateur : `https://x@evil.test/` désignerait
        // `evil.test`, et le lire comme `x` ferait vérifier le mauvais domaine.
        "https://x@evil.test/v1",
        "https://x.test:8443/v1",
        // Une espace : de l'ASCII, mais pas de l'ASCII GRAPHIQUE.
        "https://x.test/a b",
        // **UN « DOMAINE » QUI N'EN EST PAS UN.** `mailto:a@b/c` rendait `b/c`,
        // de quoi interroger un nom qui n'existe pas. Trouvé par le fuzz.
        "mailto:a@b/c",
        "mailto:a@",
        "mailto:a@.b.test",
        "mailto:a@b.test.",
        "mailto:a@b_c.test",
        "https://x_y.test/v1",
        "",
    ] {
        let txt = std::format!("v=TLSRPTv1; rua=mailto:bon@x.test,{mauvaise}");
        assert_eq!(lire(&txt), Err(Error::BadRecord), "« {mauvaise} »");
    }
}

#[test]
fn un_domaine_se_tire_de_chaque_transport() {
    let mut place = [Destination::EMPTY; 4];
    let vues = parse_record(
        "v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.net/v1/x",
        &mut place,
    )
    .expect("lisible");
    assert_eq!(vues[0].domain(), Some("example.com"));
    assert_eq!(vues[1].domain(), Some("reports.example.net"));
    // Une partie locale qui porte une arobase : c'est le DERNIER qui sépare.
    let mut place = [Destination::EMPTY; 2];
    let vues = parse_record("v=TLSRPTv1; rua=mailto:a@b@example.com", &mut place).expect("lisible");
    assert_eq!(vues[0].domain(), Some("example.com"));
}

/// **UNE CLEF QU'ON NE CONNAÎT PAS SE SAUTE.**
///
/// §3 réserve l'extension : un champ de demain ne doit pas faire perdre les
/// destinations d'aujourd'hui.
#[test]
fn une_clef_inconnue_se_saute() {
    let vues = lire("v=TLSRPTv1; futur=42; rua=mailto:a@x.test; autre=chose").expect("lisible");
    assert_eq!(vues.len(), 1);
}

/// **UN ENREGISTREMENT PLUS GARNI QUE LA PLACE EST REFUSÉ, PAS TRONQUÉ.**
#[test]
fn plus_de_destinations_que_la_place_est_refuse() {
    let liste: std::vec::Vec<std::string::String> = (0..5)
        .map(|rang| std::format!("mailto:a{rang}@x.test"))
        .collect();
    let txt = std::format!("v=TLSRPTv1; rua={}", liste.join(","));
    let mut trop_petite = [Destination::EMPTY; 4];
    assert_eq!(parse_record(&txt, &mut trop_petite), Err(Error::BadRecord));
    let mut juste = [Destination::EMPTY; 5];
    assert_eq!(parse_record(&txt, &mut juste).expect("lisible").len(), 5);
}

/// **LA BORNE DE C3 EST CELLE DE LA CRATE**, et non celle de l'appelant : sans
/// elle, un domaine dicterait combien de messages on émet pour lui.
#[test]
fn plus_de_destinations_que_la_borne_est_refuse() {
    let liste: std::vec::Vec<std::string::String> = (0..=RUA_MAX)
        .map(|rang| std::format!("mailto:a{rang}@x.test"))
        .collect();
    let txt = std::format!("v=TLSRPTv1; rua={}", liste.join(","));
    let mut place = [Destination::EMPTY; RUA_MAX * 2];
    assert_eq!(parse_record(&txt, &mut place), Err(Error::BadRecord));
}

#[test]
fn une_destination_demesuree_est_refusee() {
    let longue = "a".repeat(600);
    let txt = std::format!("v=TLSRPTv1; rua=mailto:{longue}@x.test");
    assert_eq!(lire(&txt), Err(Error::BadRecord));
}

#[test]
fn les_types_se_copient_et_se_deboguent() {
    let mut place = [Destination::EMPTY; 2];
    let vues = parse_record("v=TLSRPTv1; rua=mailto:a@x.test", &mut place).expect("lisible");
    let une = vues[0];
    let copie = une;
    assert_eq!(copie, une);
    assert!(!std::format!("{une:?}").is_empty());
    assert!(!std::format!("{:?}", Transport::Https).is_empty());
    assert_ne!(Transport::Https, Transport::Mailto);
    assert_ne!(une, Destination::EMPTY);
    assert!(!std::format!("{:?}", Error::BadRecord).is_empty());
    assert_ne!(Error::BadRecord, Error::NotPrintable);
}
