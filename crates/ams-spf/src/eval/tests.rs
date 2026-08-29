//! Ce que l'évaluation doit tenir.

use super::{Answer, Evaluator, Query, Step, Verdict};
use crate::Limits;
use crate::macros::Context;
use core::net::{IpAddr, Ipv4Addr};

/// Une zone DNS de test : ce que chaque nom répond, question par question.
struct Zone {
    txt: std::vec::Vec<(&'static str, std::vec::Vec<&'static str>)>,
    adresses: std::vec::Vec<(&'static str, std::vec::Vec<IpAddr>)>,
    mx: std::vec::Vec<(&'static str, std::vec::Vec<IpAddr>)>,
    existe: std::vec::Vec<&'static str>,
    noms_inverses: Option<std::vec::Vec<&'static str>>,
    /// Les noms dont la résolution elle-même n'aboutit pas.
    introuvables: std::vec::Vec<&'static str>,
    /// Les noms qui font échouer la résolution.
    tempo: std::vec::Vec<&'static str>,
    /// Les questions posées, dans l'ordre.
    posees: std::cell::RefCell<std::vec::Vec<(Query, std::string::String)>>,
}

impl Zone {
    fn nouvelle() -> Self {
        Self {
            txt: std::vec::Vec::new(),
            adresses: std::vec::Vec::new(),
            mx: std::vec::Vec::new(),
            existe: std::vec::Vec::new(),
            noms_inverses: None,
            introuvables: std::vec::Vec::new(),
            tempo: std::vec::Vec::new(),
            posees: std::cell::RefCell::new(std::vec::Vec::new()),
        }
    }

    fn avec_txt(mut self, nom: &'static str, records: &[&'static str]) -> Self {
        self.txt.push((nom, records.to_vec()));
        self
    }

    fn avec_adresses(mut self, nom: &'static str, adresses: &[IpAddr]) -> Self {
        self.adresses.push((nom, adresses.to_vec()));
        self
    }

    fn avec_mx(mut self, nom: &'static str, adresses: &[IpAddr]) -> Self {
        self.mx.push((nom, adresses.to_vec()));
        self
    }

    fn avec_existant(mut self, nom: &'static str) -> Self {
        self.existe.push(nom);
        self
    }

    fn avec_noms_inverses(mut self, noms: &[&'static str]) -> Self {
        self.noms_inverses = Some(noms.to_vec());
        self
    }

    /// Un nom dont la résolution rend « n'existe pas », quelle que soit la
    /// question posée.
    fn avec_introuvable(mut self, nom: &'static str) -> Self {
        self.introuvables.push(nom);
        self
    }

    fn avec_panne(mut self, nom: &'static str) -> Self {
        self.tempo.push(nom);
        self
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// Évalue jusqu'au verdict, en résolvant sur la zone.
fn evaluer_avec(zone: &Zone, domaine: &str, client: IpAddr, limits: Limits) -> Verdict {
    let contexte = Context {
        client,
        sender: b"jean@example.com",
        helo: b"mx.example.com",
    };
    let mut evaluateur = Evaluator::new(contexte, domaine.as_bytes(), limits);
    // Un garde-fou : une machine qui ne conclut pas est un défaut, pas un test
    // qui tourne longtemps.
    for _ in 0..200 {
        let question = match evaluateur.poll() {
            Step::Done(verdict) => return verdict,
            Step::Ask(question) => question,
        };
        let nom = std::string::String::from_utf8_lossy(question.name()).into_owned();
        zone.posees
            .borrow_mut()
            .push((question.kind(), nom.clone()));

        if zone.tempo.iter().any(|panne| *panne == nom) {
            evaluateur.answer(Answer::TempError);
            continue;
        }
        if zone.introuvables.iter().any(|absent| *absent == nom) {
            evaluateur.answer(Answer::NotFound);
            continue;
        }
        match question.kind() {
            Query::Txt => match zone.txt.iter().find(|(connu, _)| *connu == nom) {
                Some((_, records)) => {
                    let empruntes: std::vec::Vec<&[u8]> =
                        records.iter().map(|texte| texte.as_bytes()).collect();
                    evaluateur.answer(Answer::Txt(&empruntes));
                }
                None => evaluateur.answer(Answer::NotFound),
            },
            Query::Addresses => match zone.adresses.iter().find(|(connu, _)| *connu == nom) {
                Some((_, adresses)) => evaluateur.answer(Answer::Addresses(adresses)),
                None => evaluateur.answer(Answer::NotFound),
            },
            Query::MxAddresses => match zone.mx.iter().find(|(connu, _)| *connu == nom) {
                Some((_, adresses)) => evaluateur.answer(Answer::Addresses(adresses)),
                None => evaluateur.answer(Answer::NotFound),
            },
            Query::Exists => {
                evaluateur.answer(Answer::Exists(
                    zone.existe.iter().any(|connu| *connu == nom),
                ));
            }
            Query::PtrNames => match &zone.noms_inverses {
                Some(noms) => {
                    let empruntes: std::vec::Vec<&[u8]> =
                        noms.iter().map(|texte| texte.as_bytes()).collect();
                    evaluateur.answer(Answer::Names(&empruntes));
                }
                None => evaluateur.answer(Answer::NotFound),
            },
        }
    }
    panic!("l'évaluation n'a pas conclu en deux cents tours");
}

fn evaluer(zone: &Zone, domaine: &str, client: IpAddr) -> Verdict {
    evaluer_avec(zone, domaine, client, Limits::DEFAULT)
}

// ── Les cas simples ─────────────────────────────────────────────────────────

#[test]
fn sans_enregistrement_le_domaine_ne_dit_rien() {
    // `none` N'EST PAS UN REFUS : un domaine qui n'a pas publié de politique
    // n'autorise ni n'interdit. Le confondre avec `fail` refuserait le courrier
    // de la moitié d'internet.
    let zone = Zone::nouvelle();
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::None
    );
}

#[test]
fn un_txt_qui_parle_d_autre_chose_ne_compte_pas() {
    let zone = Zone::nouvelle().avec_txt("example.com", &["google-site-verification=x"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::None
    );
}

#[test]
fn ip4_decide_sans_aucune_resolution() {
    let zone = Zone::nouvelle().avec_txt("example.com", &["v=spf1 ip4:192.0.2.0/24 -all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 7)),
        Verdict::Pass
    );
    assert_eq!(
        evaluer(&zone, "example.com", v4(198, 51, 100, 7)),
        Verdict::Fail
    );
    // Et une seule question a été posée : celle de la politique elle-même.
    assert_eq!(zone.posees.borrow().len(), 2);
}

#[test]
fn les_quatre_qualificateurs_donnent_les_quatre_verdicts() {
    for (politique, attendu) in [
        ("v=spf1 +all", Verdict::Pass),
        ("v=spf1 -all", Verdict::Fail),
        ("v=spf1 ~all", Verdict::SoftFail),
        ("v=spf1 ?all", Verdict::Neutral),
    ] {
        let zone = Zone::nouvelle().avec_txt("example.com", &[politique]);
        assert_eq!(
            evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
            attendu,
            "{politique}"
        );
    }
}

#[test]
fn sans_mecanisme_correspondant_le_defaut_est_neutre() {
    // RFC 7208 §4.7 : comme si l'enregistrement finissait par `?all`.
    let zone = Zone::nouvelle().avec_txt("example.com", &["v=spf1 ip4:198.51.100.0/24"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Neutral
    );
}

#[test]
fn deux_politiques_sont_une_question_sans_reponse() {
    // RFC 7208 §4.5 : `permerror`. Choisir à la place de l'auteur serait pire.
    let zone = Zone::nouvelle().avec_txt("example.com", &["v=spf1 +all", "v=spf1 -all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::PermError
    );
}

#[test]
fn une_politique_mal_formee_vaut_permerror() {
    let zone = Zone::nouvelle().avec_txt("example.com", &["v=spf1 xyzzy -all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::PermError
    );
}

#[test]
fn une_resolution_en_panne_vaut_temperror() {
    // `temperror` DIT AU PAIR DE RÉESSAYER. Le confondre avec `permerror`
    // ferait jeter un message qui serait passé cinq minutes plus tard.
    let zone = Zone::nouvelle().avec_panne("example.com");
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::TempError
    );
}

// ── Les mécanismes qui résolvent ────────────────────────────────────────────

#[test]
fn a_compare_les_adresses_du_domaine() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 a -all"])
        .avec_adresses("example.com", &[v4(192, 0, 2, 7)]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 7)),
        Verdict::Pass
    );
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 8)),
        Verdict::Fail
    );
}

#[test]
fn a_avec_un_prefixe_compare_un_reseau() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 a/24 -all"])
        .avec_adresses("example.com", &[v4(192, 0, 2, 7)]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 200)),
        Verdict::Pass
    );
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 3, 1)),
        Verdict::Fail
    );
}

#[test]
fn a_avec_un_domaine_interroge_celui_la() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 a:relais.example.net -all"])
        .avec_adresses("relais.example.net", &[v4(198, 51, 100, 1)]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(198, 51, 100, 1)),
        Verdict::Pass
    );
    assert_eq!(
        zone.posees.borrow()[1],
        (
            Query::Addresses,
            std::string::String::from("relais.example.net")
        )
    );
}

#[test]
fn mx_demande_les_adresses_des_serveurs_de_courrier() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 mx -all"])
        .avec_mx("example.com", &[v4(192, 0, 2, 25)]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 25)),
        Verdict::Pass
    );
    assert_eq!(zone.posees.borrow()[1].0, Query::MxAddresses);
}

#[test]
fn exists_ne_regarde_que_la_presence() {
    // Le contenu de l'enregistrement ne compte pas : c'est son EXISTENCE qui
    // répond (RFC 7208 §5.7).
    let zone = Zone::nouvelle()
        .avec_txt(
            "example.com",
            &["v=spf1 exists:%{ir}.liste.example.net -all"],
        )
        .avec_existant("1.2.0.192.liste.example.net");
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );
    // La macro a bien été développée AVANT la question.
    assert_eq!(
        zone.posees.borrow()[1],
        (
            Query::Exists,
            std::string::String::from("1.2.0.192.liste.example.net")
        )
    );
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 9)),
        Verdict::Fail
    );
}

#[test]
fn ptr_exige_que_le_nom_soit_sous_le_domaine() {
    // RFC 7208 §5.5 : le nom doit être le domaine ou l'un de ses sous-domaines,
    // et la résolution inverse doit être confirmée — c'est l'appelant qui le
    // fait, et `Query::PtrNames` le dit.
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 ptr -all"])
        .avec_noms_inverses(&["mx.example.com"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );

    // `badexample.com` finit par `example.com` sans être dessous : le point
    // compte, et l'oublier autoriserait qui enregistre un nom qui finit par le
    // nôtre.
    let piege = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 ptr -all"])
        .avec_noms_inverses(&["badexample.com"]);
    assert_eq!(
        evaluer(&piege, "example.com", v4(192, 0, 2, 1)),
        Verdict::Fail
    );
}

// ── `include` ───────────────────────────────────────────────────────────────

#[test]
fn include_correspond_si_et_seulement_si_la_politique_incluse_passe() {
    // RFC 7208 §5.2. C'est la règle la plus contre-intuitive de SPF : un
    // `include` qui rend `fail` ne fait PAS échouer, il ne correspond pas.
    let base = |incluse: &'static str| {
        Zone::nouvelle()
            .avec_txt("example.com", &["v=spf1 include:tiers.example.net ~all"])
            .avec_txt("tiers.example.net", &[incluse])
    };
    assert_eq!(
        evaluer(
            &base("v=spf1 ip4:192.0.2.0/24 -all"),
            "example.com",
            v4(192, 0, 2, 1)
        ),
        Verdict::Pass
    );
    // La politique incluse dit `fail` : l'`include` ne correspond pas, et c'est
    // le `~all` de l'appelante qui décide.
    assert_eq!(
        evaluer(&base("v=spf1 -all"), "example.com", v4(192, 0, 2, 1)),
        Verdict::SoftFail
    );
    // Elle dit `neutral` : même chose.
    assert_eq!(
        evaluer(&base("v=spf1 ?all"), "example.com", v4(192, 0, 2, 1)),
        Verdict::SoftFail
    );
}

#[test]
fn le_qualificateur_de_l_include_est_celui_qui_decide() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 -include:tiers.example.net +all"])
        .avec_txt("tiers.example.net", &["v=spf1 +all"]);
    // L'incluse passe, donc l'`include` correspond, donc son `-` décide.
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Fail
    );
}

#[test]
fn un_include_vers_un_domaine_sans_politique_vaut_permerror() {
    // RFC 7208 §5.2. C'est différent du départ, où l'absence vaut `none` : ici,
    // une politique en désigne une qui n'existe pas.
    let zone =
        Zone::nouvelle().avec_txt("example.com", &["v=spf1 include:absent.example.net -all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::PermError
    );
}

#[test]
fn un_include_imbrique_remonte_son_verdict() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 include:un.example.net -all"])
        .avec_txt("un.example.net", &["v=spf1 include:deux.example.net -all"])
        .avec_txt("deux.example.net", &["v=spf1 ip4:192.0.2.0/24 -all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );
    assert_eq!(
        evaluer(&zone, "example.com", v4(198, 51, 100, 1)),
        Verdict::Fail
    );
}

#[test]
fn une_panne_dans_un_include_remonte_en_temperror() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 include:tiers.example.net -all"])
        .avec_panne("tiers.example.net");
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::TempError
    );
}

// ── `redirect=` ─────────────────────────────────────────────────────────────

#[test]
fn redirect_remplace_la_politique() {
    // RFC 7208 §6.1 : son verdict devient le nôtre, qualificateurs compris.
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 redirect=vrai.example.net"])
        .avec_txt("vrai.example.net", &["v=spf1 ip4:192.0.2.0/24 -all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );
    assert_eq!(
        evaluer(&zone, "example.com", v4(198, 51, 100, 1)),
        Verdict::Fail
    );
}

#[test]
fn redirect_ne_s_applique_qu_apres_les_mecanismes() {
    // Un mécanisme qui correspond décide, et la redirection n'a pas lieu.
    let zone = Zone::nouvelle()
        .avec_txt(
            "example.com",
            &["v=spf1 ip4:192.0.2.0/24 redirect=vrai.example.net"],
        )
        .avec_txt("vrai.example.net", &["v=spf1 -all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );
    // Une seule question : la redirection n'a jamais été posée.
    assert_eq!(zone.posees.borrow().len(), 1);
}

#[test]
fn un_redirect_vers_un_domaine_sans_politique_vaut_permerror() {
    // RFC 7208 §6.1, et c'est la même logique que pour `include` : une politique
    // en désigne une qui n'existe pas.
    let zone = Zone::nouvelle().avec_txt("example.com", &["v=spf1 redirect=absent.example.net"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::PermError
    );
}

// ── LES LIMITES ─────────────────────────────────────────────────────────────

#[test]
fn la_limite_des_dix_resolutions_est_tenue() {
    // RFC 7208 §4.6.4. SANS ELLE, UN ENREGISTREMENT HOSTILE FAIT TRAVAILLER LE
    // RÉSOLVEUR D'AUTRUI : une chaîne d'`include` transforme un message en
    // autant de requêtes payées par celui qui le reçoit.
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 include:c1.example.net -all"])
        .avec_txt("c1.example.net", &["v=spf1 include:c2.example.net -all"])
        .avec_txt("c2.example.net", &["v=spf1 include:c3.example.net -all"])
        .avec_txt("c3.example.net", &["v=spf1 include:c4.example.net -all"])
        .avec_txt("c4.example.net", &["v=spf1 include:c5.example.net -all"])
        .avec_txt("c5.example.net", &["v=spf1 include:c6.example.net -all"])
        .avec_txt("c6.example.net", &["v=spf1 include:c7.example.net -all"])
        .avec_txt("c7.example.net", &["v=spf1 include:c8.example.net -all"])
        .avec_txt("c8.example.net", &["v=spf1 include:c9.example.net -all"])
        .avec_txt("c9.example.net", &["v=spf1 include:c10.example.net -all"])
        .avec_txt("c10.example.net", &["v=spf1 include:c11.example.net -all"])
        .avec_txt("c11.example.net", &["v=spf1 +all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::PermError
    );
    // Onze questions au plus : la politique de départ, puis dix résolutions.
    assert!(
        zone.posees.borrow().len() <= 11,
        "{} questions posées",
        zone.posees.borrow().len()
    );
}

#[test]
fn la_limite_se_baisse_et_reste_tenue() {
    let serrees = Limits {
        max_lookups: 2,
        ..Limits::DEFAULT
    };
    let zone = Zone::nouvelle().avec_txt(
        "example.com",
        &["v=spf1 a:un.example a:deux.example a:trois.example -all"],
    );
    assert_eq!(
        evaluer_avec(&zone, "example.com", v4(192, 0, 2, 1), serrees),
        Verdict::PermError
    );
    // La politique, puis DEUX résolutions, et pas une de plus.
    assert_eq!(zone.posees.borrow().len(), 3);
}

#[test]
fn la_limite_des_deux_resolutions_vides_est_tenue() {
    // RFC 7208 §4.6.4 : une politique qui accumule les noms inexistants est
    // soit fautive, soit hostile.
    let zone = Zone::nouvelle().avec_txt(
        "example.com",
        &["v=spf1 a:un.absent a:deux.absent a:trois.absent -all"],
    );
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::PermError
    );
    // Deux vides passent, la troisième arrête.
    assert_eq!(zone.posees.borrow().len(), 4);
}

#[test]
fn deux_resolutions_vides_ne_suffisent_pas_a_arreter() {
    let zone = Zone::nouvelle().avec_txt(
        "example.com",
        &["v=spf1 a:un.absent a:deux.absent ip4:192.0.2.0/24 -all"],
    );
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );
}

#[test]
fn un_domaine_plus_long_qu_un_nom_est_refuse_tout_de_suite() {
    let zone = Zone::nouvelle();
    let long = "a".repeat(300);
    assert_eq!(evaluer(&zone, &long, v4(192, 0, 2, 1)), Verdict::PermError);
    // Aucune question n'a été posée : rien n'était interrogeable.
    assert!(zone.posees.borrow().is_empty());
}

#[test]
fn une_macro_mal_formee_dans_un_mecanisme_vaut_permerror() {
    let zone = Zone::nouvelle().avec_txt("example.com", &["v=spf1 exists:%{z} -all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::PermError
    );
}

// ── Le contrat avec l'appelant ──────────────────────────────────────────────

#[test]
fn rappeler_poll_sans_repondre_rend_la_meme_question() {
    // L'appelant qui recommence son tour de boucle ne doit pas perdre sa place.
    let contexte = Context {
        client: v4(192, 0, 2, 1),
        sender: b"jean@example.com",
        helo: b"mx.example.com",
    };
    let mut evaluateur = Evaluator::new(contexte, b"example.com", Limits::DEFAULT);
    let Step::Ask(premiere) = evaluateur.poll() else {
        panic!("une question était attendue");
    };
    let Step::Ask(seconde) = evaluateur.poll() else {
        panic!("la même question était attendue");
    };
    assert_eq!(premiere.kind(), seconde.kind());
    assert_eq!(premiere.name(), seconde.name());
    assert_eq!(premiere.name(), b"example.com");
    assert!(!std::format!("{premiere:?}").is_empty());
}

#[test]
fn une_reponse_qui_ne_repond_pas_a_la_question_vaut_permerror() {
    // Un défaut de l'appelant. Le taire ferait conclure sur du vent.
    let contexte = Context {
        client: v4(192, 0, 2, 1),
        sender: b"jean@example.com",
        helo: b"mx.example.com",
    };
    let mut evaluateur = Evaluator::new(contexte, b"example.com", Limits::DEFAULT);
    let _ = evaluateur.poll();
    evaluateur.answer(Answer::Exists(true));
    assert!(matches!(evaluateur.poll(), Step::Done(Verdict::PermError)));
}

#[test]
fn une_reponse_qu_on_n_attendait_pas_ne_change_rien() {
    let contexte = Context {
        client: v4(192, 0, 2, 1),
        sender: b"jean@example.com",
        helo: b"mx.example.com",
    };
    let mut evaluateur = Evaluator::new(contexte, b"example.com", Limits::DEFAULT);
    // Avant tout `poll`, il n'y a pas de question en attente.
    evaluateur.answer(Answer::NotFound);
    let Step::Ask(question) = evaluateur.poll() else {
        panic!("une question était attendue");
    };
    assert_eq!(question.kind(), Query::Txt);
}

#[test]
fn la_question_du_ptr_ne_porte_pas_de_nom() {
    // Elle porte sur l'ADRESSE du pair, que l'appelant connaît déjà : lui rendre
    // un nom qui n'a pas servi l'inviterait à s'en servir.
    let zone = Zone::nouvelle().avec_txt("example.com", &["v=spf1 ptr -all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Fail
    );
    assert_eq!(
        zone.posees.borrow()[1],
        (Query::PtrNames, std::string::String::new())
    );
}

#[test]
fn les_types_se_deboguent_et_se_comparent() {
    assert_ne!(Verdict::Pass, Verdict::Fail);
    assert_eq!(Verdict::Pass, Verdict::Pass);
    assert_ne!(Query::Txt, Query::Exists);
    assert!(!std::format!("{:?}", Verdict::SoftFail).is_empty());
    assert!(!std::format!("{:?}", Answer::NotFound).is_empty());
    assert!(!std::format!("{:?}", Step::Done(Verdict::None)).is_empty());
}

// ── Les familles d'adresses ─────────────────────────────────────────────────

fn v6(texte: &str) -> IpAddr {
    IpAddr::V6(texte.parse().expect("adresse IPv6"))
}

#[test]
fn a_compare_aussi_les_adresses_ipv6() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 a -all"])
        .avec_adresses("example.com", &[v6("2001:db8::25")]);
    assert_eq!(
        evaluer(&zone, "example.com", v6("2001:db8::25")),
        Verdict::Pass
    );
    assert_eq!(
        evaluer(&zone, "example.com", v6("2001:db8::26")),
        Verdict::Fail
    );
}

#[test]
fn a_avec_un_prefixe_ipv6_compare_un_reseau() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 a//64 -all"])
        .avec_adresses("example.com", &[v6("2001:db8::1")]);
    assert_eq!(
        evaluer(&zone, "example.com", v6("2001:db8::ffff")),
        Verdict::Pass
    );
    assert_eq!(
        evaluer(&zone, "example.com", v6("2001:db8:1::1")),
        Verdict::Fail
    );
}

#[test]
fn une_adresse_d_une_autre_famille_que_le_pair_ne_correspond_jamais() {
    // RFC 7208 §5.3. Le pair parle en IPv4, le domaine ne publie que de l'IPv6 :
    // les comparer octet à octet ferait dire n'importe quoi.
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 a -all"])
        .avec_adresses("example.com", &[v6("::ffff:192.0.2.1")]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Fail
    );
}

// ── Les réponses vides ──────────────────────────────────────────────────────

#[test]
fn un_domaine_sans_adresse_compte_pour_une_resolution_vide() {
    // Une liste vide et un « n'existe pas » disent la même chose du mécanisme.
    let zone = Zone::nouvelle()
        .avec_txt(
            "example.com",
            &["v=spf1 a:un.vide a:deux.vide a:trois.vide -all"],
        )
        .avec_adresses("un.vide", &[])
        .avec_adresses("deux.vide", &[])
        .avec_adresses("trois.vide", &[]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::PermError
    );
}

#[test]
fn une_resolution_inverse_vide_compte_aussi() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 ptr ip4:192.0.2.0/24 -all"])
        .avec_noms_inverses(&[]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );
}

#[test]
fn une_resolution_inverse_qui_n_aboutit_pas_compte_aussi() {
    let zone = Zone::nouvelle().avec_txt("example.com", &["v=spf1 ptr ip4:192.0.2.0/24 -all"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );
}

#[test]
fn un_exists_dont_le_nom_ne_se_resout_pas_compte_comme_vide() {
    let zone = Zone::nouvelle()
        .avec_txt(
            "example.com",
            &["v=spf1 exists:%{i}.liste.example ip4:192.0.2.0/24 -all"],
        )
        .avec_introuvable("192.0.2.1.liste.example");
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );
}

// ── `sous_domaine`, dans le détail ──────────────────────────────────────────

#[test]
fn le_nom_inverse_peut_etre_le_domaine_lui_meme() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 ptr -all"])
        .avec_noms_inverses(&["EXAMPLE.COM"]);
    // La comparaison des noms est insensible à la casse (RFC 4343).
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );
}

#[test]
fn un_nom_plus_court_que_le_domaine_n_est_pas_dessous() {
    let zone = Zone::nouvelle()
        .avec_txt("example.com", &["v=spf1 ptr -all"])
        // « com » est plus court ; « example.net » a la bonne longueur sans être
        // le bon nom ; « example.com. » a le point du mauvais côté.
        .avec_noms_inverses(&["com", "example.net", "example.com."]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Fail
    );
}

// ── Les limites qu'on desserre ──────────────────────────────────────────────

#[test]
fn une_politique_plus_longue_que_le_tampon_est_refusee() {
    // `max_record_octets` est réglable ; le tampon d'une trame ne l'est pas. Au
    // delà, on refuse — car une politique tronquée se lirait comme une
    // politique valide qui dit autre chose.
    let large = Limits {
        max_record_octets: 4000,
        max_terms: 500,
        ..Limits::DEFAULT
    };
    let longue: &'static str = std::boxed::Box::leak(
        std::format!("v=spf1{} -all", " ip4:192.0.2.1".repeat(80)).into_boxed_str(),
    );
    assert!(longue.len() > 1000);
    let zone = Zone::nouvelle().avec_txt("example.com", &[longue]);
    assert_eq!(
        evaluer_avec(&zone, "example.com", v4(192, 0, 2, 1), large),
        Verdict::PermError
    );
}

#[test]
fn la_pile_des_include_tient_meme_si_on_desserre_les_resolutions() {
    // Sous la profondeur, il y a un tableau. Si la limite des résolutions ne
    // borne plus la descente, c'est à celle-là de tenir.
    let large = Limits {
        max_lookups: 40,
        ..Limits::DEFAULT
    };
    let mut zone = Zone::nouvelle().avec_txt("example.com", &["v=spf1 include:p1.example -all"]);
    for (courant, suivant) in [
        ("p1.example", "p2.example"),
        ("p2.example", "p3.example"),
        ("p3.example", "p4.example"),
        ("p4.example", "p5.example"),
        ("p5.example", "p6.example"),
        ("p6.example", "p7.example"),
        ("p7.example", "p8.example"),
        ("p8.example", "p9.example"),
        ("p9.example", "p10.example"),
        ("p10.example", "p11.example"),
        ("p11.example", "p12.example"),
        ("p12.example", "p13.example"),
    ] {
        let politique: &'static str =
            std::boxed::Box::leak(std::format!("v=spf1 include:{suivant} -all").into_boxed_str());
        zone = zone.avec_txt(courant, &[politique]);
        let _ = suivant;
    }
    assert_eq!(
        evaluer_avec(&zone, "example.com", v4(192, 0, 2, 1), large),
        Verdict::PermError
    );
}

#[test]
fn le_redirect_compte_dans_les_dix_resolutions() {
    let serrees = Limits {
        max_lookups: 1,
        ..Limits::DEFAULT
    };
    let zone = Zone::nouvelle()
        .avec_txt(
            "example.com",
            &["v=spf1 a:un.example redirect=vrai.example"],
        )
        .avec_adresses("un.example", &[v4(198, 51, 100, 1)])
        .avec_txt("vrai.example", &["v=spf1 +all"]);
    assert_eq!(
        evaluer_avec(&zone, "example.com", v4(192, 0, 2, 1), serrees),
        Verdict::PermError
    );
}

#[test]
fn une_macro_mal_formee_dans_un_redirect_vaut_permerror() {
    let zone = Zone::nouvelle().avec_txt("example.com", &["v=spf1 redirect=%{z}.example"]);
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::PermError
    );
}

#[test]
fn un_modificateur_inconnu_s_ignore() {
    // RFC 7208 §6 : les modificateurs qu'on ne connaît pas ne sont pas des
    // fautes, et `exp=` ne se lit pas dans l'ordre des mécanismes.
    let zone = Zone::nouvelle().avec_txt(
        "example.com",
        &["v=spf1 exp=pourquoi.example ip4:192.0.2.0/24 -all"],
    );
    assert_eq!(
        evaluer(&zone, "example.com", v4(192, 0, 2, 1)),
        Verdict::Pass
    );
    assert_eq!(zone.posees.borrow().len(), 1);
}
