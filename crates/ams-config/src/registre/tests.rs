// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use alloc::boxed::Box;
use alloc::string::{String, ToString as _};
use alloc::vec;
use alloc::vec::Vec;
use core::net::IpAddr;

use super::{
    Abandon, Destinataire, Dkim, Dmarc, EnTetes, Enregistrement, Entete, Faute, Inverse,
    IssueSession, IssueTransaction, Resultat, Salut, Sceau, Session, Spf, StatutDns, StatutSalut,
    TEXTE_MAX, TRAME_MAX, Tls, Transaction, borne, borne_octets, en_hex, en_json, en_tetes,
    jour_utc, lire_trame, trame, trames_entieres, verifier,
};

fn v4() -> IpAddr {
    IpAddr::from([192, 0, 2, 7])
}

fn v6() -> IpAddr {
    IpAddr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

fn entete(precedent: Option<[u8; 32]>) -> Enregistrement {
    Enregistrement::Entete(Entete {
        format: super::FORMAT,
        jour: String::from("2026-09-29"),
        precedent,
        version: String::from("0.2.44"),
        ouvert: 1_790_640_000_000,
    })
}

fn inverse(statut: StatutDns) -> Inverse {
    Inverse {
        statut,
        noms: vec![
            String::from("mail.example.com"),
            String::from("mx.example.com"),
        ],
        ttl: 3600,
        authentifiee: true,
        confirmee: true,
    }
}

fn salut(statut: StatutSalut) -> Salut {
    Salut {
        nom: String::from("mail.example.com"),
        statut,
        adresses: vec![v4(), v6()],
    }
}

fn session(issue: IssueSession, statut: StatutDns, salue: StatutSalut, tls: bool) -> Session {
    Session {
        id: [7; 16],
        ouverte: 1,
        fermee: 2,
        ecoute: String::from("0.0.0.0:25"),
        pair: v6(),
        port: 51_234,
        inverse: inverse(statut),
        salut: salut(salue),
        tls: tls.then(|| Tls {
            version: String::from("TLS1.3"),
            suite: String::from("TLS13_AES_256_GCM_SHA384"),
        }),
        commandes: 9,
        messages: 1,
        authentifiee: true,
        mecanisme: String::from("PLAIN"),
        issue,
        erreur: String::from("délai"),
        version: String::from("0.2.44"),
        presentation: String::from("air-mail-server version 0.2.45"),
    }
}

fn transaction(issue: IssueTransaction, complete: bool) -> Transaction {
    Transaction {
        session: [7; 16],
        numero: 1,
        recue: 3,
        soumission: false,
        mail_from: String::from("a@example.com"),
        destinataires: vec![
            Destinataire {
                adresse: String::from("b@narro.ch"),
                compte: String::from("b"),
                unique: String::from("1790640000.M1P2.onyx"),
                ecarte: true,
                relaye: false,
            },
            Destinataire {
                adresse: String::from("c@ailleurs.example"),
                relaye: true,
                ..Destinataire::default()
            },
        ],
        octets: 4096,
        entetes: EnTetes {
            message_id: String::from("<x@example.com>"),
            date: String::from("Tue, 29 Sep 2026 10:00:00 +0000"),
            from: String::from("A <a@example.com>"),
            sender: String::from("s@example.com"),
            reply_to: String::from("r@autre.example"),
            list_id: String::from("<liste.example.com>"),
            list_unsubscribe: true,
            arc: true,
            objet: complete.then_some([9; 32]),
            destinataires_visibles: 2,
            sauts: 3,
            tronque: true,
        },
        spf: complete.then(|| Spf {
            resultat: Resultat::Pass,
            helo: true,
            domaine: String::from("example.com"),
        }),
        dkim: [
            Resultat::None,
            Resultat::Pass,
            Resultat::Fail,
            Resultat::SoftFail,
            Resultat::Neutral,
            Resultat::TempError,
            Resultat::PermError,
            Resultat::Policy,
        ]
        .into_iter()
        .map(|resultat| Dkim {
            resultat,
            domaine: String::from("example.com"),
            selecteur: String::from("s1"),
        })
        .collect(),
        dmarc: complete.then(|| Dmarc {
            resultat: Resultat::Fail,
            domaine: String::from("example.com"),
            politique: String::from("reject"),
            appliquee: true,
            ecartee: false,
        }),
        authentification: String::from("Authentication-Results: mail.narro.ch; spf=pass"),
        issue,
        inverse: inverse(StatutDns::Trouve),
        salut: salut(StatutSalut::PointeLePair),
        pair: v4(),
        tls: complete.then(|| Tls {
            version: String::from("TLS1.2"),
            suite: String::from("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        }),
        presentation: String::from("air-mail-server version 0.2.45"),
    }
}

fn aller_retour(quoi: &Enregistrement) {
    let octets = trame(quoi).expect("codable");
    let (relu, fin) = lire_trame(&octets, 0).expect("relisible");
    assert_eq!(&relu, quoi);
    assert_eq!(fin, octets.len());
}

#[test]
fn chaque_enregistrement_revient_tel_quel() {
    aller_retour(&entete(None));
    aller_retour(&entete(Some([3; 32])));
    for (rang, issue) in [
        IssueSession::Servie,
        IssueSession::Ralentie,
        IssueSession::Injection,
        IssueSession::Interrompue,
    ]
    .into_iter()
    .enumerate()
    {
        let statut = [
            StatutDns::NonCherche,
            StatutDns::Trouve,
            StatutDns::Absent,
            StatutDns::Panne,
        ][rang];
        for salue in [
            StatutSalut::NonVerifie,
            StatutSalut::Litteral,
            StatutSalut::PointeLePair,
            StatutSalut::PointeAilleurs,
            StatutSalut::NeResoutPas,
            StatutSalut::Panne,
        ] {
            aller_retour(&Enregistrement::Session(Box::new(session(
                issue,
                statut,
                salue,
                rang % 2 == 0,
            ))));
        }
    }
    for (rang, issue) in [
        IssueTransaction::Acceptee,
        IssueTransaction::RefuseePolitique,
        IssueTransaction::RefuseeDefinitive,
        IssueTransaction::RefuseeTemporaire,
    ]
    .into_iter()
    .enumerate()
    {
        aller_retour(&Enregistrement::Transaction(Box::new(transaction(
            issue,
            rang % 2 == 0,
        ))));
    }
    aller_retour(&Enregistrement::Abandon(Abandon {
        session: [7; 16],
        numero: 2,
        quand: 4,
        raison: String::from("disque plein"),
    }));
    aller_retour(&Enregistrement::Sceau(Sceau {
        enregistrements: 5,
        condensat: [1; 32],
        scelle: 6,
        tronques: 7,
    }));
}

#[test]
fn les_listes_sont_bornees() {
    let mut longue = transaction(IssueTransaction::Acceptee, true);
    longue.destinataires = vec![Destinataire::default(); super::LISTE_MAX + 5];
    let octets = trame(&Enregistrement::Transaction(Box::new(longue))).expect("codable");
    let Ok((Enregistrement::Transaction(relue), _)) = lire_trame(&octets, 0) else {
        panic!("une transaction");
    };
    assert_eq!(relue.destinataires.len(), super::LISTE_MAX);
}

#[test]
fn un_enregistrement_trop_gros_ne_s_ecrit_pas() {
    let enorme = Enregistrement::Abandon(Abandon {
        session: [0; 16],
        numero: 0,
        quand: 0,
        raison: "x".repeat(TRAME_MAX),
    });
    assert_eq!(trame(&enorme), Err(Faute::Illisible(0)));
}

#[test]
fn les_textes_se_bornent_sur_un_caractere() {
    assert_eq!(borne("court"), (String::from("court"), false));
    let mut long = "a".repeat(TEXTE_MAX - 1);
    long.push('é');
    long.push_str("fin");
    let (coupe, tronque) = borne(&long);
    assert!(tronque);
    assert_eq!(coupe.len(), TEXTE_MAX - 1, "é ne se coupe pas en deux");
    assert_eq!(borne_octets(b"a\xffb"), (String::from("a\u{fffd}b"), false));
}

/// Les octets d'une trame, avec la longueur recalculée.
fn retrame(corps: &[u8]) -> Vec<u8> {
    let mut sortie = u32::try_from(corps.len())
        .expect("court")
        .to_le_bytes()
        .to_vec();
    sortie.extend_from_slice(corps);
    sortie
}

/// Le corps d'une trame dont le pointeur de l'union — le premier mot de la
/// section des pointeurs de la racine — désigne hors du segment.
fn pointeur_casse(quoi: &Enregistrement) -> Vec<u8> {
    let mut octets = trame(quoi).expect("codable");
    // 4 (longueur) + 8 (table des segments) + 8 (pointeur racine) + 8 (données).
    let rang = 4 + 8 + 8 + 8;
    octets[rang..rang + 4].copy_from_slice(&(0x3FFF_FFFC_u32).to_le_bytes());
    octets
}

#[test]
fn une_trame_abimee_se_refuse() {
    let bonne = trame(&entete(None)).expect("codable");
    // Coupée dans sa longueur, puis dans son corps.
    assert_eq!(lire_trame(&bonne[..3], 0), Err(Faute::Coupee(0)));
    assert_eq!(lire_trame(&bonne[..10], 0), Err(Faute::Coupee(0)));
    // Une longueur au-delà de la borne.
    let mut grosse = bonne.clone();
    grosse[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(lire_trame(&grosse, 0), Err(Faute::Illisible(0)));
    // Un corps qui ne fait pas un nombre entier de mots.
    assert_eq!(lire_trame(&retrame(&[0; 12]), 0), Err(Faute::Illisible(0)));
    // Un corps qui n'est pas du Cap'n Proto.
    assert_eq!(
        lire_trame(&retrame(&[0xFF; 16]), 0),
        Err(Faute::Illisible(0))
    );
    // Des octets de trop derrière le message, dans la même trame.
    let mut bavarde = bonne[4..].to_vec();
    bavarde.extend_from_slice(&[0; 8]);
    assert_eq!(lire_trame(&retrame(&bavarde), 0), Err(Faute::Illisible(0)));
    // Une racine qui n'est pas une structure.
    let mut liste = bonne.clone();
    liste[12] = 0x01;
    assert_eq!(lire_trame(&liste, 0), Err(Faute::Illisible(0)));
    // Une variante que ce schéma ne connaît pas.
    let mut inconnue = bonne.clone();
    inconnue[20] = 9;
    assert_eq!(lire_trame(&inconnue, 0), Err(Faute::Illisible(0)));
    // Le pointeur de chaque variante, cassé.
    for quoi in [
        entete(None),
        Enregistrement::Session(Box::new(session(
            IssueSession::Servie,
            StatutDns::Trouve,
            StatutSalut::Litteral,
            true,
        ))),
        Enregistrement::Transaction(Box::new(transaction(IssueTransaction::Acceptee, true))),
        Enregistrement::Abandon(Abandon {
            session: [0; 16],
            numero: 0,
            quand: 0,
            raison: String::new(),
        }),
        Enregistrement::Sceau(Sceau {
            enregistrements: 0,
            condensat: [0; 32],
            scelle: 0,
            tronques: 0,
        }),
    ] {
        assert_eq!(
            lire_trame(&pointeur_casse(&quoi), 0),
            Err(Faute::Illisible(0)),
            "{quoi:?}"
        );
    }
}

/// **UN TEXTE QUI N'EST PAS DE L'UTF-8 SE LIT VIDE**, et le reste de
/// l'enregistrement se lit quand même : la chaîne de condensats, elle, dit si
/// le fichier a été retouché.
#[test]
fn un_texte_illisible_se_lit_vide() {
    let mut abime = session(
        IssueSession::Servie,
        StatutDns::Trouve,
        StatutSalut::Panne,
        false,
    );
    abime.mecanisme = String::from("ZZZZZZZZ");
    let mut octets = trame(&Enregistrement::Session(Box::new(abime))).expect("codable");
    let rang = octets
        .windows(8)
        .position(|fenetre| fenetre == b"ZZZZZZZZ")
        .expect("le texte est écrit");
    octets[rang..rang + 8].copy_from_slice(&[0xFF; 8]);
    let Ok((Enregistrement::Session(relue), _)) = lire_trame(&octets, 0) else {
        panic!("une session");
    };
    assert!(relue.mecanisme.is_empty());
    assert_eq!(relue.version, "0.2.44");
}

/// Un fichier : entête, deux enregistrements, et — si demandé — son sceau.
fn fichier(scelle: bool) -> Vec<u8> {
    let mut octets = trame(&entete(Some([5; 32]))).expect("codable");
    for issue in [IssueSession::Servie, IssueSession::Interrompue] {
        octets.extend(
            trame(&Enregistrement::Session(Box::new(session(
                issue,
                StatutDns::Absent,
                StatutSalut::NeResoutPas,
                false,
            ))))
            .expect("codable"),
        );
    }
    if scelle {
        let condensat: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&octets).into();
        octets.extend(
            trame(&Enregistrement::Sceau(Sceau {
                enregistrements: 3,
                condensat,
                scelle: 9,
                tronques: 0,
            }))
            .expect("codable"),
        );
    }
    octets
}

#[test]
fn un_fichier_scelle_se_verifie() {
    let octets = fichier(true);
    let bilan = verifier(&octets).expect("vérifiable");
    assert_eq!(bilan.enregistrements, 3);
    assert_eq!(bilan.entete.precedent, Some([5; 32]));
    assert_eq!(bilan.sceau.map(|sceau| sceau.enregistrements), Some(3));
    let attendu: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&octets).into();
    assert_eq!(bilan.condensat, attendu);
    // Le fichier du jour, pas encore scellé.
    let ouvert = verifier(&fichier(false)).expect("vérifiable");
    assert!(ouvert.sceau.is_none());
    assert_eq!(en_hex(&[0xab, 0x01]), "ab01");
}

#[test]
fn un_fichier_retouche_se_voit() {
    // Vide.
    assert_eq!(verifier(&[]), Err(Faute::Coupee(0)));
    // Sans entête.
    let sans = trame(&Enregistrement::Abandon(Abandon {
        session: [0; 16],
        numero: 0,
        quand: 0,
        raison: String::new(),
    }))
    .expect("codable");
    assert_eq!(verifier(&sans), Err(Faute::SansEntete));
    // Un second entête.
    let mut deux = fichier(false);
    let rang = deux.len();
    deux.extend(trame(&entete(None)).expect("codable"));
    assert_eq!(verifier(&deux), Err(Faute::EnteteEnTrop(rang)));
    // Une trame coupée au milieu.
    let ouvert = fichier(false);
    assert!(matches!(
        verifier(&ouvert[..ouvert.len() - 3]),
        Err(Faute::Coupee(_))
    ));
    // Un octet changé avant le sceau.
    let mut retouche = fichier(true);
    let rang = retouche
        .windows(10)
        .position(|fenetre| fenetre == b"0.0.0.0:25")
        .expect("écrit");
    retouche[rang] = b'1';
    assert_eq!(verifier(&retouche), Err(Faute::SceauFaux));
    // Un sceau au bon condensat, mais au mauvais compte.
    let mut compte = fichier(false);
    let condensat: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&compte).into();
    compte.extend(
        trame(&Enregistrement::Sceau(Sceau {
            enregistrements: 99,
            condensat,
            scelle: 0,
            tronques: 0,
        }))
        .expect("codable"),
    );
    assert_eq!(verifier(&compte), Err(Faute::SceauFaux));
    // Quelque chose après le sceau.
    let mut apres = fichier(true);
    apres.extend(trame(&entete(None)).expect("codable"));
    assert_eq!(verifier(&apres), Err(Faute::ApresLeSceau));
}

#[test]
fn les_trames_entieres_se_comptent() {
    let entier = fichier(false);
    assert_eq!(trames_entieres(&entier), (entier.len(), 3));
    let (garde, combien) = trames_entieres(&entier[..entier.len() - 5]);
    assert_eq!(combien, 2);
    assert!(garde < entier.len() - 5);
    assert_eq!(trames_entieres(&[]), (0, 0));
}

#[test]
fn les_fautes_se_disent() {
    for faute in [
        Faute::Coupee(1),
        Faute::Illisible(2),
        Faute::SansEntete,
        Faute::EnteteEnTrop(3),
        Faute::SceauFaux,
        Faute::ApresLeSceau,
    ] {
        assert!(!faute.to_string().is_empty());
    }
}

#[test]
fn chaque_enregistrement_s_ecrit_en_json() {
    let entete = en_json(&entete(Some([0xab; 32])));
    assert!(entete.starts_with("{\"type\":\"entete\""), "{entete}");
    assert!(entete.contains("\"precedent\":\"abab"), "{entete}");
    assert!(en_json(&super::tests::entete(None)).contains("\"precedent\":\"\""));
    for issue in [
        IssueSession::Servie,
        IssueSession::Ralentie,
        IssueSession::Injection,
        IssueSession::Interrompue,
    ] {
        for statut in [
            StatutDns::NonCherche,
            StatutDns::Trouve,
            StatutDns::Absent,
            StatutDns::Panne,
        ] {
            let ligne = en_json(&Enregistrement::Session(Box::new(session(
                issue,
                statut,
                StatutSalut::PointeAilleurs,
                statut == StatutDns::Trouve,
            ))));
            assert!(ligne.contains("\"pair\":\"2001:db8::1\""), "{ligne}");
        }
    }
    for salue in [
        StatutSalut::NonVerifie,
        StatutSalut::Litteral,
        StatutSalut::PointeLePair,
        StatutSalut::PointeAilleurs,
        StatutSalut::NeResoutPas,
        StatutSalut::Panne,
    ] {
        let ligne = en_json(&Enregistrement::Session(Box::new(session(
            IssueSession::Servie,
            StatutDns::Trouve,
            salue,
            false,
        ))));
        assert!(ligne.contains("\"tls\":null"), "{ligne}");
    }
    for (rang, issue) in [
        IssueTransaction::Acceptee,
        IssueTransaction::RefuseePolitique,
        IssueTransaction::RefuseeDefinitive,
        IssueTransaction::RefuseeTemporaire,
    ]
    .into_iter()
    .enumerate()
    {
        let ligne = en_json(&Enregistrement::Transaction(Box::new(transaction(
            issue,
            rang % 2 == 0,
        ))));
        assert!(ligne.contains("\"type\":\"transaction\""), "{ligne}");
        assert!(ligne.contains("\"resultat\":\"softfail\""), "{ligne}");
    }
    let abandon = en_json(&Enregistrement::Abandon(Abandon {
        session: [1; 16],
        numero: 2,
        quand: 3,
        raison: String::from("dit \"non\"\\\n\r\t\u{1}"),
    }));
    assert!(
        abandon.contains(r#""raison":"dit \"non\"\\\n\r\t\u0001""#),
        "{abandon}"
    );
    let sceau = en_json(&Enregistrement::Sceau(Sceau {
        enregistrements: 1,
        condensat: [0; 32],
        scelle: 2,
        tronques: 3,
    }));
    assert!(sceau.contains("\"tronques\":3"), "{sceau}");
}

#[test]
fn les_en_tetes_utiles_se_lisent() {
    let long = "x".repeat(TEXTE_MAX + 10);
    let bloc = alloc::format!(
        " suite sans champ\r\n\
         Received: from a\r\n\
         Received: from b\r\n\
         Message-ID: <premier@example.com>\r\n\
         Message-Id: <second@example.com>\r\n\
         From: A\r\n  <a@example.com>\r\n\
         Sender: s@example.com\r\n\
         Reply-To: r@autre.example\r\n\
         To: b@x.example, c@x.example\r\n\
         Cc: d@x.example\r\n\
         Date: {long}\r\n\
         Subject: Bonjour\r\n\
         Subject: Autre\r\n\
         List-Id: <liste.example.com>\r\n\
         List-Unsubscribe: <mailto:u@example.com>\r\n\
         ARC-Seal: i=1\r\n\
         X-Inconnu: rien\r\n\
         ligne sans deux-points\r\n\
         \r\n\
         Message-ID: <corps@example.com>\r\n"
    );
    let vus = en_tetes(bloc.as_bytes());
    assert_eq!(vus.message_id, "<premier@example.com>");
    assert_eq!(vus.from, "A <a@example.com>");
    assert_eq!(vus.sender, "s@example.com");
    assert_eq!(vus.reply_to, "r@autre.example");
    assert_eq!(vus.list_id, "<liste.example.com>");
    assert!(vus.list_unsubscribe && vus.arc && vus.tronque);
    assert_eq!(vus.date.len(), TEXTE_MAX);
    assert_eq!(vus.destinataires_visibles, 3);
    assert_eq!(vus.sauts, 2);
    let bonjour: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(b"Bonjour").into();
    assert_eq!(vus.objet, Some(bonjour), "le premier objet l'emporte");
    // Des fins de ligne nues, et rien d'autre.
    let nu = en_tetes(b"ARC-Message-Signature: a\nARC-Authentication-Results: b\n");
    assert!(nu.arc && nu.objet.is_none());
}

#[test]
fn le_jour_utc_se_calcule() {
    assert_eq!(jour_utc(0), "1970-01-01");
    // 2026-09-29 00:00:00 UTC, puis la dernière milliseconde du jour.
    assert_eq!(jour_utc(1_790_640_000_000), "2026-09-29");
    assert_eq!(jour_utc(1_790_726_399_999), "2026-09-29");
    // Un 29 février, et le passage de janvier à l'année.
    assert_eq!(jour_utc(1_709_164_800_000), "2024-02-29");
    assert_eq!(jour_utc(1_704_067_199_000), "2023-12-31");
}

/// **LA LECTURE BORNE COMME L'ÉCRITURE** — trouvé par le fuzz : un fichier
/// qui porterait plus de [`super::LISTE_MAX`] signatures se lisait en entier,
/// et se réécrivait tronqué. Ce qui se lit doit se réécrire à l'identique.
#[test]
fn une_liste_trop_longue_se_lit_bornee() {
    let mut message = capnp::message::Builder::new_default();
    {
        let racine = message.init_root::<crate::ams_registre_capnp::enregistrement::Builder<'_>>();
        let mut ecrit = racine.init_transaction();
        ecrit.set_session(&[1; 16]);
        let _ = ecrit.reborrow().init_dkim(100);
        let _ = ecrit.reborrow().init_destinataires(100);
        let mut inverse = ecrit.reborrow().init_inverse();
        let _ = inverse.reborrow().init_noms(100);
        let _ = ecrit.init_salut().init_adresses(100);
    }
    let corps = capnp::serialize::write_message_to_words(&message);
    let Ok((Enregistrement::Transaction(lue), _)) = lire_trame(&retrame(&corps), 0) else {
        panic!("une transaction");
    };
    assert_eq!(lue.dkim.len(), super::LISTE_MAX);
    assert_eq!(lue.destinataires.len(), super::LISTE_MAX);
    assert_eq!(lue.inverse.noms.len(), super::LISTE_MAX);
    assert!(
        lue.salut.adresses.is_empty(),
        "des adresses vides ne se lisent pas"
    );
    let reecrite = trame(&Enregistrement::Transaction(lue.clone())).expect("codable");
    let Ok((Enregistrement::Transaction(relue), _)) = lire_trame(&reecrite, 0) else {
        panic!("une transaction");
    };
    assert_eq!(relue, lue);
}
