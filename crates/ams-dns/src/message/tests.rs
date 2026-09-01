//! Ce que le décodage d'une réponse doit tenir.

use super::{Message, Records, Status};
use crate::{CLASS_IN, Error, KIND_OPT, Kind};

/// Les octets d'un nom, tel qu'il s'écrit sur le fil.
fn nom(texte: &str) -> std::vec::Vec<u8> {
    let mut octets = std::vec::Vec::new();
    for etiquette in texte.split('.').filter(|e| !e.is_empty()) {
        octets.push(u8::try_from(etiquette.len()).expect("étiquette courte"));
        octets.extend_from_slice(etiquette.as_bytes());
    }
    octets.push(0);
    octets
}

/// Une chaîne de caractères telle qu'un `TXT` la porte.
fn chaine(texte: &str) -> std::vec::Vec<u8> {
    let mut octets = std::vec::Vec::new();
    octets.push(u8::try_from(texte.len()).expect("chaîne courte"));
    octets.extend_from_slice(texte.as_bytes());
    octets
}

/// Un en-tête de réponse.
fn entete(drapeaux: u16, qd: u16, an: u16, ns: u16, ar: u16) -> std::vec::Vec<u8> {
    let mut octets = std::vec::Vec::new();
    octets.extend_from_slice(&0xBEEF_u16.to_be_bytes());
    octets.extend_from_slice(&drapeaux.to_be_bytes());
    octets.extend_from_slice(&qd.to_be_bytes());
    octets.extend_from_slice(&an.to_be_bytes());
    octets.extend_from_slice(&ns.to_be_bytes());
    octets.extend_from_slice(&ar.to_be_bytes());
    octets
}

/// Une question, telle que le serveur la répète.
fn question(texte: &str, kind: Kind) -> std::vec::Vec<u8> {
    let mut octets = nom(texte);
    octets.extend_from_slice(&kind.code().to_be_bytes());
    octets.extend_from_slice(&CLASS_IN.to_be_bytes());
    octets
}

/// Un enregistrement.
fn enregistrement(texte: &str, kind: u16, class: u16, rdata: &[u8]) -> std::vec::Vec<u8> {
    let mut octets = nom(texte);
    octets.extend_from_slice(&kind.to_be_bytes());
    octets.extend_from_slice(&class.to_be_bytes());
    octets.extend_from_slice(&300_u32.to_be_bytes());
    octets.extend_from_slice(
        &u16::try_from(rdata.len())
            .expect("données courtes")
            .to_be_bytes(),
    );
    octets.extend_from_slice(rdata);
    octets
}

/// La réponse la plus ordinaire : une question, un enregistrement.
fn reponse(kind: Kind, rdata: &[u8]) -> std::vec::Vec<u8> {
    let mut octets = entete(0x8180, 1, 1, 0, 0);
    octets.extend_from_slice(&question("example.com", kind));
    octets.extend_from_slice(&enregistrement("example.com", kind.code(), CLASS_IN, rdata));
    octets
}

#[test]
fn une_reponse_txt_rend_ses_chaines() {
    let mut donnees = chaine("v=spf1 ip4:192.0.2.0/24 ");
    donnees.extend_from_slice(&chaine("-all"));
    let octets = reponse(Kind::Txt, &donnees);
    let message = Message::parse(&octets).expect("réponse lisible");

    assert_eq!(message.id(), 0xBEEF);
    assert_eq!(message.status(), Status::NoError);
    assert!(!message.truncated());

    let enregistrements: std::vec::Vec<_> = message.answers().collect();
    assert_eq!(enregistrements.len(), 1);
    let seul = enregistrements[0];
    assert_eq!(seul.kind(), Kind::Txt.code());
    assert_eq!(seul.class(), CLASS_IN);
    assert!(!seul.is_opt());
    assert_eq!(seul.owner().expect("nom").as_bytes(), b"example.com");
    assert_eq!(seul.rdata(), &donnees[..]);

    // UN `TXT` N'EST PAS UNE CHAÎNE, C'EN EST UNE SUITE. RFC 7208 §3.3 veut
    // qu'on les concatène SANS séparateur : une politique de 300 octets arrive
    // en deux morceaux, et les joindre par une espace en ferait une autre.
    let morceaux: std::vec::Vec<&[u8]> = seul.strings().collect();
    assert_eq!(morceaux.len(), 2);
    let recollee: std::vec::Vec<u8> = morceaux.concat();
    assert_eq!(&recollee[..], b"v=spf1 ip4:192.0.2.0/24 -all");
}

#[test]
fn une_chaine_qui_deborde_arrete_la_suite() {
    // Rendre ce qu'on a lu jusque-là ferait passer une moitié de politique pour
    // une politique.
    let octets = reponse(Kind::Txt, &[9, b'a', b'b']);
    let message = Message::parse(&octets).expect("réponse lisible");
    let morceaux: std::vec::Vec<&[u8]> = message.answers().next().expect("un").strings().collect();
    assert!(morceaux.is_empty());
}

#[test]
fn les_adresses_se_lisent_dans_les_deux_familles() {
    let octets = reponse(Kind::A, &[192, 0, 2, 7]);
    let message = Message::parse(&octets).expect("réponse lisible");
    assert_eq!(
        message.answers().next().expect("un").address(),
        Some("192.0.2.7".parse().expect("adresse"))
    );

    let octets = reponse(
        Kind::Aaaa,
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    );
    let message = Message::parse(&octets).expect("réponse lisible");
    assert_eq!(
        message.answers().next().expect("un").address(),
        Some("2001:db8::1".parse().expect("adresse"))
    );
}

#[test]
fn une_adresse_de_la_mauvaise_longueur_n_en_est_pas_une() {
    // Un `A` de huit octets : en lire quatre laisserait la moitié non lue, et
    // ce qui n'est pas lu dans un message qui vient d'ailleurs mérite un refus.
    for (kind, donnees) in [
        (Kind::A, &[192, 0, 2, 7, 1, 2, 3, 4][..]),
        (Kind::A, &[192, 0][..]),
        (Kind::Aaaa, &[0x20, 0x01][..]),
        (Kind::Txt, &[4, b'a', b'b', b'c', b'd'][..]),
    ] {
        let octets = reponse(kind, donnees);
        let message = Message::parse(&octets).expect("réponse lisible");
        assert_eq!(
            message.answers().next().expect("un").address(),
            None,
            "{kind:?} {donnees:?}"
        );
    }
}

#[test]
fn un_mx_porte_sa_preference_et_son_nom() {
    let mut donnees = std::vec::Vec::from(&10_u16.to_be_bytes()[..]);
    donnees.extend_from_slice(&nom("mx.example.com"));
    let octets = reponse(Kind::Mx, &donnees);
    let message = Message::parse(&octets).expect("réponse lisible");
    let (preference, echange) = message
        .answers()
        .next()
        .expect("un")
        .exchange()
        .expect("MX lisible");
    assert_eq!(preference, 10);
    assert_eq!(echange.as_bytes(), b"mx.example.com");
}

#[test]
fn un_ptr_porte_un_nom() {
    let octets = reponse(Kind::Ptr, &nom("mx.example.com"));
    let message = Message::parse(&octets).expect("réponse lisible");
    assert_eq!(
        message
            .answers()
            .next()
            .expect("un")
            .target()
            .expect("PTR lisible")
            .as_bytes(),
        b"mx.example.com"
    );
}

#[test]
fn un_nom_de_donnees_illisible_est_refuse_a_la_lecture() {
    // La validation d'ensemble marche les SECTIONS ; les noms qui vivent DANS
    // les données ne se lisent qu'à la demande, et c'est là qu'ils sont
    // éprouvés.
    let octets = reponse(Kind::Ptr, &[0xC0, 0xFF]);
    let message = Message::parse(&octets).expect("réponse lisible");
    let seul = message.answers().next().expect("un");
    assert_eq!(seul.target(), Err(Error::BadPointer));

    // Un `MX` dont la préférence seule tient.
    let octets = reponse(Kind::Mx, &[0]);
    let message = Message::parse(&octets).expect("réponse lisible");
    assert_eq!(
        message.answers().next().expect("un").exchange(),
        Err(Error::Truncated)
    );
    // Un `MX` sans même sa préférence : elle est lue DANS le message, donc la
    // troncature se voit sur le nom qui suit.
    let octets = reponse(Kind::Mx, &[10, 0, 0x40]);
    let message = Message::parse(&octets).expect("réponse lisible");
    assert_eq!(
        message.answers().next().expect("un").exchange(),
        Err(Error::Malformed)
    );
}

#[test]
fn un_proprietaire_illisible_se_voit_aussi() {
    // Le nom du propriétaire est SAUTÉ à la validation, pas reconstitué : un
    // pointeur qui ne recule pas ne se voit qu'en le lisant.
    let mut octets = entete(0x8180, 0, 1, 0, 0);
    // Un pointeur, à l'octet douze, qui vise l'octet douze : il ne recule pas.
    octets.extend_from_slice(&[0xC0, 12]);
    octets.extend_from_slice(&Kind::A.code().to_be_bytes());
    octets.extend_from_slice(&CLASS_IN.to_be_bytes());
    octets.extend_from_slice(&300_u32.to_be_bytes());
    octets.extend_from_slice(&4_u16.to_be_bytes());
    octets.extend_from_slice(&[192, 0, 2, 1]);
    let message = Message::parse(&octets).expect("réponse lisible");
    assert_eq!(
        message.answers().next().expect("un").owner(),
        Err(Error::BadPointer)
    );
}

#[test]
fn les_sections_qu_on_n_a_pas_demandees_ne_sont_pas_rendues() {
    // Une section d'autorité et une d'additionnels portent ce que le serveur a
    // jugé bon d'ajouter. UN CLIENT STUB QUI LES CROIRAIT accepterait des
    // données que personne n'a demandées — c'est l'empoisonnement de cache le
    // plus ancien du monde.
    let mut octets = entete(0x8180, 1, 1, 1, 1);
    octets.extend_from_slice(&question("example.com", Kind::A));
    octets.extend_from_slice(&enregistrement(
        "example.com",
        Kind::A.code(),
        CLASS_IN,
        &[192, 0, 2, 1],
    ));
    octets.extend_from_slice(&enregistrement(
        "example.com",
        2,
        CLASS_IN,
        &nom("ns.attaquant.example"),
    ));
    octets.extend_from_slice(&enregistrement(
        "ns.attaquant.example",
        Kind::A.code(),
        CLASS_IN,
        &[198, 51, 100, 1],
    ));

    let message = Message::parse(&octets).expect("réponse lisible");
    let rendus: std::vec::Vec<_> = message.answers().collect();
    assert_eq!(rendus.len(), 1);
    assert_eq!(
        rendus[0].address(),
        Some("192.0.2.1".parse().expect("adresse"))
    );
}

#[test]
fn l_opt_d_edns_se_reconnait() {
    let mut octets = entete(0x8180, 0, 1, 0, 0);
    octets.extend_from_slice(&enregistrement("", KIND_OPT, 1232, &[]));
    let message = Message::parse(&octets).expect("réponse lisible");
    assert!(message.answers().next().expect("un").is_opt());
}

#[test]
fn les_quatre_issues_du_serveur_se_distinguent() {
    for (code, attendu) in [
        (0, Status::NoError),
        (3, Status::NameError),
        (2, Status::ServerFailure),
        (5, Status::Other(5)),
    ] {
        let octets = entete(0x8180 | code, 0, 0, 0, 0);
        let message = Message::parse(&octets).expect("réponse lisible");
        assert_eq!(message.status(), attendu, "code {code}");
        assert!(!std::format!("{attendu:?}").is_empty());
    }
    assert_ne!(Status::NoError, Status::NameError);
}

#[test]
fn la_troncature_se_lit_sur_le_drapeau() {
    // Ce qui est arrivé NE S'UTILISE PAS : une politique SPF coupée en deux se
    // lirait comme une politique valide qui dit autre chose. L'appelant
    // reprend en TCP.
    let octets = entete(0x8380, 0, 0, 0, 0);
    let message = Message::parse(&octets).expect("réponse lisible");
    assert!(message.truncated());
}

#[test]
fn une_question_qui_revient_n_est_pas_une_reponse() {
    // Sans ce refus, un pair injecterait ses propres questions dans le flot des
    // réponses attendues.
    let octets = entete(0x0100, 0, 0, 0, 0);
    assert_eq!(Message::parse(&octets).unwrap_err(), (Error::NotAResponse));
}

#[test]
fn un_message_plus_court_que_son_en_tete_est_refuse() {
    for taille in 0..12 {
        let octets = std::vec![0x80_u8; taille];
        assert_eq!(
            Message::parse(&octets).unwrap_err(),
            (Error::Truncated),
            "taille {taille}"
        );
    }
}

#[test]
fn un_message_qui_ment_sur_ses_sections_est_refuse() {
    // Il annonce une question qui n'est pas là.
    let octets = entete(0x8180, 1, 0, 0, 0);
    assert_eq!(Message::parse(&octets).unwrap_err(), (Error::Truncated));

    // La question est là, mais son type et sa classe manquent.
    let mut coupee = entete(0x8180, 1, 0, 0, 0);
    coupee.extend_from_slice(&nom("example.com"));
    assert_eq!(Message::parse(&coupee).unwrap_err(), (Error::Truncated));

    // Il annonce un enregistrement qui n'est pas là.
    let octets = entete(0x8180, 0, 1, 0, 0);
    assert_eq!(Message::parse(&octets).unwrap_err(), (Error::Truncated));

    // Les données annoncées débordent du message.
    let mut menteuse = entete(0x8180, 0, 1, 0, 0);
    menteuse.extend_from_slice(&nom("example.com"));
    menteuse.extend_from_slice(&Kind::A.code().to_be_bytes());
    menteuse.extend_from_slice(&CLASS_IN.to_be_bytes());
    menteuse.extend_from_slice(&300_u32.to_be_bytes());
    menteuse.extend_from_slice(&500_u16.to_be_bytes());
    assert_eq!(Message::parse(&menteuse).unwrap_err(), (Error::Truncated));

    // Un enregistrement d'autorité manquant condamne le message entier : LA
    // VALIDATION EST D'UN SEUL TENANT, et un pair qui sait ce qu'on lit
    // d'abord choisirait ce qu'on ne lit pas.
    let mut queue = entete(0x8180, 0, 1, 1, 0);
    queue.extend_from_slice(&enregistrement(
        "example.com",
        Kind::A.code(),
        CLASS_IN,
        &[192, 0, 2, 1],
    ));
    assert_eq!(Message::parse(&queue).unwrap_err(), (Error::Truncated));
}

#[test]
fn l_iterateur_s_arrete_meme_sans_la_validation_d_ensemble() {
    // `Message::parse` a déjà marché la section : l'itérateur ne devrait jamais
    // rencontrer d'enregistrement illisible. IL NE S'EN REMET PAS À CELA pour
    // autant — sans quoi la sûreté de l'itérateur dépendrait d'un appel qu'un
    // remaniement futur pourrait séparer. On l'éprouve donc directement.
    let octets = entete(0x8180, 0, 0, 0, 0);
    let mut deraille = Records {
        octets: &octets,
        position: 6,
        restants: 3,
    };
    assert!(deraille.next().is_none());

    // Et quand il n'y a plus rien à rendre, il le dit.
    let mut vide = Records {
        octets: &octets,
        position: 12,
        restants: 0,
    };
    assert!(vide.next().is_none());
    assert!(!std::format!("{vide:?}").is_empty());
}

#[test]
fn les_types_se_deboguent_et_se_copient() {
    let octets = reponse(Kind::A, &[192, 0, 2, 1]);
    let message = Message::parse(&octets).expect("réponse lisible");
    let copie = message;
    assert_eq!(copie.id(), message.id());
    assert!(!std::format!("{message:?}").is_empty());
    let enregistrement = message.answers().next().expect("un");
    assert!(!std::format!("{enregistrement:?}").is_empty());
    assert!(!std::format!("{:?}", enregistrement.strings()).is_empty());
    assert!(!std::format!("{:?}", message.answers()).is_empty());
}

#[test]
fn un_enregistrement_reduit_a_son_nom_est_refuse() {
    // Le nom se saute jusqu'au bout du message ; ce qui devait suivre — type,
    // classe, TTL, longueur — n'est pas là. Chacune de ces quatre lectures a sa
    // borne, et aucune ne suppose que la précédente a laissé de la place.
    let mut base = entete(0x8180, 0, 1, 0, 0);
    base.extend_from_slice(&nom("example.com"));
    for surplus in 0..10 {
        let mut octets = base.clone();
        octets.extend_from_slice(&std::vec![0_u8; surplus]);
        assert_eq!(
            Message::parse(&octets).unwrap_err(),
            Error::Truncated,
            "surplus {surplus}"
        );
    }
}

/// **LE BIT `AD` SE TRANSPORTE, IL NE S'INVENTE PAS.**
///
/// C'est lui qui décide si DANE s'applique. Le poser d'office ferait croire à
/// une validation que personne n'a faite ; l'ignorer ferait retomber tout le
/// monde sur le chiffrement opportuniste sans jamais le dire.
#[test]
fn le_bit_ad_se_transporte_tel_quel() {
    for (drapeaux, attendu) in [(0x8180_u16, false), (0x81a0_u16, true)] {
        let mut octets = entete(drapeaux, 1, 1, 0, 0);
        octets.extend_from_slice(&question("example.com", Kind::Tlsa));
        octets.extend_from_slice(&enregistrement(
            "example.com",
            Kind::Tlsa.code(),
            CLASS_IN,
            &[3, 1, 1, 0],
        ));
        let message = Message::parse(&octets).expect("lisible");
        assert_eq!(
            message.authentic_data(),
            attendu,
            "drapeaux {drapeaux:#06x}"
        );
    }
}
