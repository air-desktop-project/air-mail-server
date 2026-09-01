// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que les représentations de l'API ont le droit de rendre.

use std::string::{String, ToString};

use ams_api::Reason;
use ams_proto_imap::Flags;

use super::{
    AccountRow, BanRow, FlagPatch, MailboxRow, MessageRow, read_account_body, read_flag_patch,
    read_search_criteria, write_account, write_accounts, write_bans, write_domains, write_health,
    write_mailbox, write_mailboxes, write_message, write_messages, write_metrics, write_search,
};

/// Un tampon confortable.
const PLACE: usize = 4_096;

/// Une boîte d'essai.
fn boite() -> MailboxRow<'static> {
    MailboxRow {
        name: "INBOX",
        messages: 12,
        unseen: 3,
        uid_next: 42,
        uid_validity: 1_700_000_000,
    }
}

/// Un message d'essai.
fn message() -> MessageRow<'static> {
    MessageRow {
        uid: 41,
        size: 2_048,
        flags: Flags::SEEN.with(Flags::FLAGGED),
        received: 1_699_999_000,
        subject: Some("Bonjour"),
        from: Some("Anne <anne@exemple.fr>"),
    }
}

/// Un compte d'essai.
fn compte() -> AccountRow<'static> {
    AccountRow {
        login: "marc",
        addresses: &["marc@exemple.test", "postmaster@exemple.test"],
    }
}

/// Un compte qui ne reçoit rien.
fn sans_adresse() -> AccountRow<'static> {
    AccountRow {
        login: "depot",
        addresses: &[],
    }
}

/// Un bannissement d'essai.
fn bannissement() -> BanRow<'static> {
    BanRow {
        source: "192.0.2.1",
        prefix: 32,
        seconds: 3_540,
    }
}

/// Le texte d'une écriture.
fn texte(ecrit: &[u8]) -> String {
    core::str::from_utf8(ecrit).expect("de l'UTF-8").to_string()
}

/// La liste des boîtes se rend.
#[test]
fn la_liste_des_boites_se_rend() {
    let mut place = [0_u8; PLACE];
    let ecrit = write_mailboxes(&[boite()], &mut place).expect("écrivable");
    assert_eq!(
        texte(ecrit),
        concat!(
            r#"{"mailboxes":[{"name":"INBOX","messages":12,"unseen":3,"#,
            r#""uidNext":42,"uidValidity":1700000000}]}"#
        )
    );
}

/// Une liste vide reste une liste.
#[test]
fn une_liste_vide_reste_une_liste() {
    let mut place = [0_u8; PLACE];
    let ecrit = write_mailboxes(&[], &mut place).expect("écrivable");
    assert_eq!(texte(ecrit), r#"{"mailboxes":[]}"#);
}

/// Une boîte seule se rend.
#[test]
fn une_boite_seule_se_rend() {
    let mut place = [0_u8; PLACE];
    let ecrit = write_mailbox(&boite(), &mut place).expect("écrivable");
    assert_eq!(
        texte(ecrit),
        r#"{"name":"INBOX","messages":12,"unseen":3,"uidNext":42,"uidValidity":1700000000}"#
    );
}

/// **L'`uidvalidity` ACCOMPAGNE TOUT CE QUI PORTE UN UID** (§2.3.1.1 de
/// RFC 9051) : sans lui, un client agirait sur des identifiants qui ne désignent
/// plus rien.
#[test]
fn l_uid_validity_accompagne_tout_uid() {
    let mut place = [0_u8; PLACE];
    for ecrit in [
        texte(write_mailboxes(&[boite()], &mut place).expect("écrivable")),
        texte(write_mailbox(&boite(), &mut [0_u8; PLACE]).expect("écrivable")),
        texte(write_messages(&[message()], 7, None, &mut [0_u8; PLACE]).expect("écrivable")),
        texte(write_message(&message(), 7, &mut [0_u8; PLACE]).expect("écrivable")),
    ] {
        assert!(ecrit.contains("uidValidity"), "{ecrit}");
    }
}

/// Une page de messages se rend, avec son curseur.
#[test]
fn une_page_de_messages_se_rend() {
    let mut place = [0_u8; PLACE];
    let ecrit =
        write_messages(&[message()], 1_700_000_000, Some(40), &mut place).expect("écrivable");
    assert_eq!(
        texte(ecrit),
        concat!(
            r#"{"uidValidity":1700000000,"messages":[{"uid":41,"size":2048,"#,
            r#""received":1699999000,"subject":"Bonjour","#,
            r#""from":"Anne <anne@exemple.fr>","#,
            r#""flags":["\\Seen","\\Flagged"]}],"next":40}"#
        )
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    );
}

/// **`null` PLUTÔT QUE L'ABSENCE DU CHAMP** : un client qui cherche `next` doit
/// trouver une réponse.
#[test]
fn la_fin_d_une_pagination_se_dit() {
    let mut place = [0_u8; PLACE];
    let ecrit = write_messages(&[], 7, None, &mut place).expect("écrivable");
    assert_eq!(
        texte(ecrit),
        r#"{"uidValidity":7,"messages":[],"next":null}"#
    );
}

/// **LE VIDE ET L'ABSENCE NE SONT PAS LA MÊME CHOSE.**
#[test]
fn le_vide_et_l_absence_se_distinguent() {
    let mut sans = message();
    sans.subject = None;
    sans.from = None;
    let mut place = [0_u8; PLACE];
    let ecrit = texte(write_message(&sans, 7, &mut place).expect("écrivable"));
    assert!(ecrit.contains(r#""subject":null"#), "{ecrit}");
    assert!(ecrit.contains(r#""from":null"#), "{ecrit}");

    let mut vide = message();
    vide.subject = Some("");
    vide.from = Some("");
    let mut place = [0_u8; PLACE];
    let ecrit = texte(write_message(&vide, 7, &mut place).expect("écrivable"));
    assert!(ecrit.contains(r#""subject":"""#), "{ecrit}");
    assert!(ecrit.contains(r#""from":"""#), "{ecrit}");
}

/// **CE SONT LES NOMS D'IMAP**, et non des noms inventés : deux vocabulaires
/// pour la même chose finiraient par diverger.
#[test]
fn les_drapeaux_portent_leurs_noms_d_imap() {
    let tous = [
        (Flags::SEEN, "\\\\Seen"),
        (Flags::ANSWERED, "\\\\Answered"),
        (Flags::FLAGGED, "\\\\Flagged"),
        (Flags::DELETED, "\\\\Deleted"),
        (Flags::DRAFT, "\\\\Draft"),
        (Flags::MDN_SENT, "$MDNSent"),
        (Flags::FORWARDED, "$Forwarded"),
        (Flags::JUNK, "$Junk"),
        (Flags::NON_JUNK, "$NonJunk"),
        (Flags::PHISHING, "$Phishing"),
    ];
    for (drapeau, nom) in tous {
        let mut seul = message();
        seul.flags = drapeau;
        let mut place = [0_u8; PLACE];
        let ecrit = texte(write_message(&seul, 7, &mut place).expect("écrivable"));
        assert!(
            ecrit.contains(&std::format!("\"flags\":[\"{nom}\"]")),
            "{drapeau:?} : {ecrit}"
        );
    }
}

/// Un message sans drapeau rend un tableau vide, et non l'absence du champ.
#[test]
fn un_message_sans_drapeau_rend_un_tableau_vide() {
    let mut nu = message();
    nu.flags = Flags::NONE;
    let mut place = [0_u8; PLACE];
    let ecrit = texte(write_message(&nu, 7, &mut place).expect("écrivable"));
    assert!(ecrit.contains(r#""flags":[]"#), "{ecrit}");
}

/// **UN SUJET VIENT D'UN INCONNU**, et c'est l'écrivain JSON qui l'échappe.
#[test]
fn un_sujet_hostile_ne_casse_rien() {
    let mut hostile = message();
    hostile.subject = Some(r#"a","admin":true,"x":"b"#);
    hostile.from = Some("<script>alert(1)</script>");
    let mut place = [0_u8; PLACE];
    let ecrit = texte(write_message(&hostile, 7, &mut place).expect("écrivable"));
    assert!(!ecrit.contains(r#""admin":true"#), "{ecrit}");
    assert!(!ecrit.contains('<'), "{ecrit}");
    // Et le document reste lisible : un seul objet, bien clos.
    assert!(ecrit.starts_with('{') && ecrit.ends_with('}'), "{ecrit}");
}

/// **LA SANTÉ NE DIT QUE « OUI »** : pas de version, pas de nom de machine.
#[test]
fn la_sante_ne_dit_que_oui() {
    let mut place = [0_u8; PLACE];
    let ecrit = texte(write_health(&mut place).expect("écrivable"));
    assert_eq!(ecrit, r#"{"status":"ok"}"#);
    for indice in ["version", "air-mail", "rust", "build"] {
        assert!(!ecrit.contains(indice), "{ecrit} nomme « {indice} »");
    }
}

/// Des compteurs se rendent.
#[test]
fn les_compteurs_se_rendent() {
    let mut place = [0_u8; PLACE];
    let ecrit =
        write_metrics(&[("connexions", 12), ("messages", 340)], &mut place).expect("écrivable");
    assert_eq!(texte(ecrit), r#"{"connexions":12,"messages":340}"#);
    let mut place = [0_u8; PLACE];
    assert_eq!(
        texte(write_metrics(&[], &mut place).expect("écrivable")),
        "{}"
    );
}

/// Une modification de drapeaux se lit.
#[test]
fn une_modification_de_drapeaux_se_lit() {
    assert_eq!(
        read_flag_patch(br#"{"add":["\\Seen"],"remove":["\\Flagged"]}"#),
        Ok(FlagPatch {
            add: Flags::SEEN,
            remove: Flags::FLAGGED,
        })
    );
    // Un seul des deux champs suffit.
    assert_eq!(
        read_flag_patch(br#"{"add":["\\Seen","$Junk"]}"#),
        Ok(FlagPatch {
            add: Flags::SEEN.with(Flags::JUNK),
            remove: Flags::NONE,
        })
    );
    assert_eq!(
        read_flag_patch(br#"{"remove":["\\Deleted"]}"#),
        Ok(FlagPatch {
            add: Flags::NONE,
            remove: Flags::DELETED,
        })
    );
}

/// **UN CHAMP QU'ON NE CONNAÎT PAS SE REFUSE**, et ne s'ignore pas : sur une
/// modification, l'ignorer ferait croire au client qu'on a fait ce qu'il
/// demandait.
#[test]
fn un_champ_inconnu_se_refuse() {
    for corps in [
        &br#"{"set":["\\Seen"]}"#[..],
        br#"{"add":["\\Seen"],"autre":1}"#,
        br#"{"flags":["\\Seen"]}"#,
    ] {
        assert!(read_flag_patch(corps).is_err(), "{corps:?}");
    }
}

/// **POSER ET ÔTER LE MÊME DRAPEAU N'A PAS DE SENS**, et choisir lequel l'emporte
/// serait inventer une règle que le client ne connaît pas.
#[test]
fn poser_et_oter_le_meme_drapeau_se_refuse() {
    assert!(read_flag_patch(br#"{"add":["\\Seen"],"remove":["\\Seen"]}"#).is_err());
    assert!(
        read_flag_patch(br#"{"add":["\\Seen","$Junk"],"remove":["$Junk"]}"#).is_err(),
        "un seul en commun suffit"
    );
}

/// Une modification vide ne demande rien, et se refuse.
#[test]
fn une_modification_vide_se_refuse() {
    for corps in [&b"{}"[..], br#"{"add":[]}"#, br#"{"add":[],"remove":[]}"#] {
        assert!(read_flag_patch(corps).is_err(), "{corps:?}");
    }
}

/// Un drapeau qu'on ne sait pas écrire ne se lit pas.
#[test]
fn un_drapeau_inconnu_se_refuse() {
    for corps in [
        &br#"{"add":["\\Inconnu"]}"#[..],
        br#"{"add":["$Autre"]}"#,
        br#"{"add":["Seen"]}"#,
        br#"{"add":[""]}"#,
    ] {
        assert_eq!(
            read_flag_patch(corps).map_err(|e| e.reason()),
            Err(Reason::BadJsonBody),
            "{corps:?}"
        );
    }
}

/// Un corps qui n'est pas ce qu'on attend se refuse.
#[test]
fn un_corps_qui_n_est_pas_une_modification_se_refuse() {
    for corps in [
        &b""[..],
        b"[]",
        b"null",
        b"pas du json",
        br#"{"add":1}"#,
        br#"{"add":[1]}"#,
        br#"{"add":[true]}"#,
        // Une valeur avant toute clé.
        br#"["\\Seen"]"#,
    ] {
        assert!(read_flag_patch(corps).is_err(), "{corps:?}");
    }
}

/// **NOTRE TAMPON, NOTRE FAUTE**, et à chaque étape de chaque écriture.
///
/// Toutes les tailles jusqu'à la bonne, pour chaque représentation : c'est ce
/// qui met en jeu chacune des écritures, plutôt que la première qui échoue.
#[test]
fn chaque_tampon_insuffisant_se_dit() {
    type Ecrivain = fn(&mut [u8]) -> Result<&[u8], ams_api::Error>;
    let ecrivains: [(&str, Ecrivain); 14] = [
        ("mailboxes", |place| write_mailboxes(&[boite()], place)),
        ("mailbox", |place| write_mailbox(&boite(), place)),
        ("messages", |place| {
            write_messages(&[message()], 7, Some(3), place)
        }),
        // La fin d'une pagination écrit `null` là où l'autre écrit un nombre :
        // c'est une écriture de plus, donc une place de plus à manquer.
        ("messages-fin", |place| {
            write_messages(&[message()], 7, None, place)
        }),
        ("message", |place| write_message(&message(), 7, place)),
        ("health", write_health),
        ("metrics", |place| {
            write_metrics(&[("connexions", 12)], place)
        }),
        ("accounts", |place| write_accounts(&[compte()], place)),
        // Un compte SANS adresse écrit un tableau vide : c'est une suite
        // d'écritures différente, donc d'autres places à manquer.
        ("accounts-vide", |place| {
            write_accounts(&[sans_adresse()], place)
        }),
        ("account", |place| write_account(&compte(), place)),
        ("domains", |place| {
            write_domains(&["exemple.test", "autre.test"], place)
        }),
        ("bans", |place| write_bans(&[bannissement()], place)),
        ("search", |place| write_search(&[3, 41], 7, true, place)),
        // `complete: false` écrit un mot de plus : c'est une place de plus à
        // manquer.
        ("search-tronquee", |place| {
            write_search(&[3], 7, false, place)
        }),
    ];
    for (nom, ecrire) in ecrivains {
        let mut place = [0_u8; PLACE];
        let entier = ecrire(&mut place).expect("écrivable").len();
        assert!(entier > 0, "{nom} n'écrit rien");
        for taille in 0..entier {
            let mut petit = std::vec![0_u8; taille];
            let faute = ecrire(&mut petit).expect_err("trop court");
            assert_eq!(faute.reason(), Reason::BufferTooSmall, "{nom} à {taille}");
        }
    }
}

/// **UN NOM DE DRAPEAU PLUS LONG QUE CE QU'ON RETIENT SE REFUSE** : le décoder
/// demanderait une place qu'on ne prend pas pour un nom qu'on ne connaît pas.
#[test]
fn un_nom_de_drapeau_demesure_se_refuse() {
    // La séquence est écrite telle quelle : c'est du JSON, pas du Rust.
    let long = r"\u0041".repeat(40);
    let corps = std::format!("{{\"add\":[\"{long}\"]}}");
    assert_eq!(
        read_flag_patch(corps.as_bytes()).map_err(|e| e.reason()),
        Err(Reason::BadJsonBody)
    );
}

/// **UNE REPRÉSENTATION DE COMPTE NE PORTE AUCUN SECRET.**
///
/// §3.2 de RFC 9110 : elle dit l'état d'une ressource. Le mot de passe est une
/// ressource à part, qui ne se lit pas — et la séparation n'est pas une question
/// de présentation : c'est ce qui rend impossible de fuir une empreinte en lisant
/// un compte.
#[test]
fn un_compte_se_rend_sans_son_empreinte() {
    let mut place = [0_u8; PLACE];
    let compte = AccountRow {
        login: "marc",
        addresses: &["marc@exemple.test", "postmaster@exemple.test"],
    };
    let dit = texte(write_account(&compte, &mut place).expect("écrivable"));
    assert_eq!(
        dit,
        r#"{"login":"marc","addresses":["marc@exemple.test","postmaster@exemple.test"]}"#
    );
    assert!(!dit.contains("argon2") && !dit.contains("hash"), "{dit}");
}

/// **VIDE EST LICITE**, et ce n'est pas la même chose qu'absent.
///
/// Un compte qui peut se connecter sans rien recevoir est un compte de
/// soumission, et c'est une situation réelle.
#[test]
fn un_compte_sans_adresse_se_rend_quand_meme() {
    let mut place = [0_u8; PLACE];
    let compte = AccountRow {
        login: "depot",
        addresses: &[],
    };
    assert_eq!(
        texte(write_account(&compte, &mut place).expect("écrivable")),
        r#"{"login":"depot","addresses":[]}"#
    );
}

/// La liste des comptes se rend, vide comme pleine.
#[test]
fn la_liste_des_comptes_se_rend() {
    let mut place = [0_u8; PLACE];
    assert_eq!(
        texte(write_accounts(&[], &mut place).expect("écrivable")),
        r#"{"accounts":[]}"#
    );
    let comptes = [
        AccountRow {
            login: "marc",
            addresses: &["marc@exemple.test"],
        },
        AccountRow {
            login: "jeanne",
            addresses: &[],
        },
    ];
    assert_eq!(
        texte(write_accounts(&comptes, &mut place).expect("écrivable")),
        r#"{"accounts":[{"login":"marc","addresses":["marc@exemple.test"]},{"login":"jeanne","addresses":[]}]}"#
    );
}

/// Les domaines hébergés se rendent.
#[test]
fn les_domaines_se_rendent() {
    let mut place = [0_u8; PLACE];
    assert_eq!(
        texte(write_domains(&[], &mut place).expect("écrivable")),
        r#"{"domains":[]}"#
    );
    assert_eq!(
        texte(write_domains(&["exemple.test", "autre.test"], &mut place).expect("écrivable")),
        r#"{"domains":["exemple.test","autre.test"]}"#
    );
}

/// **UN BANNISSEMENT SE DIT EN TEMPS RESTANT, ET NON EN DATE.**
///
/// L'horloge du garde compte depuis l'ouverture du serveur et n'a de sens que
/// pour lui ; un exploitant veut savoir combien de temps il reste.
#[test]
fn les_bannissements_se_rendent_en_temps_restant() {
    let mut place = [0_u8; PLACE];
    assert_eq!(
        texte(write_bans(&[], &mut place).expect("écrivable")),
        r#"{"bans":[]}"#
    );
    let bans = [
        BanRow {
            source: "192.0.2.1",
            prefix: 32,
            seconds: 3_540,
        },
        BanRow {
            source: "2001:db8::",
            prefix: 64,
            seconds: 12,
        },
    ];
    assert_eq!(
        texte(write_bans(&bans, &mut place).expect("écrivable")),
        r#"{"bans":[{"source":"192.0.2.1","prefixBits":32,"secondsRemaining":3540},{"source":"2001:db8::","prefixBits":64,"secondsRemaining":12}]}"#
    );
}

/// Ce qu'un essai lit d'un corps de compte.
type CorpsLu = (
    Option<String>,
    Option<String>,
    Option<std::vec::Vec<String>>,
);

/// Lit un corps de compte, sous une forme qu'un essai lit.
fn corps_de_compte(json: &str) -> Result<CorpsLu, Reason> {
    let mut secret = [0_u8; 128];
    let mut adresses = [""; 8];
    let lu = read_account_body(json.as_bytes(), &mut secret, &mut adresses)
        .map_err(|faute| faute.reason())?;
    Ok((
        lu.login.map(ToString::to_string),
        lu.password.map(ToString::to_string),
        lu.addresses.map(|combien| {
            adresses
                .get(..combien)
                .unwrap_or_default()
                .iter()
                .map(ToString::to_string)
                .collect()
        }),
    ))
}

/// **LES TROIS CHAMPS SE LISENT**, et un secret échappé se déséchappe.
///
/// Un mot de passe a le droit de porter un guillemet ou une barre oblique
/// inverse — c'est même souhaitable —, et JSON les écrit alors échappés.
#[test]
fn un_corps_de_compte_se_lit() {
    let lu = corps_de_compte(
        r#"{"login":"marc","password":"a\"b\\c","addresses":["marc@exemple.test","m@exemple.test"]}"#,
    )
    .expect("lisible");
    assert_eq!(lu.0.as_deref(), Some("marc"));
    assert_eq!(lu.1.as_deref(), Some("a\"b\\c"));
    assert_eq!(
        lu.2,
        Some(std::vec![
            "marc@exemple.test".to_string(),
            "m@exemple.test".to_string()
        ])
    );
}

/// **L'ABSENCE D'UN CHAMP ET UNE LISTE VIDE NE SONT PAS LA MÊME CHOSE.**
///
/// L'un ne touche pas aux adresses, l'autre les efface toutes. Les confondre
/// ferait perdre à un compte ses adresses parce qu'on changeait son mot de passe.
#[test]
fn l_absence_d_un_champ_n_est_pas_une_liste_vide() {
    let lu = corps_de_compte(r#"{"password":"x"}"#).expect("lisible");
    assert_eq!(lu.2, None, "on ne touche pas aux adresses");

    let lu = corps_de_compte(r#"{"addresses":[]}"#).expect("lisible");
    assert_eq!(lu.2, Some(std::vec![]), "on les efface toutes");
    assert_eq!(lu.1, None, "et on ne touche pas au secret");
}

/// **UN CHAMP QU'ON NE CONNAÎT PAS, OU RÉPÉTÉ, SE REFUSE.**
///
/// Sur une modification, ignorer un champ ferait croire au client qu'on a fait ce
/// qu'il demandait. Répété est aussi grave : rien ne dit lequel des deux il
/// voulait — et c'est `Reader` qui l'écarte, une couche plus bas.
#[test]
fn un_champ_inconnu_ou_repete_se_refuse() {
    for json in [
        r#"{"login":"marc","admin":true}"#,
        r#"{"login":"marc","login":"jeanne"}"#,
        r#"{"password":"a","password":"b"}"#,
        r#"{"addresses":[],"addresses":[]}"#,
    ] {
        assert_eq!(corps_de_compte(json), Err(Reason::BadJsonBody), "{json}");
    }
}

/// **UNE ADRESSE OU UN NOM QUI A BESOIN D'ÊTRE ÉCHAPPÉ N'EN EST PAS UN.**
///
/// Les refuser ici est plus honnête que de les déséchapper pour les refuser deux
/// lignes plus loin. `r` est un `r` ordinaire, écrit de la façon qu'un JSON
/// permet et qu'un nom de compte n'a aucune raison d'employer.
#[test]
fn un_nom_ou_une_adresse_echappee_se_refuse() {
    for json in [
        r#"{"login":"ma\u0072c"}"#,
        r#"{"addresses":["m\u0040e.test"]}"#,
    ] {
        assert_eq!(corps_de_compte(json), Err(Reason::BadJsonBody), "{json}");
    }
}

/// **PLUS D'ADRESSES QUE LA TRANCHE N'EN TIENT SE REFUSE**, et ne se tronque pas.
///
/// Tronquer ferait perdre au compte des adresses que le client croyait avoir
/// posées, et rien dans la réponse ne le dirait.
#[test]
fn trop_d_adresses_se_refuse_plutot_que_de_tronquer() {
    let liste: std::vec::Vec<String> = (0..9)
        .map(|rang| std::format!("\"a{rang}@exemple.test\""))
        .collect();
    let json = std::format!(r#"{{"addresses":[{}]}}"#, liste.join(","));
    assert_eq!(corps_de_compte(&json), Err(Reason::BadJsonBody));
}

/// **UNE VALEUR DU MAUVAIS TYPE SE REFUSE**, et un corps qui n'est pas du JSON
/// aussi.
#[test]
fn une_valeur_du_mauvais_type_se_refuse() {
    for json in [
        r#"{"login":3}"#,
        r#"{"password":true}"#,
        r#"{"addresses":"marc@exemple.test"}"#,
        r#"{"login":null}"#,
        // Une chaîne AVANT toute clef : elle ne répond à aucune question.
        r#""marc""#,
        "pas du json",
    ] {
        assert_eq!(corps_de_compte(json), Err(Reason::BadJsonBody), "{json}");
    }
}

/// **UN CORPS VIDE NE DIT RIEN, ET CE N'EST PAS UNE FAUTE ICI.**
///
/// C'est l'appelant qui exige : lui seul sait quel champ sa ressource demande.
#[test]
fn un_corps_sans_champ_ne_dit_rien() {
    let lu = corps_de_compte("{}").expect("lisible");
    assert_eq!((lu.0, lu.1, lu.2), (None, None, None));
}

/// **UN SECRET PLUS LONG QUE LE TAMPON SE REFUSE**, et ne se tronque pas.
///
/// Tronquer un mot de passe le rendrait vérifiable par un préfixe : le compte
/// s'ouvrirait avec moins que ce que son propriétaire a choisi, sans que rien ne
/// le dise.
#[test]
fn un_secret_trop_long_se_refuse() {
    let mut secret = [0_u8; 8];
    let mut adresses = [""; 4];
    let json = br#"{"password":"beaucoup trop long pour huit octets"}"#;
    let faute = read_account_body(json, &mut secret, &mut adresses).expect_err("trop long");
    assert_eq!(faute.reason(), Reason::BadJsonBody);
}

/// **LES CRITÈRES SE LISENT, DRAPEAUX ET TEXTES.**
#[test]
fn des_criteres_de_recherche_se_lisent() {
    let lu =
        read_search_criteria(br#"{"seen":false,"flagged":true,"subject":"facture","from":"marc"}"#)
            .expect("lisible");
    assert_eq!(lu.seen, Some(false));
    assert_eq!(lu.flagged, Some(true));
    assert_eq!(lu.subject, Some("facture"));
    assert_eq!(lu.from, Some("marc"));
    assert_eq!(lu.to, None, "ce qu'on n'a pas demandé reste indifférent");
    assert!(!lu.is_empty());
}

/// **UNE RECHERCHE SANS CRITÈRE SE RECONNAÎT**, et c'est l'appelant qui décide
/// quoi en faire.
#[test]
fn une_recherche_sans_critere_se_reconnait() {
    let lu = read_search_criteria(b"{}").expect("lisible");
    assert!(lu.is_empty());
}

/// **UN CHAMP INCONNU, RÉPÉTÉ, OU DU MAUVAIS TYPE SE REFUSE.**
///
/// Ignorer un critère rendrait au client d'autres messages que ceux qu'il a
/// demandés, et rien dans la réponse ne le dirait.
#[test]
fn un_critere_inconnu_ou_repete_se_refuse() {
    for json in [
        &br#"{"urgent":true}"#[..],
        br#"{"seen":true,"seen":false}"#,
        br#"{"subject":"a","subject":"b"}"#,
        br#"{"seen":"oui"}"#,
        br#"{"subject":true}"#,
        br#"{"subject":["a"]}"#,
        b"pas du json",
    ] {
        assert!(
            read_search_criteria(json).is_err(),
            "{}",
            std::string::String::from_utf8_lossy(json)
        );
    }
}

/// **UN TEXTE ÉCHAPPÉ SE REFUSE** : il porte un guillemet, une barre oblique
/// inverse ou une commande, et ce serveur ne les cherche pas.
#[test]
fn un_critere_echappe_se_refuse() {
    assert!(read_search_criteria(br#"{"subject":"fa\u0063ture"}"#).is_err());
    assert!(read_search_criteria(br#"{"from":"dit \\"oui\\""}"#).is_err());
}

/// **DES UID, ET NON DES RANGS** (§2.3.1.1 de RFC 9051).
///
/// Un rang change dès qu'un message disparaît ; rendre des rangs ferait désigner
/// au client, une seconde plus tard, d'autres messages que ceux qu'il a trouvés.
///
/// **ET L'ON DIT SI LA LISTE EST COMPLÈTE** : un client qui croirait avoir tous
/// les résultats agirait sur une moitié.
#[test]
fn un_resultat_de_recherche_se_rend() {
    let mut place = [0_u8; PLACE];
    assert_eq!(
        texte(write_search(&[], 7, true, &mut place).expect("écrivable")),
        r#"{"uids":[],"uidValidity":7,"complete":true}"#
    );
    assert_eq!(
        texte(write_search(&[3, 41], 7, false, &mut place).expect("écrivable")),
        r#"{"uids":[3,41],"uidValidity":7,"complete":false}"#
    );
}

/// **LES DIX CRITÈRES SE LISENT, ET CHACUN SE REFUSE S'IL EST RÉPÉTÉ.**
///
/// Les éprouver un par un n'est pas du zèle : chaque clef a son bras, et un bras
/// qui rangerait la valeur dans le mauvais champ ferait chercher autre chose que
/// ce qu'on a demandé — sans jamais échouer.
///
/// La répétition, elle, est écartée par `Reader` une couche plus bas ; on
/// l'éprouve ici parce que c'est ici qu'on en dépend.
#[test]
fn les_dix_criteres_se_lisent_et_ne_se_repetent_pas() {
    let lu = read_search_criteria(
        br#"{"seen":true,"answered":false,"flagged":true,"deleted":false,"draft":true,
             "from":"a","to":"b","subject":"c","body":"d","text":"e"}"#,
    )
    .expect("lisible");
    assert_eq!(
        (lu.seen, lu.answered, lu.flagged, lu.deleted, lu.draft),
        (Some(true), Some(false), Some(true), Some(false), Some(true))
    );
    assert_eq!(
        (lu.from, lu.to, lu.subject, lu.body, lu.text),
        (Some("a"), Some("b"), Some("c"), Some("d"), Some("e"))
    );

    for (nom, valeur) in [
        ("seen", "true"),
        ("answered", "true"),
        ("flagged", "true"),
        ("deleted", "true"),
        ("draft", "true"),
        ("from", "\"a\""),
        ("to", "\"a\""),
        ("subject", "\"a\""),
        ("body", "\"a\""),
        ("text", "\"a\""),
    ] {
        let json = std::format!(r#"{{"{nom}":{valeur},"{nom}":{valeur}}}"#);
        assert!(
            read_search_criteria(json.as_bytes()).is_err(),
            "« {nom} » répété devait être refusé"
        );
    }
}

/// **UN DRAPEAU N'EST PAS UN TEXTE, ET RÉCIPROQUEMENT.**
///
/// Les deux se refusent, et pour la même raison : ranger la valeur ailleurs
/// ferait chercher autre chose que ce qu'on a demandé.
#[test]
fn un_drapeau_et_un_texte_ne_se_confondent_pas() {
    for json in [
        &br#"{"subject":true}"#[..],
        br#"{"from":false}"#,
        br#"{"seen":"oui"}"#,
        br#"{"draft":"non"}"#,
    ] {
        assert!(
            read_search_criteria(json).is_err(),
            "{}",
            std::string::String::from_utf8_lossy(json)
        );
    }
}
