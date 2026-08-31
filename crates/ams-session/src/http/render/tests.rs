// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que les représentations de l'API ont le droit de rendre.

use std::string::{String, ToString};

use ams_api::Reason;
use ams_proto_imap::Flags;

use super::{
    FlagPatch, MailboxRow, MessageRow, read_flag_patch, write_health, write_mailbox,
    write_mailboxes, write_message, write_messages, write_metrics,
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
    let ecrivains: [(&str, Ecrivain); 7] = [
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
