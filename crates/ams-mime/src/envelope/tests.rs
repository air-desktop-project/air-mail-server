//! Ce qu'une enveloppe dit d'un message.

use super::write_envelope;
use crate::{Error, Limits};

const BORNES: Limits = Limits::DEFAULT;

/// Compose l'enveloppe d'un en-tête, ou panique.
fn enveloppe(entete: &[u8]) -> std::string::String {
    let mut sortie = [0_u8; 4096];
    let ecrits = write_envelope(entete, &mut sortie, &BORNES).expect("composable");
    std::string::String::from_utf8_lossy(sortie.get(..ecrits).unwrap_or_default()).into_owned()
}

#[test]
fn la_forme_la_plus_simple_se_compose() {
    assert_eq!(
        enveloppe(b"From: jean@exemple.test\r\nSubject: bonjour\r\n\r\ncorps\r\n"),
        "(NIL \"bonjour\" ((NIL NIL \"jean\" \"exemple.test\")) \
         ((NIL NIL \"jean\" \"exemple.test\")) ((NIL NIL \"jean\" \"exemple.test\")) \
         NIL NIL NIL NIL NIL)"
    );
}

/// **§7.5.2 : si `Sender` ou `Reply-To` manque, c'est `From` qui vaut.** Rendre
/// `NIL` ferait croire au client qu'il n'y a personne à qui répondre.
#[test]
fn sender_et_reply_to_prennent_la_valeur_de_from() {
    let compose = enveloppe(b"From: a@x.test\r\nSender: b@y.test\r\nReply-To: c@z.test\r\n\r\n");
    assert!(compose.contains("\"a\" \"x.test\""), "{compose}");
    assert!(compose.contains("\"b\" \"y.test\""), "{compose}");
    assert!(compose.contains("\"c\" \"z.test\""), "{compose}");
    // Un champ présent mais VIDE vaut absent (§7.5.2).
    let vide = enveloppe(b"From: a@x.test\r\nSender:  \r\n\r\n");
    assert_eq!(vide.matches("\"a\" \"x.test\"").count(), 3, "{vide}");
}

/// **Un nom d'affichage n'est pas une adresse**, et ses guillemets ne lui
/// appartiennent pas.
#[test]
fn le_nom_d_affichage_se_lit_et_se_recite() {
    assert!(
        enveloppe(b"From: \"Jean Dupont\" <jean@exemple.test>\r\n\r\n")
            .contains("(\"Jean Dupont\" NIL \"jean\" \"exemple.test\")")
    );
    // Sans guillemets, il se lit pareil.
    assert!(
        enveloppe(b"From: Jean Dupont <jean@exemple.test>\r\n\r\n")
            .contains("(\"Jean Dupont\" NIL \"jean\" \"exemple.test\")")
    );
    // Les échappements de la RFC 5322 se défont, et se refont aux règles d'IMAP.
    assert!(
        enveloppe(b"From: \"Jean \\\"le vrai\\\"\" <jean@exemple.test>\r\n\r\n")
            .contains("(\"Jean \\\"le vrai\\\"\" NIL \"jean\" \"exemple.test\")")
    );
    // Un antislash aussi.
    assert!(
        enveloppe(b"From: \"a\\\\b\" <jean@exemple.test>\r\n\r\n")
            .contains("(\"a\\\\b\" NIL \"jean\" \"exemple.test\")")
    );
}

/// **Les commentaires se traversent et ne se recopient pas.**
#[test]
fn les_commentaires_ne_se_recopient_pas() {
    assert!(
        enveloppe(b"From: (le vrai) Jean <jean@exemple.test>\r\n\r\n")
            .contains("(\"Jean\" NIL \"jean\" \"exemple.test\")")
    );
    // Imbriqués, ils se traversent aussi.
    assert!(
        enveloppe(b"From: Jean ((tres) vrai) <jean@exemple.test>\r\n\r\n")
            .contains("(\"Jean\" NIL \"jean\" \"exemple.test\")")
    );
    // Un nom qui n'est QUE commentaire ne vaut rien.
    assert!(
        enveloppe(b"From: (rien) <jean@exemple.test>\r\n\r\n")
            .contains("(NIL NIL \"jean\" \"exemple.test\")")
    );
}

#[test]
fn plusieurs_adresses_se_suivent() {
    let compose = enveloppe(b"To: a@x.test, Bee <b@y.test>, c@z.test\r\n\r\n");
    assert!(
        compose.contains(
            "((NIL NIL \"a\" \"x.test\")(\"Bee\" NIL \"b\" \"y.test\")(NIL NIL \"c\" \"z.test\"))"
        ),
        "{compose}"
    );
}

/// **Un groupe s'ouvre et se ferme** (§7.5.2) : `(NIL NIL "nom" NIL)` puis
/// `(NIL NIL NIL NIL)`.
#[test]
fn un_groupe_s_ouvre_et_se_ferme() {
    let compose = enveloppe(b"To: Amis: a@x.test, b@y.test;\r\n\r\n");
    assert!(
        compose.contains(
            "((NIL NIL \"Amis\" NIL)(NIL NIL \"a\" \"x.test\")\
             (NIL NIL \"b\" \"y.test\")(NIL NIL NIL NIL))"
        ),
        "{compose}"
    );
    // Un groupe vide s'ouvre et se ferme quand même.
    let vide = enveloppe(b"To: Personne:;\r\n\r\n");
    assert!(
        vide.contains("((NIL NIL \"Personne\" NIL)(NIL NIL NIL NIL))"),
        "{vide}"
    );
}

/// **Une virgule entre guillemets n'en est pas une**, et un chevron protège ce
/// qu'il contient.
#[test]
fn les_separateurs_se_lisent_au_bon_niveau() {
    let compose = enveloppe(b"To: \"Dupont, Jean\" <jean@exemple.test>\r\n\r\n");
    assert!(
        compose.contains("((\"Dupont, Jean\" NIL \"jean\" \"exemple.test\"))"),
        "{compose}"
    );
}

/// **Le DERNIER arobase fait l'hôte** : un nom peut en porter un.
#[test]
fn le_dernier_arobase_fait_l_hote() {
    let compose = enveloppe(b"From: \"a@b\" <c@d.test>\r\n\r\n");
    assert!(
        compose.contains("(\"a@b\" NIL \"c\" \"d.test\")"),
        "{compose}"
    );
}

/// Une adresse sans arobase n'a pas d'hôte, et le dire vaut mieux que d'en
/// inventer un.
#[test]
fn une_adresse_sans_arobase_n_a_pas_d_hote() {
    let compose = enveloppe(b"From: local\r\n\r\n");
    assert!(compose.contains("((NIL NIL \"local\" NIL))"), "{compose}");
}

/// **On ne décode rien** : les mots encodés se recopient encodés (§7.5.2).
#[test]
fn les_mots_encodes_ne_se_decodent_pas() {
    let compose = enveloppe(b"Subject: =?utf-8?B?w6l0w6k=?=\r\n\r\n");
    assert!(compose.contains("\"=?utf-8?B?w6l0w6k=?=\""), "{compose}");
}

/// **Le pliage disparaît** : un `CRLF` suivi d'un blanc n'est pas du texte.
#[test]
fn le_pliage_ne_se_rend_pas() {
    let compose = enveloppe(b"Subject: un sujet\r\n  qui se plie\r\n\r\n");
    assert!(compose.contains("\"un sujet qui se plie\""), "{compose}");
    let adresses = enveloppe(b"To: a@x.test,\r\n b@y.test\r\n\r\n");
    assert!(
        adresses.contains("((NIL NIL \"a\" \"x.test\")(NIL NIL \"b\" \"y.test\"))"),
        "{adresses}"
    );
}

#[test]
fn les_champs_absents_valent_nil() {
    let compose = enveloppe(b"X-Rien: rien\r\n\r\n");
    assert_eq!(compose, "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)");
}

/// Un champ présent mais sans aucune adresse lisible ne désigne personne.
#[test]
fn un_champ_sans_adresse_lisible_vaut_nil() {
    let compose = enveloppe(b"To:   \r\n\r\n");
    assert!(compose.starts_with("(NIL NIL NIL NIL NIL NIL"), "{compose}");
}

/// **Le premier champ fait foi** : un message à deux `From:` est mal formé, et
/// prendre le dernier laisserait qui l'a fabriqué choisir lequel on montre.
#[test]
fn le_premier_champ_fait_foi() {
    let compose = enveloppe(b"From: a@x.test\r\nFrom: b@y.test\r\n\r\n");
    assert!(compose.contains("\"a\" \"x.test\""), "{compose}");
    assert!(!compose.contains("\"b\" \"y.test\""), "{compose}");
}

#[test]
fn in_reply_to_et_message_id_se_recopient() {
    let compose = enveloppe(
        b"Message-Id: <abc@x.test>\r\nIn-Reply-To: <def@y.test>\r\nDate: Mon, 1 Jan 2020 00:00:00 +0000\r\n\r\n",
    );
    assert!(
        compose.starts_with("(\"Mon, 1 Jan 2020 00:00:00 +0000\" NIL"),
        "{compose}"
    );
    assert!(
        compose.ends_with("\"<def@y.test>\" \"<abc@x.test>\")"),
        "{compose}"
    );
}

/// **Un tampon trop court le dit**, plutôt que d'écrire une enveloppe à moitié.
#[test]
fn un_tampon_trop_court_le_dit() {
    // Une forme par chemin d'écriture : sans quoi la première faute masquerait
    // toutes les suivantes, et des morceaux de la composition ne seraient jamais
    // éprouvés à court de place.
    for entete in [
        &b"From: \"Jean Dupont\" <jean@exemple.test>\r\nSubject: bonjour\r\n\r\n"[..],
        b"To: Amis: a@x.test, b@y.test;\r\n\r\n",
        b"To: (le vrai) Jean <jean@exemple.test>, sans-arobase\r\n\r\n",
        b"From: a@x.test\r\nDate: hier\r\nMessage-Id: <m@x>\r\nIn-Reply-To: <r@x>\r\n\r\n",
        b"To: \"a\\\"b\" <c@d.test>\r\n\r\n",
        b"X-Rien: rien\r\n\r\n",
        // Un sujet à plusieurs mots, un nom nu à plusieurs mots, un nom cité qui
        // commence par un blanc, une fermeture de groupe sans groupe, un champ
        // sans adresse : autant de chemins d'écriture distincts.
        b"Subject: deux mots\r\n\r\n",
        b"From: Jean Dupont <a@b.test>\r\n\r\n",
        b"From: \" Jean Dupont\" <a@b.test>\r\n\r\n",
        b"To: ;\r\n\r\n",
        b"To:   \r\n\r\n",
        // Un champ qui porte du texte mais aucune adresse, et un nom fait d'un
        // mot nu suivi d'un mot cité.
        b"To: ,,\r\n\r\n",
        b"From: Jean \"Dupont\" <a@b.test>\r\n\r\n",
    ] {
        let mut assez = [0_u8; 4096];
        let entiere = write_envelope(entete, &mut assez, &BORNES).expect("composable");
        for taille in 0..entiere {
            let mut petit = std::vec![0_u8; taille];
            assert_eq!(
                write_envelope(entete, &mut petit, &BORNES),
                Err(Error::BufferTooSmall),
                "taille {taille} pour {:?}",
                core::str::from_utf8(entete)
            );
        }
    }
}

/// **Le nombre d'adresses est borné** : sans quoi un seul message ferait écrire
/// autant de structures que sa taille le permet.
#[test]
fn le_nombre_d_adresses_est_borne() {
    // Le champ est PLIÉ : une ligne d'en-tête ne dépasse pas 998 octets
    // (RFC 5322 §2.1.1), et une adresse par ligne reste bien en deçà.
    let mut entete = std::vec::Vec::from(&b"To:"[..]);
    for _ in 0..(super::ENVELOPE_ADDRESSES_MAX + 20) {
        entete.extend_from_slice(b"\r\n a@x.test,");
    }
    entete.pop();
    entete.extend_from_slice(b"\r\n\r\n");
    let mut sortie = std::vec![0_u8; 65536];
    let ecrits = write_envelope(&entete, &mut sortie, &BORNES).expect("composable");
    let compose = std::string::String::from_utf8_lossy(sortie.get(..ecrits).unwrap_or_default());
    assert_eq!(
        compose.matches("\"a\" \"x.test\"").count(),
        super::ENVELOPE_ADDRESSES_MAX
    );
}

/// Un en-tête qu'on ne sait pas lire n'a pas d'enveloppe.
#[test]
fn un_entete_illisible_n_a_pas_d_enveloppe() {
    let mut sortie = [0_u8; 4096];
    assert!(write_envelope(b" pas un en-tete\r\n\r\n", &mut sortie, &BORNES).is_err());
}

/// **Ce qui ne se ferme pas se lit jusqu'au bout**, sans jamais sortir du
/// texte : une chaîne, un commentaire ou un chevron laissé ouvert est une
/// écriture fautive, pas une raison de boucler ou de déborder.
#[test]
fn ce_qui_ne_se_ferme_pas_se_lit_jusqu_au_bout() {
    for entete in [
        &b"From: \"jamais fermee <a@b.test>\r\n\r\n"[..],
        b"From: (jamais ferme <a@b.test>\r\n\r\n",
        b"From: <jamais ferme\r\n\r\n",
        b"From: <\"dedans\" jamais ferme\r\n\r\n",
        // Un antislash en fin de chaîne, et en fin de commentaire.
        b"From: \"fin\\\r\n\r\n",
        b"From: (fin\\\r\n\r\n",
    ] {
        // Ce qu'on demande ici n'est pas un résultat : c'est que la composition
        // se termine, et qu'elle tienne dans ce qu'on lui donne.
        let mut sortie = [0_u8; 4096];
        let _ = write_envelope(entete, &mut sortie, &BORNES);
    }
}

/// Un nom qui n'est qu'une paire de guillemets ne vaut rien.
#[test]
fn un_nom_vide_entre_guillemets_ne_vaut_rien() {
    assert!(enveloppe(b"From: \"\" <a@b.test>\r\n\r\n").contains("(NIL NIL \"a\" \"b.test\")"));
}

/// Un arobase dans un commentaire n'est pas celui de l'adresse.
#[test]
fn un_arobase_dans_un_commentaire_ne_compte_pas() {
    let compose = enveloppe(b"From: <a(x@y)@b.test>\r\n\r\n");
    assert!(compose.contains("\"b.test\""), "{compose}");
}

/// Un mot nu et un mot cité se recollent avec l'espace qui les séparait.
#[test]
fn un_nom_mele_de_cite_et_de_nu_se_recolle() {
    assert!(
        enveloppe(b"From: Jean \"Dupont\" <a@b.test>\r\n\r\n")
            .contains("(\"Jean Dupont\" NIL \"a\" \"b.test\")")
    );
}

/// Un champ qui porte du texte sans porter d'adresse ne désigne personne.
#[test]
fn un_champ_de_virgules_ne_designe_personne() {
    let compose = enveloppe(b"To: ,,\r\n\r\n");
    assert!(compose.starts_with("(NIL NIL NIL NIL NIL NIL"), "{compose}");
}

/// UN PLI TOMBÉ DANS UN NOM CITÉ NE PART PAS SUR LE FIL. Une chaîne IMAP ne peut
/// porter de fin de ligne : le client lirait la fin de la réponse au milieu du
/// nom, puis la suite du dialogue comme du protocole.
#[test]
fn un_pli_dans_un_nom_cite_redevient_un_blanc() {
    let compose = enveloppe(b"From: \"Jean\r\n Dupont\" <a@b.test>\r\n\r\n");
    assert!(
        compose.contains("(\"Jean Dupont\" NIL \"a\" \"b.test\")"),
        "{compose}"
    );
    assert!(
        !compose.contains('\r') && !compose.contains('\n'),
        "{compose}"
    );
}

/// Un pli échappé reste un pli : l'antislash de la RFC 5322 ne fait pas d'une
/// fin de ligne du texte.
///
/// Le pli OUVRE ici le nom, parce que c'est le seul endroit où l'élagage ne l'a
/// pas déjà emporté : le contrôle qui précède l'écriture doit alors le sauter
/// comme la plume le saute. Le blanc qui suit le `CRLF`, lui, RESTE — il est
/// entre les guillemets, donc il appartient au nom, et c'est précisément
/// pourquoi le pli s'efface au lieu d'en ajouter un second.
#[test]
fn un_pli_echappe_dans_un_nom_cite_redevient_un_blanc() {
    let compose = enveloppe(b"From: \"\\\r\n Dupont\" <a@b.test>\r\n\r\n");
    assert!(
        compose.contains("(\" Dupont\" NIL \"a\" \"b.test\")"),
        "{compose}"
    );
}

/// Un nom qui n'est QU'UN PLI ne vaut rien : `NIL`, et non des guillemets vides.
/// Le blanc du pli tombe à l'élagage, et il ne reste rien à citer.
#[test]
fn un_nom_qui_n_est_qu_un_pli_ne_vaut_rien() {
    let compose = enveloppe(b"From: \"\r\n \r\n\r\n");
    assert!(compose.contains("((NIL NIL NIL NIL))"), "{compose}");
}

/// Le dernier octet d'un nom cité est du texte comme les autres — y compris
/// quand c'est le seul. Un nom d'une lettre est le cas où le contrôle qui
/// précède l'écriture et l'écriture elle-même doivent s'arrêter au même octet.
#[test]
fn le_dernier_octet_d_un_nom_cite_compte() {
    let compose = enveloppe(b"From: \"J\" <a@b.test>\r\n\r\n");
    assert!(
        compose.contains("(\"J\" NIL \"a\" \"b.test\")"),
        "{compose}"
    );
}
