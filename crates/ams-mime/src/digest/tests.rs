// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un résumé rend, et ce qu'il refuse de rendre.

use super::{DIGEST_FROM_MAX, DIGEST_SUBJECT_MAX, Digest, write_digest};
use crate::limits::Limits;

/// Résume cet en-tête, et rend les deux textes.
fn resumer(entete: &[u8]) -> (Digest, std::string::String, std::string::String) {
    let mut sujet = [0_u8; DIGEST_SUBJECT_MAX];
    let mut expediteur = [0_u8; DIGEST_FROM_MAX];
    let vu = write_digest(entete, &mut sujet, &mut expediteur, &Limits::DEFAULT);
    let lire = |octets: &[u8], combien: Option<usize>| {
        combien.map_or_else(std::string::String::new, |n| {
            std::string::String::from_utf8_lossy(octets.get(..n).unwrap_or_default()).into_owned()
        })
    };
    (vu, lire(&sujet, vu.subject), lire(&expediteur, vu.from))
}

/// **LE SUJET SE DÉCODE, ET L'ADRESSE SE DÉGAGE DE SON NOM.**
#[test]
fn un_resume_rend_le_sujet_decode_et_l_adresse_seule() {
    let entete = b"From: \"Jean Dupont\" <jean@example.test>\r\n\
                   Subject: =?utf-8?B?ZmFjdHVyZQ==?=\r\n\
                   \r\n";
    let (vu, sujet, expediteur) = resumer(entete);
    assert_eq!(vu.subject, Some(7), "« facture »");
    assert_eq!(sujet, "facture");
    assert_eq!(expediteur, "jean@example.test", "et non le nom d'affichage");
}

/// **UN NOM D'AFFICHAGE QUI MENT NE PASSE PAS POUR UNE ADRESSE.**
///
/// C'est la forme ordinaire de l'hameçonnage, et rien dans la RFC 5322 ne
/// l'interdit. Rendre le nom ferait afficher au client ce que l'expéditeur a
/// choisi de lui faire lire.
#[test]
fn un_nom_qui_ment_ne_devient_pas_l_adresse() {
    let entete = b"From: \"support@banque.test\" <pirate@example.test>\r\n\r\n";
    let (_vu, _sujet, expediteur) = resumer(entete);
    assert_eq!(expediteur, "pirate@example.test");
}

/// **L'ABSENCE ET LE VIDE NE SONT PAS LA MÊME CHOSE.**
///
/// Un message sans `Subject:` n'a pas de sujet ; un `Subject:` vide en a un, qui
/// est vide. Les confondre ferait mentir la liste dans les deux sens.
#[test]
fn l_absence_et_le_vide_se_distinguent() {
    let (vu, _sujet, _expediteur) = resumer(b"From: jean@example.test\r\n\r\n");
    assert_eq!(vu.subject, None, "aucun champ `Subject:`");

    let (vu, sujet, _expediteur) = resumer(b"Subject:\r\nFrom: jean@example.test\r\n\r\n");
    assert_eq!(vu.subject, Some(0), "un champ présent, et vide");
    assert_eq!(sujet, "");
}

/// **UN PLI S'EFFACE, IL NE DEVIENT PAS UN BLANC** (§2.2.3 de RFC 5322).
///
/// Le blanc qui suit le `CRLF` appartient déjà à la valeur : le remplacer en
/// mettrait deux. C'est la règle que suit déjà l'`ENVELOPE`, et deux règles pour
/// un même pli donneraient deux textes pour un même message.
#[test]
fn un_pli_s_efface_et_ne_laisse_pas_deux_blancs() {
    let entete = b"Subject: la facture\r\n de mars\r\nFrom: jean@example.test\r\n\r\n";
    let (_vu, sujet, _expediteur) = resumer(entete);
    assert_eq!(sujet, "la facture de mars");
    assert!(
        !sujet.contains('\r') && !sujet.contains('\n'),
        "et il ne reste aucune fin de ligne"
    );
}

/// **LE BLANC ENTRE DEUX MOTS ENCODÉS DISPARAÎT**, pli compris (§6.2 de
/// RFC 2047).
///
/// Il ne sert qu'à les séparer : le garder couperait en deux un texte que
/// l'expéditeur a dû découper pour tenir dans une ligne.
#[test]
fn deux_mots_encodes_separes_par_un_pli_se_recollent() {
    let entete = b"Subject: =?utf-8?Q?fac?=\r\n =?utf-8?Q?ture?=\r\n\r\n";
    let (_vu, sujet, _expediteur) = resumer(entete);
    assert_eq!(sujet, "facture");
}

/// **UN SUJET QU'ON NE PEUT PAS RENDRE ENTIER N'EST PAS RENDU.**
///
/// Le tronquer ferait afficher un texte qui n'est pas celui du message — et,
/// pire, un texte qu'on aurait choisi de couper là.
#[test]
fn un_sujet_trop_long_n_est_pas_rendu_a_moitie() {
    // **PLIÉ, ET NON D'UN SEUL TENANT** : une ligne plus longue que ce que §2.1.1
    // recommande ferait refuser tout l'en-tête, et l'essai montrerait alors la
    // borne de ligne au lieu de celle du tampon.
    let mut entete = std::vec::Vec::from(&b"Subject:"[..]);
    for _ in 0..=DIGEST_SUBJECT_MAX / 64 {
        entete.extend_from_slice(b"\r\n ");
        entete.extend(std::iter::repeat_n(b'a', 64));
    }
    entete.extend_from_slice(b"\r\nFrom: jean@example.test\r\n\r\n");
    let (vu, _sujet, expediteur) = resumer(&entete);
    assert_eq!(vu.subject, None, "rien plutôt qu'une moitié");
    assert_eq!(
        expediteur, "jean@example.test",
        "et l'autre champ est rendu quand même"
    );
}

/// **UN `From:` À PLUSIEURS ADRESSES NE REND RIEN** (§3.6.2 de RFC 5322).
///
/// Il l'admet — un message écrit à plusieurs mains — et demande alors un
/// `Sender:`. En choisir une désignerait un auteur que le message ne désigne pas.
#[test]
fn un_expediteur_multiple_ne_designe_personne() {
    let entete = b"From: jean@example.test, marie@example.test\r\nSubject: a\r\n\r\n";
    let (vu, sujet, _expediteur) = resumer(entete);
    assert_eq!(vu.from, None);
    assert_eq!(sujet, "a", "et le sujet est rendu quand même");
}

/// **UNE ADRESSE PLUS LONGUE QUE LE TAMPON N'EST PAS RENDUE À MOITIÉ.**
///
/// §4.5.3.1.3 de RFC 5321 borne un chemin ; au-delà, c'est le message qui sort
/// des clous, et une adresse coupée en désignerait une autre.
#[test]
fn une_adresse_trop_longue_n_est_pas_rendue() {
    let mut entete = std::vec::Vec::from(&b"From: "[..]);
    entete.extend(std::iter::repeat_n(b'a', DIGEST_FROM_MAX));
    entete.extend_from_slice(b"@example.test\r\n\r\n");
    let (vu, _sujet, _expediteur) = resumer(&entete);
    assert_eq!(vu.from, None);
}

/// **UN EN-TÊTE QU'ON NE SAIT PAS LIRE NE REND RIEN, ET NE FAUTE PAS.**
///
/// Un résumé est une commodité d'affichage : refuser toute une page parce qu'un
/// message est mal formé servirait moins bien le client que de lui rendre `null`.
#[test]
fn un_en_tete_illisible_ne_rend_rien() {
    let mut trop = std::vec::Vec::new();
    for rang in 0..=Limits::DEFAULT.max_fields {
        trop.extend_from_slice(b"X-Bruit-");
        trop.extend_from_slice(std::format!("{rang}").as_bytes());
        trop.extend_from_slice(b": x\r\n");
    }
    trop.extend_from_slice(b"\r\n");
    let (vu, _sujet, _expediteur) = resumer(&trop);
    assert_eq!(vu, Digest::default(), "ni sujet, ni expéditeur, ni faute");
}

/// **CE QU'ON NE PEUT PAS AFFICHER COMME UNE ADRESSE N'EST PAS RENDU.**
///
/// `sole_address` sert d'abord à trouver un DOMAINE : sans chevrons, elle rend la
/// valeur entière — blanc, plis et commentaires compris —, et le découpage du
/// domaine écarte ensuite ce qui traîne. C'est juste pour ce qu'elle sert, et
/// insuffisant pour ce qu'on affiche : un client lirait autre chose qu'une
/// adresse, et croirait que c'en est une.
#[test]
fn ce_qui_n_est_pas_une_adresse_n_est_pas_rendu() {
    for valeur in [
        &b"From: pas-d-arobase-ici\r\n\r\n"[..],
        // Un blanc au milieu : ce n'est plus une adresse, c'est ce qui
        // l'entourait.
        b"From: jean @ example.test\r\n\r\n",
        // Un commentaire, que §3.2.2 de RFC 5322 admet et qui n'est pas l'adresse.
        b"From: jean@example.test (chez lui)\r\n\r\n",
        // Rien que du blanc.
        b"From: \r\n\r\n",
        // Pas de champ du tout.
        b"Subject: a\r\n\r\n",
    ] {
        let (vu, _sujet, _expediteur) = resumer(valeur);
        assert_eq!(
            vu.from,
            None,
            "« {} »",
            std::string::String::from_utf8_lossy(valeur)
        );
    }
}
