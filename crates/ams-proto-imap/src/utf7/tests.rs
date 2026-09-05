// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que l'UTF-7 modifié doit rendre, et ce qu'il doit refuser.

use super::{decode, encode};
use crate::error::Error;

/// Décode, et rend le texte.
fn dec(entree: &[u8]) -> Result<std::string::String, Error> {
    let mut place = [0_u8; 512];
    let ecrits = decode(entree, &mut place)?;
    Ok(std::string::String::from_utf8_lossy(&place[..ecrits]).into_owned())
}

/// Encode, et rend le texte.
fn enc(entree: &str) -> Result<std::string::String, Error> {
    let mut place = [0_u8; 512];
    let ecrits = encode(entree.as_bytes(), &mut place)?;
    Ok(std::string::String::from_utf8_lossy(&place[..ecrits]).into_owned())
}

/// **LES EXEMPLES DE RFC 3501 §5.1.3 EUX-MÊMES.**
///
/// C'est le seul contrôle qu'on ne puisse pas se donner à soi-même : les autres
/// éprouvent ce que ce code fait, celui-ci éprouve ce que la RFC dit.
#[test]
fn les_exemples_de_la_rfc_se_transcrivent_dans_les_deux_sens() {
    for (utf7, utf8) in [
        // §5.1.3 : « le dossier de courrier personnel de 台北 ».
        ("~peter/mail/&U,BTFw-/&ZeVnLIqe-", "~peter/mail/台北/日本語"),
        // L'exemple d'un `&` littéral.
        ("&-", "&"),
        ("Hello&-World", "Hello&World"),
        // Rien à transcrire.
        ("INBOX", "INBOX"),
        ("Sent Messages", "Sent Messages"),
    ] {
        assert_eq!(dec(utf7.as_bytes()).as_deref(), Ok(utf8), "décoder {utf7}");
        assert_eq!(enc(utf8).as_deref(), Ok(utf7), "encoder {utf8}");
    }
}

/// **UN ALLER-RETOUR NE CHANGE PAS LE NOM**, et c'est la propriété qui compte :
/// un nom qui reviendrait différent serait une autre boîte.
#[test]
fn l_aller_retour_est_l_identite() {
    for nom in [
        "Créations",
        "Éléments envoyés",
        "Корзина",
        "垃圾桶",
        "a&b&c",
        "&&&",
        // Un caractère HORS du plan de base, donc écrit sur deux substituts.
        "brouillons 😀",
        "Dossier/Sous-dossier",
        "un espace   et trois",
        "~!@#$%^*()_+`={}[]|;'<>?,.",
    ] {
        let code = enc(nom).expect("encodable");
        assert_eq!(
            dec(code.as_bytes()).as_deref(),
            Ok(nom),
            "aller-retour {nom}"
        );
    }
}

/// **L'ASCII IMPRIMABLE NE S'ÉCHAPPE PAS**, et le vérifier octet par octet
/// ferme la porte à une règle qui dériverait.
#[test]
fn tout_l_ascii_imprimable_se_represente_lui_meme() {
    for octet in 0x20_u8..=0x7E {
        let nom = std::string::String::from_utf8(std::vec![octet]).expect("ascii");
        let attendu = if octet == b'&' {
            std::string::String::from("&-")
        } else {
            nom.clone()
        };
        assert_eq!(
            enc(&nom).as_deref(),
            Ok(attendu.as_str()),
            "octet {octet:#04x}"
        );
    }
}

/// **CE QUI DONNERAIT DEUX ÉCRITURES POUR UN MÊME NOM SE REFUSE.**
///
/// Un nom qui s'écrirait de deux façons ferait deux boîtes que le client
/// croirait une seule — et il ne s'en apercevrait qu'en perdant du courrier.
#[test]
fn deux_ecritures_pour_un_nom_se_refusent() {
    for (entree, pourquoi) in [
        // `&AGE-` code un `a`, qui doit s'écrire directement.
        (&b"&AGE-"[..], "une séquence qui code de l'ASCII imprimable"),
        // Des bits de remplissage non nuls.
        (b"&AOl-", "du remplissage nul est exigé"),
    ] {
        assert_eq!(dec(entree), Err(Error::MalformedMailbox), "{pourquoi}");
    }
}

/// Ce qui n'est pas de l'UTF-7 modifié bien formé se refuse, et ne se devine pas.
#[test]
fn ce_qui_n_est_pas_bien_forme_se_refuse() {
    for (entree, pourquoi) in [
        (&b"&AOk"[..], "une séquence qui ne se ferme pas"),
        (b"&", "un `&` en fin de nom"),
        (b"&*-", "un octet hors de l'alphabet base64 modifié"),
        (b"&AOk-&", "la seconde séquence ne se ferme pas"),
        // Un demi-substitut HAUT sans son bas.
        (b"&2AA-", "un demi-substitut isolé"),
        // Un demi-substitut BAS qui arrive seul.
        (b"&3AA-", "un demi-substitut bas orphelin"),
        // Une séquence vide, qui ne désigne rien.
        (b"&&-", "une séquence vide"),
        // Un octet non-ASCII HORS séquence : ce n'est pas de l'UTF-7.
        (b"Cr\xc3\xa9ations", "de l'UTF-8 brut n'est pas de l'UTF-7"),
        (b"\x01", "un caractère de contrôle"),
        (b"\x7f", "`DEL` n'est pas imprimable"),
    ] {
        assert_eq!(dec(entree), Err(Error::MalformedMailbox), "{pourquoi}");
    }
}

/// De l'UTF-8 invalide ne s'encode pas, et ne se remplace pas non plus.
#[test]
fn de_l_utf8_invalide_ne_s_encode_pas() {
    let mut place = [0_u8; 64];
    assert_eq!(
        encode(b"Cr\xe9ations", &mut place),
        Err(Error::MalformedMailbox),
        "l'octet `0xE9` seul n'est pas de l'UTF-8"
    );
}

/// **UN TAMPON TROP COURT LE DIT**, dans les deux sens et à chaque endroit où
/// l'on écrit — plutôt que de rendre un nom tronqué, qui serait un autre nom.
#[test]
fn un_tampon_trop_court_le_dit() {
    for taille in 0..6_usize {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(
            encode("Créations".as_bytes(), &mut place),
            Err(Error::MalformedMailbox),
            "encoder dans {taille} octets"
        );
    }
    for taille in 0..3_usize {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(
            decode(b"Cr&AOk-ations", &mut place),
            Err(Error::MalformedMailbox),
            "décoder dans {taille} octets"
        );
    }
    // Le `&` littéral aussi demande de la place.
    let mut rien = [0_u8; 0];
    assert_eq!(decode(b"&-", &mut rien), Err(Error::MalformedMailbox));
    assert_eq!(encode(b"&", &mut rien), Err(Error::MalformedMailbox));

    // **LA FERMETURE D'UNE SÉQUENCE DEMANDE DE LA PLACE ELLE AUSSI**, et à deux
    // endroits : celui qui vide les bits restants, et celui qui écrit le `-`.
    // `été&` les emprunte tous les deux — la séquence se ferme avant le `&`.
    for taille in 0..13_usize {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(
            encode("été&".as_bytes(), &mut place),
            Err(Error::MalformedMailbox),
            "encoder `été&` dans {taille} octets"
        );
    }
    // **LA FERMETURE FINALE AUSSI**, quand le nom se termine PAR une séquence :
    // `été` fait `&AOk-t&AOk-`, onze octets, et c'est le dernier `-` qui manque
    // de place à dix.
    for taille in 0..11_usize {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(
            encode("été".as_bytes(), &mut place),
            Err(Error::MalformedMailbox),
            "encoder `été` dans {taille} octets"
        );
    }

    // **TREIZE, ET PAS DOUZE.** Une séquence se ferme À CHAQUE caractère
    // direct — le `t` du milieu — puis se rouvre : `&AOk-t&AOk-`, onze octets,
    // et `&-` en fait deux. §5.1.3 n'exige pas la transcription la plus courte,
    // et celle-ci a l'avantage de n'avoir qu'une règle.
    let mut assez = [0_u8; 13];
    let ecrits = encode("été&".as_bytes(), &mut assez).expect("treize suffisent");
    assert_eq!(&assez[..ecrits], b"&AOk-t&AOk-&-");
}

/// **UN DEMI-SUBSTITUT HAUT SUIVI D'AUTRE CHOSE QU'UN BAS** ne désigne rien.
///
/// C'est le cas que le contrôle de fin ne peut pas attraper : la séquence se
/// ferme bien, et pourtant la paire n'est pas formée.
#[test]
fn un_substitut_haut_mal_apparie_se_refuse() {
    // `&2ADpAA-` : un demi-substitut haut (0xD800), puis `é` (0x00E9) — qui
    // n'est pas un demi-substitut bas.
    assert_eq!(dec(b"&2ADpAA-"), Err(Error::MalformedMailbox));
    // Deux demi-substituts HAUTS de suite.
    assert_eq!(dec(b"&2ADYAA-"), Err(Error::MalformedMailbox));
}

/// **UNE SÉQUENCE SE FERME AVANT UN `&` LITTÉRAL.**
///
/// `été&` demande d'ouvrir une séquence, de la fermer, puis d'écrire `&-`. Sans
/// la fermeture, le `&` serait avalé par la séquence en cours.
#[test]
fn une_sequence_se_ferme_avant_un_esperluette() {
    let code = enc("été&").expect("encodable");
    assert!(
        code.ends_with("-&-"),
        "la séquence se ferme d'abord : {code}"
    );
    assert_eq!(dec(code.as_bytes()).as_deref(), Ok("été&"));
}

/// Chaque erreur du codec se DIT, et se lit.
#[test]
fn l_erreur_se_dit_en_toutes_lettres() {
    let dite = std::format!("{}", Error::MalformedMailbox);
    assert!(dite.contains("nom de boîte"), "{dite}");
    assert!(dite.contains("version"), "{dite}");
}

/// Un nom vide reste vide, dans les deux sens.
#[test]
fn un_nom_vide_traverse() {
    assert_eq!(dec(b"").as_deref(), Ok(""));
    assert_eq!(enc("").as_deref(), Ok(""));
}
