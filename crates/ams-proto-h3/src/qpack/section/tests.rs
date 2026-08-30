// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une section de champs entière a le droit d'être.

use ams_proto_http::{Limits, Method, StatusCode};
use std::string::String;

use super::{read_section, write_section};
use crate::error::{H3Error, Reason};

/// Assemble une section : un préfixe nul, puis des octets.
fn section(corps: &[u8]) -> std::vec::Vec<u8> {
    let mut sortie = std::vec::Vec::from([0_u8, 0]);
    sortie.extend_from_slice(corps);
    sortie
}

/// **LA JOINTURE** : une section devient une requête, et tout tient dans un
/// seul tampon.
#[test]
fn une_section_devient_une_requete() {
    // `:method GET` est à l'index 17 de la table statique, `:scheme https` à 23,
    // `:authority` à 0 (avec une valeur écrite), `:path` à 1.
    let mut corps = std::vec::Vec::from([
        0b1100_0000_u8 | 17, // indexé statique : :method GET
        0b1100_0000 | 23,    // indexé statique : :scheme https
        0b0101_0000,         // nom indexé statique 0 (:authority), valeur écrite
        12,
    ]);
    corps.extend_from_slice(b"exemple.test");
    corps.push(0b0101_0001); // nom indexé statique 1 (:path), valeur écrite
    corps.push(10);
    corps.extend_from_slice(b"/comptes/7");
    let brut = section(&corps);

    let mut place = [0_u8; 1024];
    let requete = read_section(&brut, &mut place, &Limits::DEFAULT).expect("bien formée");
    assert_eq!(requete.method(), Method::Get);
    assert_eq!(requete.scheme(), b"https");
    assert_eq!(requete.authority(), b"exemple.test");
    assert_eq!(requete.path(), b"/comptes/7");
}

/// Un champ ordinaire écrit en entier se lit aussi.
#[test]
fn un_champ_ecrit_en_entier_se_lit() {
    let mut corps = std::vec::Vec::from([
        0b1100_0000_u8 | 17,
        0b1100_0000 | 23,
        0b0101_0000,
        1,
        b'a',
        0b0101_0001,
        1,
        b'/',
    ]);
    // §4.5.6 : `001` + `N=0` + `H=0` + longueur 6, puis « x-truc », puis « oui ».
    corps.push(0b0010_0110);
    corps.extend_from_slice(b"x-truc");
    corps.push(3);
    corps.extend_from_slice(b"oui");
    let brut = section(&corps);

    let mut place = [0_u8; 1024];
    let requete = read_section(&brut, &mut place, &Limits::DEFAULT).expect("bien formée");
    assert_eq!(requete.field(b"x-truc"), Some(b"oui".as_slice()));
}

/// **UN INDEX DYNAMIQUE NE DÉSIGNE RIEN** : nous n'avons pas de table, et le
/// pair n'avait pas le droit d'y mettre quoi que ce soit.
#[test]
fn un_index_dynamique_ne_designe_rien() {
    let cas: [&[u8]; 4] = [
        &[0b1000_0000],       // indexé dynamique
        &[0b0001_0000],       // indexé après le rang
        &[0b0100_0000, 0x00], // nom indexé dynamique
        &[0b0000_0000, 0x00], // nom après le rang
    ];
    for corps in cas {
        let brut = section(corps);
        let mut place = [0_u8; 256];
        let issue = read_section(&brut, &mut place, &Limits::DEFAULT).expect_err("sans table");
        assert_eq!(issue.reason(), Reason::BadIndex, "{corps:02x?}");
        assert_eq!(issue.code(), H3Error::QpackDecompressionFailed);
    }
}

/// Un index statique au-delà de la table ne désigne rien non plus.
#[test]
fn un_index_statique_hors_table_ne_designe_rien() {
    for corps in [
        std::vec::Vec::from([0b1111_1111_u8, 0x24]), // index 99, hors table
        std::vec::Vec::from([0b0101_1111_u8, 0x54, 0x00]), // nom index 99
    ] {
        let brut = section(&corps);
        let mut place = [0_u8; 256];
        let issue = read_section(&brut, &mut place, &Limits::DEFAULT).expect_err("hors table");
        assert_eq!(issue.reason(), Reason::BadIndex, "{corps:02x?}");
    }
}

/// **UNE SECTION QUI RÉCLAME DES INSERTIONS N'ATTENDRAIT PAS : ELLE ATTENDRAIT
/// POUR TOUJOURS.** On le dit plutôt que de le subir.
#[test]
fn une_section_qui_reclame_des_insertions_se_refuse() {
    let brut = [0x01_u8, 0x00];
    let mut place = [0_u8; 256];
    let issue = read_section(&brut, &mut place, &Limits::DEFAULT).expect_err("sans table");
    assert_eq!(issue.reason(), Reason::BadInsertCount);
}

/// **DEUX FAMILLES DE FAUTES** : une liste bien décomprimée qui ne fait pas une
/// requête ne condamne que son flux (§4.1.2 de RFC 9114).
#[test]
fn une_liste_malformee_ne_condamne_que_son_flux() {
    // `:method GET` et `:scheme https`, sans `:path` ni `:authority`.
    let corps = [0b1100_0000 | 17, 0b1100_0000 | 23];
    let brut = section(&corps);
    let mut place = [0_u8; 256];
    let issue = read_section(&brut, &mut place, &Limits::DEFAULT).expect_err("il manque un pseudo");
    assert_eq!(issue.reason(), Reason::MalformedRequest);
    assert_eq!(issue.code(), H3Error::MessageError);
}

/// Une section tronquée, et un tampon qui ne suffit pas.
#[test]
fn une_section_mal_formee_se_refuse() {
    let mut place = [0_u8; 256];
    for brut in [[0_u8; 0].as_slice(), &[0x00]] {
        let issue = read_section(brut, &mut place, &Limits::DEFAULT).expect_err("tronquée");
        assert_eq!(issue.reason(), Reason::Truncated, "{brut:02x?}");
    }
    // Une valeur qui ment sur sa taille.
    let brut = section(&[0b0101_0000, 0x05, b'/']);
    let issue = read_section(&brut, &mut place, &Limits::DEFAULT).expect_err("elle ment");
    assert_eq!(issue.reason(), Reason::BadFieldLine);
}

/// **UNE RÉPONSE S'ÉCRIT ET SE RELIT** : l'index statique quand il existe, le
/// nom seul sinon, et le tout écrit sinon encore.
#[test]
fn une_reponse_s_ecrit_au_plus_court() {
    let ok = StatusCode::new(200).expect("licite");
    let mut place = [0_u8; 512];

    // `:status 200` est à l'index 25 : le préfixe plus un octet.
    let ecrits = write_section(ok, &[], &mut place).expect("écrivable");
    assert_eq!(ecrits, 3, "deux octets de préfixe, un de statut");
    assert_eq!(place.get(..2), Some([0_u8, 0].as_slice()), "préfixe nul");
    assert_eq!(place.get(2), Some(&(0b1100_0000 | 25)));

    // `content-type` a un nom dans la table statique, avec d'autres valeurs :
    // le nom s'indexe, la valeur s'écrit.
    let ecrits = write_section(ok, &[(b"content-type", b"application/x-truc")], &mut place)
        .expect("écrivable");
    assert!(ecrits > 3);

    // Un nom qui n'est nulle part s'écrit en entier.
    let ecrits = write_section(ok, &[(b"x-mon-champ", b"oui")], &mut place).expect("écrivable");
    let premier = place.get(3).copied().expect("écrit");
    assert_eq!(premier & 0b1110_0000, 0b0010_0000, "un littéral complet");
    assert!(ecrits > 3);
}

/// **CE QU'ON REFUSE DE RECEVOIR, ON REFUSE DE L'ÉCRIRE** — la même règle qu'en
/// HTTP/2, et elle vit au même endroit.
#[test]
fn un_champ_de_reponse_interdit_se_refuse() {
    let ok = StatusCode::new(200).expect("licite");
    let mut place = [0_u8; 512];
    for (nom, valeur) in [
        (b"connection".as_slice(), b"close".as_slice()),
        (b"transfer-encoding", b"chunked"),
        (b":status", b"200"),
        (b"Content-Type", b"text/plain"),
        (b"content-type", b"text/plain\r\nx: y"),
        (b"", b"vide"),
    ] {
        let issue = write_section(ok, &[(nom, valeur)], &mut place).expect_err("refusé");
        assert_eq!(
            issue.reason(),
            Reason::BadResponseField,
            "{}",
            String::from_utf8_lossy(nom)
        );
        assert_eq!(issue.code(), H3Error::InternalError);
    }
}

/// La place manque à l'écriture, et c'est notre tampon.
#[test]
fn l_ecriture_veut_de_la_place() {
    let ok = StatusCode::new(200).expect("licite");
    let complet = {
        let mut place = [0_u8; 512];
        write_section(ok, &[(b"x-mon-champ", b"oui")], &mut place).expect("écrivable")
    };
    for taille in 0..complet {
        let mut court = [0_u8; 512];
        let issue = write_section(
            ok,
            &[(b"x-mon-champ", b"oui")],
            court.get_mut(..taille).expect("assez court"),
        )
        .expect_err("la place manque");
        assert_eq!(issue.reason(), Reason::BufferTooSmall, "{taille}");
    }
}

/// **TOUS LES STATUTS S'ÉCRIVENT EN TROIS CHIFFRES**, ceux que la table statique
/// ne porte pas comme les autres.
#[test]
fn chaque_statut_s_ecrit_en_trois_chiffres() {
    let mut place = [0_u8; 512];
    for code in [100_u16, 200, 204, 301, 404, 418, 500, 599] {
        let statut = StatusCode::new(code).expect("licite");
        let ecrits = write_section(statut, &[], &mut place).expect("écrivable");
        assert!(ecrits >= 3, "{code}");
    }
}

/// **UN CHAMP QUE LA SÉMANTIQUE REFUSE NE CONDAMNE QUE SON FLUX** : la
/// décompression a réussi, c'est le MESSAGE qui ne tient pas debout.
#[test]
fn un_champ_refuse_par_la_semantique_ne_condamne_que_son_flux() {
    // Une requête complète, plus `transfer-encoding` que §8.2.2 interdit.
    let mut corps = std::vec::Vec::from([
        0b1100_0000_u8 | 17,
        0b1100_0000 | 23,
        0b0101_0000,
        1,
        b'a',
        0b0101_0001,
        1,
        b'/',
    ]);
    // Le préfixe de longueur fait TROIS bits : dix-sept ne s'y écrit pas d'un
    // coup, et se poursuit sur l'octet suivant. C'est exactement le genre de
    // détail qu'on manque en écrivant l'octet à la main.
    corps.push(0b0010_0111);
    corps.push(17 - 7);
    corps.extend_from_slice(b"transfer-encoding");
    corps.push(7);
    corps.extend_from_slice(b"chunked");
    let brut = section(&corps);

    let mut place = [0_u8; 1024];
    let issue = read_section(&brut, &mut place, &Limits::DEFAULT).expect_err("§8.2.2");
    assert_eq!(issue.reason(), Reason::MalformedRequest);
    assert_eq!(issue.code(), H3Error::MessageError);
}

/// **UN NOM QUE HUFFMAN N'AIME PAS S'ÉCRIT EN CLAIR** : le codage ne raccourcit
/// que ce qu'il sait raccourcir, et comprimer d'office allongerait ces noms-là.
#[test]
fn un_nom_que_huffman_n_aime_pas_s_ecrit_en_clair() {
    let ok = StatusCode::new(200).expect("licite");
    let mut place = [0_u8; 512];
    // `~` coûte treize bits : quatre en font sept octets, contre quatre en
    // clair.
    let ecrits = write_section(ok, &[(b"~~~~", b"oui")], &mut place).expect("écrivable");
    let premier = place.get(3).copied().expect("écrit");
    assert_eq!(premier & 0b0000_1000, 0, "le fanion de Huffman est à zéro");
    assert_eq!(premier & 0b0000_0111, 4, "quatre octets de nom");
    assert!(ecrits > 3);

    // Et un nom que Huffman raccourcit, lui, se comprime.
    let ecrits =
        write_section(ok, &[(b"x-un-nom-plutot-long", b"oui")], &mut place).expect("écrivable");
    let premier = place.get(3).copied().expect("écrit");
    assert_ne!(premier & 0b0000_1000, 0, "le fanion de Huffman est à un");
    assert!(ecrits > 3);
}

/// La place manque, sur chacun des trois chemins d'écriture.
#[test]
fn chaque_chemin_d_ecriture_veut_de_la_place() {
    let ok = StatusCode::new(200).expect("licite");
    let cas: [(&[u8], &[u8]); 4] = [
        // Nom ET valeur dans la table statique : un seul octet.
        (b"accept-ranges", b"bytes"),
        // Nom seul dans la table : l'index, puis la valeur écrite.
        (b"content-type", b"application/x-truc"),
        // Rien dans la table, et le nom se comprime.
        (b"x-mon-champ", b"oui"),
        // Rien dans la table, et le nom NE se comprime PAS : c'est un
        // quatrième chemin, avec sa propre borne de place.
        (b"~~~~", b"oui"),
    ];
    for (nom, valeur) in cas {
        let complet = {
            let mut place = [0_u8; 512];
            write_section(ok, &[(nom, valeur)], &mut place).expect("écrivable")
        };
        for taille in 0..complet {
            let mut court = [0_u8; 512];
            let issue = write_section(
                ok,
                &[(nom, valeur)],
                court.get_mut(..taille).expect("assez court"),
            )
            .expect_err("la place manque");
            assert_eq!(
                issue.reason(),
                Reason::BufferTooSmall,
                "{} à {taille}",
                String::from_utf8_lossy(nom)
            );
        }
    }
}
