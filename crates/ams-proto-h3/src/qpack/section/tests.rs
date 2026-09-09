// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une section de champs entière a le droit d'être.

use ams_proto_http::{Limits, Method, StatusCode};
use std::string::String;

use super::{read_response_section, read_section, write_request_section, write_section};
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

// ── L'AUTRE SENS : CE QU'UN CLIENT ÉCRIT, ET CE QU'IL LIT ───────────────────

/// **LA JOINTURE, DANS L'AUTRE SENS** : une requête écrite ici se relit par le
/// lecteur de sections d'en face, et rend le même message.
#[test]
fn une_requete_ecrite_se_relit_comme_une_requete() {
    let mut sortie = [0_u8; 256];
    let combien = write_request_section(
        b"POST",
        b"https",
        b"annuaire.example",
        b"/v1/annonce",
        &[(b"content-type", b"application/json")],
        &mut sortie,
    )
    .expect("elle s'écrit");

    let mut place = [0_u8; 512];
    let tete = read_section(
        sortie.get(..combien).expect("la borne"),
        &mut place,
        &Limits::DEFAULT,
    )
    .expect("elle se relit");
    assert_eq!(tete.method(), Method::Post);
    assert_eq!(tete.path(), b"/v1/annonce");
    assert_eq!(tete.authority(), &b"annuaire.example"[..]);
}

#[test]
fn une_requete_qui_ne_tient_pas_dans_le_tampon_se_refuse() {
    // Deux octets de préfixe, et rien pour les champs.
    let mut minuscule = [0_u8; 1];
    assert_eq!(
        write_request_section(b"GET", b"https", b"a", b"/", &[], &mut minuscule)
            .expect_err("il n'y a pas la place")
            .reason(),
        Reason::BufferTooSmall
    );
}

/// Assemble une réponse : un préfixe nul, puis ces octets.
fn reponse(corps: &[u8]) -> std::vec::Vec<u8> {
    section(corps)
}

#[test]
fn une_reponse_ecrite_se_relit_comme_une_reponse() {
    let mut sortie = [0_u8; 256];
    let combien = write_section(
        StatusCode::NOT_FOUND,
        &[(b"content-type", b"application/problem+json")],
        &mut sortie,
    )
    .expect("elle s'écrit");

    let mut place = [0_u8; 512];
    let statut = read_response_section(sortie.get(..combien).expect("la borne"), &mut place)
        .expect("elle se relit");
    assert_eq!(statut, StatusCode::NOT_FOUND);
}

#[test]
fn une_reponse_sans_statut_n_en_est_pas_une() {
    // §4.3.2 : « The ":status" pseudo-header field […] MUST be included in all
    // responses. » Une liste bien décomprimée qui n'en porte pas ne fait pas un
    // message.
    let mut place = [0_u8; 128];
    assert_eq!(
        read_response_section(&reponse(&[]), &mut place)
            .expect_err("il n'y a pas de statut")
            .reason(),
        Reason::MalformedResponse
    );
}

#[test]
fn deux_statuts_ne_se_departagent_pas() {
    // Choisir le premier ou le dernier ferait lire deux réponses différentes à
    // deux implémentations.
    let mut sortie = [0_u8; 256];
    let combien = write_section(StatusCode::OK, &[], &mut sortie).expect("elle s'écrit");
    let une = sortie.get(2..combien).expect("le corps").to_vec();
    let mut deux = une.clone();
    deux.extend_from_slice(&une);

    let mut place = [0_u8; 128];
    assert_eq!(
        read_response_section(&reponse(&deux), &mut place)
            .expect_err("deux statuts")
            .reason(),
        Reason::MalformedResponse
    );
}

#[test]
fn un_statut_apres_un_champ_ordinaire_est_refuse() {
    // §4.3 : « All pseudo-header fields MUST appear in the field section before
    // regular header fields. »
    let mut sortie = [0_u8; 256];
    let combien = write_section(StatusCode::OK, &[], &mut sortie).expect("elle s'écrit");
    let statut = sortie.get(2..combien).expect("le corps").to_vec();

    let mut avec_champ = [0_u8; 256];
    let combien =
        write_section(StatusCode::OK, &[(b"age", b"1")], &mut avec_champ).expect("elle s'écrit");
    // On garde le champ ordinaire seul, puis on remet le statut derrière.
    let tout = avec_champ.get(2..combien).expect("le corps").to_vec();
    let ordinaire = tout
        .get(statut.len()..)
        .expect("ce qui suit le statut")
        .to_vec();
    let mut renverse = ordinaire;
    renverse.extend_from_slice(&statut);

    let mut place = [0_u8; 128];
    assert_eq!(
        read_response_section(&reponse(&renverse), &mut place)
            .expect_err("le statut vient après un champ ordinaire")
            .reason(),
        Reason::MalformedResponse
    );
}

#[test]
fn un_pseudo_champ_de_requete_dans_une_reponse_est_refuse() {
    // §4.3 : une réponse n'a qu'un pseudo-champ, et c'est `:status`.
    // `:path` est l'index 1 de la table statique.
    let mut place = [0_u8; 128];
    assert_eq!(
        read_response_section(&reponse(&[0b1100_0001]), &mut place)
            .expect_err(":path n'a rien à faire dans une réponse")
            .reason(),
        Reason::MalformedResponse
    );
}

#[test]
fn un_statut_qui_n_est_pas_trois_chiffres_est_refuse() {
    // Index 24 de la table statique : `:status` avec un nom seulement, suivi
    // d'une valeur littérale. `0101_1000` = `01NTxxxx` avec l'index 24 sur
    // quatre bits, donc une continuation.
    let mut section = std::vec::Vec::from([0_u8, 0]);
    // `:status` sans valeur — index 24, encodé sur 4 bits : 24 >= 15, donc
    // préfixe plein puis la continuation.
    section.extend_from_slice(&[0b0101_1111, 24 - 15]);
    // Une valeur littérale de deux caractères : « ok ».
    section.extend_from_slice(&[0b0000_0010, b'o', b'k']);

    let mut place = [0_u8; 128];
    assert_eq!(
        read_response_section(&section, &mut place)
            .expect_err("« ok » n'est pas un code d'état")
            .reason(),
        Reason::MalformedResponse
    );
}

#[test]
fn une_reponse_qui_reclame_la_table_dynamique_ne_designe_rien() {
    // Nous avons annoncé une table nulle : le serveur n'a pas pu y mettre quoi
    // que ce soit, et un index qui l'invoque ne désigne rien.
    let mut place = [0_u8; 128];
    // `1Txxxxxx` avec `T` à zéro : la table DYNAMIQUE.
    assert_eq!(
        read_response_section(&reponse(&[0b1000_0001]), &mut place)
            .expect_err("la table dynamique est vide")
            .reason(),
        Reason::BadIndex
    );
}

#[test]
fn un_champ_de_reponse_entierement_litteral_se_lit() {
    // Un nom qui n'est dans aucune table statique : il voyage en toutes lettres
    // (§4.5.6), et le lecteur doit savoir le prendre — sans quoi une réponse
    // portant un champ que nous ne connaissons pas casserait la lecture.
    let mut sortie = [0_u8; 256];
    let combien = write_section(
        StatusCode::OK,
        &[(b"x-annuaire-verdict", b"joignable")],
        &mut sortie,
    )
    .expect("elle s'écrit");

    let mut place = [0_u8; 512];
    let statut = read_response_section(sortie.get(..combien).expect("la borne"), &mut place)
        .expect("elle se relit");
    assert_eq!(statut, StatusCode::OK);
}

#[test]
fn chacun_des_quatre_pseudo_champs_peut_manquer_de_place() {
    // **LES QUATRE SONT OBLIGATOIRES** (§4.3.1), donc les quatre s'écrivent, donc
    // chacun peut buter sur la fin du tampon. Un `?` qu'on n'éprouverait pas
    // serait une branche que personne n'a lue.
    for taille in 2..12_usize {
        let mut sortie = std::vec![0_u8; taille];
        assert_eq!(
            write_request_section(
                b"GET",
                b"https",
                b"annuaire.example",
                b"/v1/defi",
                &[],
                &mut sortie
            )
            .expect_err("il n'y a pas la place")
            .reason(),
            Reason::BufferTooSmall,
            "{taille} octets"
        );
    }
}

#[test]
fn une_reponse_dont_le_prefixe_reclame_des_insertions_est_refusee() {
    // §4.5.1 : nous avons annoncé une table nulle. Une section qui dépendrait
    // d'insertions n'attendrait pas — elle attendrait pour toujours.
    let mut place = [0_u8; 64];
    assert_eq!(
        read_response_section(&[0x01, 0x00], &mut place)
            .expect_err("aucune insertion n'a eu lieu")
            .reason(),
        Reason::BadInsertCount
    );
}

#[test]
fn une_ligne_de_champ_tronquee_est_refusee() {
    // Un littéral qui annonce plus d'octets qu'il n'en reste : la section ne se
    // lit pas, et c'est une faute de DÉCOMPRESSION — celle qui condamne la
    // connexion, parce que sans table partagée les deux camps divergeraient.
    let mut place = [0_u8; 64];
    // `001NHxxx` avec une longueur de nom de 7, et rien derrière.
    assert!(read_response_section(&[0x00, 0x00, 0b0010_0111], &mut place).is_err());
}

#[test]
fn le_chemin_aussi_peut_manquer_de_place() {
    // Les trois premiers pseudo-champs tiennent, le quatrième non : c'est le
    // dernier `?` de la série, et il doit être éprouvé comme les autres.
    let mut sortie = [0_u8; 13];
    assert_eq!(
        write_request_section(
            b"GET",
            b"https",
            b"a",
            b"/un/chemin/qui/ne/tient/pas",
            &[],
            &mut sortie
        )
        .expect_err("il n'y a pas la place")
        .reason(),
        Reason::BufferTooSmall
    );
}

#[test]
fn un_index_statique_qui_ne_designe_rien_est_refuse() {
    // La table statique de §3.1 compte 99 entrées. Au-delà, l'index ne désigne
    // rien — et prétendre le contraire ferait lire un champ inventé.
    let mut place = [0_u8; 64];
    // `1Txxxxxx` avec `T` à un et l'index 63 : la continuation porte le reste.
    assert_eq!(
        read_response_section(&[0x00, 0x00, 0b1111_1111, 200, 0x01], &mut place)
            .expect_err("cet index ne désigne rien")
            .reason(),
        Reason::BadIndex
    );
}

#[test]
fn un_nom_statique_qui_ne_designe_rien_est_refuse() {
    // Même chose pour un littéral dont seul le NOM vient de la table.
    let mut place = [0_u8; 64];
    // `01NTxxxx` avec `T` à un, index 15 puis continuation, puis une valeur.
    assert_eq!(
        read_response_section(&[0x00, 0x00, 0b0101_1111, 200, 0x01, 0x00], &mut place)
            .expect_err("ce nom ne désigne rien")
            .reason(),
        Reason::BadIndex
    );
}

#[test]
fn un_champ_ordinaire_peut_aussi_manquer_de_place() {
    // Les quatre pseudo-champs tiennent, le champ ordinaire non. **C'est le `?`
    // de la boucle**, et il se distingue des quatre précédents : celui-là est
    // atteint autant de fois qu'il y a de champs.
    for taille in 14..40_usize {
        let mut sortie = std::vec![0_u8; taille];
        let issue = write_request_section(
            b"GET",
            b"https",
            b"a",
            b"/",
            &[(b"x-un-nom-assez-long-pour-ne-pas-tenir", b"et-sa-valeur")],
            &mut sortie,
        );
        if let Err(faute) = issue {
            assert_eq!(faute.reason(), Reason::BufferTooSmall, "{taille} octets");
        }
    }
    // Et avec la place, elle passe.
    let mut sortie = [0_u8; 128];
    assert!(
        write_request_section(
            b"GET",
            b"https",
            b"a",
            b"/",
            &[(b"x-un-nom-assez-long-pour-ne-pas-tenir", b"et-sa-valeur")],
            &mut sortie,
        )
        .is_ok()
    );
}
