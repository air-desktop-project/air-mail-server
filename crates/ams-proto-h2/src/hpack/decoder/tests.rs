// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un bloc d'en-têtes a le droit d'être.

use super::{Decoder, Sensitivity};
use crate::error::Cause;

/// Un champ décodé, recopié : le décodeur prête son tampon, et l'épreuve le
/// réemploie au tour suivant.
type Recopie = (std::vec::Vec<u8>, std::vec::Vec<u8>, Sensitivity);

/// Décode un bloc entier, et rend les paires.
fn lire(decodeur: &mut Decoder, bloc: &[u8]) -> Result<std::vec::Vec<Recopie>, crate::Error> {
    decodeur.begin_block();
    let mut reste = bloc;
    let mut champs = std::vec::Vec::new();
    let mut place = [0_u8; 8192];
    while let Some((champ, lus)) = decodeur.next(reste, &mut place)? {
        champs.push((champ.name.to_vec(), champ.value.to_vec(), champ.sensitivity));
        assert!(lus > 0, "le décodeur n'avance pas");
        reste = reste.get(lus..).unwrap_or_default();
    }
    Ok(champs)
}

/// Les exemples de l'annexe C.2 de RFC 7541.
#[test]
fn les_exemples_de_la_rfc_se_decodent() {
    // C.2.1 : littéral avec indexation, nom en clair.
    let mut decodeur = Decoder::new();
    let champs = lire(
        &mut decodeur,
        &[
            0x40, 0x0a, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x0d, b'c',
            b'u', b's', b't', b'o', b'm', b'-', b'h', b'e', b'a', b'd', b'e', b'r',
        ],
    )
    .expect("lisible");
    assert_eq!(champs.len(), 1);
    assert_eq!(champs[0].0, b"custom-key");
    assert_eq!(champs[0].1, b"custom-header");
    assert_eq!(decodeur.table().len(), 1, "il est entré en table");
    assert_eq!(decodeur.table().size(), 55);

    // C.2.2 : littéral SANS indexation, nom indexé (`:path`).
    let mut decodeur = Decoder::new();
    let champs = lire(
        &mut decodeur,
        &[
            0x04, 0x0c, b'/', b's', b'a', b'm', b'p', b'l', b'e', b'/', b'p', b'a', b't', b'h',
        ],
    )
    .expect("lisible");
    assert_eq!(champs[0].0, b":path");
    assert_eq!(champs[0].1, b"/sample/path");
    assert!(decodeur.table().is_empty(), "il n'est pas entré en table");

    // C.2.3 : littéral JAMAIS indexé.
    let mut decodeur = Decoder::new();
    let champs = lire(
        &mut decodeur,
        &[
            0x10, 0x08, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', 0x06, b's', b'e', b'c',
            b'r', b'e', b't',
        ],
    )
    .expect("lisible");
    assert_eq!(champs[0].0, b"password");
    assert_eq!(champs[0].1, b"secret");
    assert_eq!(champs[0].2, Sensitivity::NeverIndexed);
    assert!(decodeur.table().is_empty());

    // C.2.4 : champ indexé, nom ET valeur d'un coup — `:method: GET`.
    let mut decodeur = Decoder::new();
    let champs = lire(&mut decodeur, &[0x82]).expect("lisible");
    assert_eq!(champs[0].0, b":method");
    assert_eq!(champs[0].1, b"GET");
}

/// **LA TABLE SURVIT D'UN BLOC À L'AUTRE**, et c'est tout l'intérêt de HPACK :
/// la seconde requête coûte quelques octets.
#[test]
fn la_table_survit_d_un_bloc_a_l_autre() {
    // Les trois requêtes de l'annexe C.3, sans compression Huffman.
    let mut decodeur = Decoder::new();
    let premier = lire(
        &mut decodeur,
        &[
            0x82, 0x86, 0x84, 0x41, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b'c', b'o', b'm',
        ],
    )
    .expect("lisible");
    assert_eq!(premier.len(), 4);
    assert_eq!(premier[0].0, b":method");
    assert_eq!(premier[0].1, b"GET");
    assert_eq!(premier[1].0, b":scheme");
    assert_eq!(premier[1].1, b"http");
    assert_eq!(premier[2].0, b":path");
    assert_eq!(premier[2].1, b"/");
    assert_eq!(premier[3].0, b":authority");
    assert_eq!(premier[3].1, b"www.example.com");
    assert_eq!(decodeur.table().len(), 1);

    // La deuxième reprend l'autorité par l'index soixante-deux.
    let second = lire(
        &mut decodeur,
        &[
            0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, b'n', b'o', b'-', b'c', b'a', b'c', b'h', b'e',
        ],
    )
    .expect("lisible");
    assert_eq!(second.len(), 5);
    assert_eq!(second[3].0, b":authority");
    assert_eq!(second[3].1, b"www.example.com");
    assert_eq!(second[4].0, b"cache-control");
    assert_eq!(second[4].1, b"no-cache");
    assert_eq!(decodeur.table().len(), 2);
}

/// **L'INDEX ZÉRO NE DÉSIGNE RIEN** (§6.1), et un index qui dépasse non plus.
#[test]
fn un_index_qui_ne_designe_rien_se_refuse() {
    let mut decodeur = Decoder::new();
    let mut place = [0_u8; 64];
    for bloc in [
        // §6.1 avec l'index zéro.
        &[0x80_u8][..],
        // Un index au-delà de la statique, table dynamique vide.
        &[0xbe],
        &[0xff, 0x00],
    ] {
        decodeur.begin_block();
        let issue = decodeur.next(bloc, &mut place).expect_err("refusé");
        assert_eq!(issue.cause(), Cause::BadIndex, "{bloc:?}");
        assert!(issue.is_fatal(), "l'état HPACK est partagé");
    }
}

/// **« JAMAIS INDEXÉ » N'EST PAS « SANS INDEXATION »**, et l'ordre de
/// reconnaissance est ce qui les sépare : les deux partagent leurs trois
/// premiers bits.
#[test]
fn jamais_indexe_se_distingue_de_sans_indexation() {
    let mut decodeur = Decoder::new();
    // `0000xxxx` : ordinaire.
    let sans = lire(&mut decodeur, &[0x00, 0x01, b'a', 0x01, b'b']).expect("lisible");
    assert_eq!(sans[0].2, Sensitivity::Ordinary);

    // `0001xxxx` : jamais indexé.
    let jamais = lire(&mut decodeur, &[0x10, 0x01, b'a', 0x01, b'b']).expect("lisible");
    assert_eq!(jamais[0].2, Sensitivity::NeverIndexed);

    // Ni l'un ni l'autre n'entre en table.
    assert!(decodeur.table().is_empty());
}

/// **UNE MISE À JOUR DE TAILLE VIENT AU DÉBUT D'UN BLOC** (§4.2). La tolérer
/// ailleurs laisserait un encodeur changer la taille au milieu, et un décodeur
/// qui l'appliquerait plus tard verrait une autre table.
#[test]
fn une_mise_a_jour_de_taille_vient_au_debut() {
    let mut decodeur = Decoder::new();
    // `001xxxxx` : taille zéro, puis un champ indexé.
    let champs = lire(&mut decodeur, &[0x20, 0x82]).expect("lisible");
    assert_eq!(champs.len(), 1);
    assert_eq!(champs[0].0, b":method");
    assert_eq!(decodeur.table().max_size(), 0);

    // La même, mais APRÈS un champ : c'est une faute.
    let mut decodeur = Decoder::new();
    let mut place = [0_u8; 64];
    decodeur.begin_block();
    let (_, lus) = decodeur
        .next(&[0x82, 0x20], &mut place)
        .expect("le champ passe")
        .expect("un champ");
    let issue = decodeur
        .next([0x82_u8, 0x20].get(lus..).unwrap_or_default(), &mut place)
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::TableUpdateTooLate);

    // Et un nouveau bloc rouvre la fenêtre.
    decodeur.begin_block();
    assert!(decodeur.next(&[0x20], &mut place).is_ok());
}

/// **LA BORNE DE TAILLE EST CELLE QU'ON A ANNONCÉE** : une mise à jour au-delà
/// est une faute, pas une demande.
#[test]
fn une_mise_a_jour_demesuree_se_refuse() {
    let mut decodeur = Decoder::new();
    let mut place = [0_u8; 64];
    decodeur.begin_block();
    // `0x3f 0xe1 0x1f` : 31 + 0x61 + (0x1f << 7) = 4097.
    let issue = decodeur
        .next(&[0x3f, 0xe2, 0x1f], &mut place)
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::TableSizeTooLarge);
}

/// **CHAQUE LECTURE QUI PEUT ÉCHOUER LE DIT**, et la faute remonte telle
/// quelle : l'appelant ferme la connexion sur le code, et le journal garde la
/// cause.
#[test]
fn chaque_lecture_qui_echoue_remonte() {
    let mut place = [0_u8; 512];
    for (bloc, cause) in [
        // Une mise à jour dont l'entier ne se termine pas.
        (
            &[0x3f_u8, 0xff, 0xff, 0xff, 0xff, 0xff][..],
            Cause::BadInteger,
        ),
        // Une mise à jour SUIVIE d'un index qui ne désigne rien.
        (&[0x20, 0x80], Cause::BadIndex),
        // Un champ indexé dont l'entier ne se termine pas.
        (&[0xff, 0xff], Cause::BadInteger),
        // Un littéral dont l'entier d'INDEX ne se termine pas : `0x7f` remplit
        // le préfixe de six bits, et la continuation reste ouverte.
        (&[0x7f, 0xff], Cause::BadInteger),
        // Le même, sur un préfixe de quatre bits.
        (&[0x0f, 0xff], Cause::BadInteger),
        // Un littéral dont la LONGUEUR de nom ne se termine pas.
        (&[0x4f, 0xff], Cause::BadInteger),
        // Un littéral dont le NOM en clair déborde.
        (&[0x40, 0x0a, b'a'], Cause::BadString),
        // Un littéral dont le nom vient d'un index qui ne désigne rien.
        (&[0x7f, 0x00, 0x01, b'x'], Cause::BadIndex),
        // Un littéral dont la VALEUR déborde.
        (&[0x40, 0x01, b'a', 0x0a, b'b'], Cause::BadString),
    ] {
        let mut decodeur = Decoder::new();
        decodeur.begin_block();
        let issue = decodeur.next(bloc, &mut place).expect_err("refusé");
        assert_eq!(issue.cause(), cause, "{bloc:?}");
        assert!(issue.is_fatal(), "{bloc:?} : l'état HPACK est partagé");
    }
}

/// Un bloc vide ne rend rien, et ce n'est pas une faute.
#[test]
fn un_bloc_vide_ne_rend_rien() {
    let mut decodeur = Decoder::new();
    assert_eq!(lire(&mut decodeur, b"").expect("lisible").len(), 0);
    // Une mise à jour seule non plus.
    assert_eq!(lire(&mut decodeur, &[0x20]).expect("lisible").len(), 0);
}

/// Un tampon de sortie trop court le dit, sur les deux chemins.
#[test]
fn un_tampon_trop_court_le_dit() {
    let mut decodeur = Decoder::new();
    // Un champ indexé : `:authority` fait dix octets, et sa valeur est vide.
    for taille in 0..10_usize {
        let mut petit = std::vec![0_u8; taille];
        decodeur.begin_block();
        let issue = decodeur.next(&[0x81], &mut petit).expect_err("refusé");
        assert_eq!(issue.cause(), Cause::BufferTooSmall, "{taille}");
    }
    // Un littéral dont le NOM vient de la table : `:path` fait cinq octets, et
    // le tampon se coupe en deux.
    for taille in 0..10_usize {
        let mut petit = std::vec![0_u8; taille];
        decodeur.begin_block();
        let issue = decodeur
            .next(&[0x04, 0x01, b'/'], &mut petit)
            .expect_err("refusé");
        assert!(
            matches!(issue.cause(), Cause::BufferTooSmall),
            "{taille} : {issue:?}"
        );
    }
}

/// Ce que le décodeur rend se montre, sans montrer les valeurs de la table.
#[test]
fn ce_que_le_decodeur_rend_se_montre() {
    let decodeur = Decoder::default();
    let texte = std::format!("{decodeur:?}");
    assert!(texte.contains("Decoder"), "{texte}");
    assert!(std::format!("{:?}", Sensitivity::NeverIndexed).contains("NeverIndexed"));
}
