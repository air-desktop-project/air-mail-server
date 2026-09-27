// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que les brouillons font du disque — lu sur le disque.

use super::{Brouillons, DUREE_S, Faute, PIECES_MAX, composer};
use std::path::PathBuf;

struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let chemin = std::env::temp_dir().join(format!(
        "ams-brouillons-{nom}-{unique}-{:?}",
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&chemin).expect("créable");
    Atelier(chemin)
}

fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

const CORPS: &[u8] = b"From: marie@example.com\r\nTo: paul@example.com\r\nSubject: s\r\n\
Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nbonjour\r\n";

/// Un brouillon neuf, et son identifiant.
fn neuf(brouillons: &Brouillons) -> String {
    brouillons
        .creer("marie", CORPS, maintenant(), [7; 16])
        .expect("créé")
        .0
}

/// Un décodeur base64 écrit à part : on juge le serveur, pas lui-même.
fn decoder(texte: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let chiffres: Vec<u32> = texte
        .iter()
        .filter_map(|c| ALPHABET.iter().position(|a| a == c))
        .filter_map(|rang| u32::try_from(rang).ok())
        .collect();
    let mut sortie = Vec::new();
    for groupe in chiffres.chunks(4) {
        // Quatre chiffres de six bits font vingt-quatre bits ; les manquants
        // comptent pour zéro, et ne rendent pas d'octet.
        let paquet = (0..4).fold(0_u32, |paquet, rang| {
            paquet
                .saturating_mul(64)
                .saturating_add(groupe.get(rang).copied().unwrap_or(0))
        });
        let octets = paquet.to_be_bytes();
        sortie.extend_from_slice(&octets[1..groupe.len()]);
    }
    sortie
}

#[test]
fn un_brouillon_se_cree_et_se_relit() {
    let atelier = atelier("creation");
    let brouillons = Brouillons::new(atelier.0.clone(), 1_000_000);
    let (id, expire) = brouillons
        .creer("marie", CORPS, maintenant(), [0xab; 16])
        .expect("créé");
    assert_eq!(id, "ab".repeat(16));
    assert!(expire > maintenant() && expire <= maintenant() + DUREE_S + 1);
    assert_eq!(
        brouillons
            .a_composer("marie", &id, maintenant())
            .map(|(corps, _)| corps),
        Ok(CORPS.to_vec())
    );
    assert_eq!(
        brouillons
            .etat("marie", &id, maintenant())
            .expect("vivant")
            .1,
        Vec::new()
    );
    // Le brouillon est à son compte, et à lui seul.
    assert_eq!(
        brouillons.etat("paul", &id, maintenant()).err(),
        Some(Faute::Introuvable)
    );
    for mauvais in ["", "abc", &"zz".repeat(16), "../marie"] {
        assert_eq!(
            brouillons.etat("marie", mauvais, maintenant()),
            Err(Faute::Introuvable),
            "{mauvais}"
        );
    }
    for compte in ["", ".cache", "a/b"] {
        assert_eq!(
            brouillons.creer(compte, CORPS, maintenant(), [1; 16]),
            Err(Faute::Refus)
        );
    }
    assert_eq!(brouillons.supprimer("marie", &id, maintenant()), Ok(()));
    assert_eq!(
        brouillons.supprimer("marie", &id, maintenant()),
        Err(Faute::Introuvable)
    );
}

/// **LES MORCEAUX ARRIVENT DANS LE DÉSORDRE, ET SE RASSEMBLENT AU DERNIER.**
#[test]
fn les_morceaux_se_rassemblent_au_dernier() {
    let atelier = atelier("morceaux");
    let brouillons = Brouillons::new(atelier.0.clone(), 1_000_000);
    let id = neuf(&brouillons);
    let piece = brouillons
        .declarer(
            "marie",
            &id,
            "facture.pdf",
            "application/pdf",
            10,
            maintenant(),
        )
        .expect("déclarée");
    assert_eq!((piece.numero, piece.recu.len()), (1, 0));
    let fichier = b"0123456789";

    let apres = brouillons
        .poser("marie", &id, 1, (5, 9, 10), &fichier[5..], maintenant())
        .expect("second morceau d'abord");
    assert_eq!(
        (apres.recu.clone(), apres.complete()),
        (vec![(5, 9)], false)
    );
    // Renvoyé à l'identique : il remplace le sien.
    brouillons
        .poser("marie", &id, 1, (5, 9, 10), &fichier[5..], maintenant())
        .expect("renvoyé");
    // Un morceau qui chevauche sans égaler : refusé.
    assert_eq!(
        brouillons.poser("marie", &id, 1, (3, 6, 10), b"3456", maintenant()),
        Err(Faute::Conflit)
    );
    // Une taille qui n'est pas celle de la pièce, des octets qui ne font pas
    // la portée : refusés.
    assert_eq!(
        brouillons.poser("marie", &id, 1, (0, 4, 11), b"01234", maintenant()),
        Err(Faute::Refus)
    );
    assert_eq!(
        brouillons.poser("marie", &id, 1, (0, 4, 10), b"0123", maintenant()),
        Err(Faute::Refus)
    );
    let entiere = brouillons
        .poser("marie", &id, 1, (0, 4, 10), &fichier[..5], maintenant())
        .expect("le dernier");
    assert!(entiere.complete());
    let (_, pieces) = brouillons
        .a_composer("marie", &id, maintenant())
        .expect("prêt");
    assert_eq!(std::fs::read(&pieces[0].1).expect("rassemblée"), fichier);
    // Les morceaux s'en sont allés.
    let restants = std::fs::read_dir(atelier.0.join("marie").join(&id))
        .expect("lisible")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("pj-1.0"))
        .count();
    assert_eq!(restants, 0);
    // Une pièce entière ne reçoit plus rien.
    assert_eq!(
        brouillons.poser("marie", &id, 1, (0, 4, 10), &fichier[..5], maintenant()),
        Err(Faute::Conflit)
    );
    assert_eq!(
        brouillons.poser("marie", &id, 9, (0, 4, 10), &fichier[..5], maintenant()),
        Err(Faute::Introuvable)
    );
}

/// **UNE PIÈCE INCOMPLÈTE N'EMPÊCHE PAS DE COMPOSER EN SILENCE : ELLE L'EMPÊCHE.**
#[test]
fn une_piece_incomplete_empeche_de_composer() {
    let atelier = atelier("incomplete");
    let brouillons = Brouillons::new(atelier.0.clone(), 1_000_000);
    let id = neuf(&brouillons);
    brouillons
        .declarer(
            "marie",
            &id,
            "a.bin",
            "application/octet-stream",
            4,
            maintenant(),
        )
        .expect("déclarée");
    assert_eq!(
        brouillons.a_composer("marie", &id, maintenant()).err(),
        Some(Faute::Conflit)
    );
    assert_eq!(brouillons.retirer("marie", &id, 1, maintenant()), Ok(()));
    assert_eq!(
        brouillons.retirer("marie", &id, 1, maintenant()),
        Err(Faute::Introuvable)
    );
    assert!(brouillons.a_composer("marie", &id, maintenant()).is_ok());
}

/// **LA TAILLE SE JUGE À LA DÉCLARATION**, et le nombre de pièces aussi.
#[test]
fn les_bornes_se_jugent_a_la_declaration() {
    let atelier = atelier("bornes");
    let brouillons = Brouillons::new(atelier.0.clone(), 10_000);
    let id = neuf(&brouillons);
    assert_eq!(
        brouillons.declarer("marie", &id, "gros", "application/pdf", 9_000, maintenant()),
        Err(Faute::TropGros),
        "9000 octets en base64 dépassent 10000"
    );
    let grand = Brouillons::new(atelier.0.clone(), u64::MAX);
    for _ in 0..PIECES_MAX {
        grand
            .declarer("marie", &id, "a", "text/plain", 1, maintenant())
            .expect("dans la borne");
    }
    assert_eq!(
        grand.declarer("marie", &id, "a", "text/plain", 1, maintenant()),
        Err(Faute::Conflit)
    );
}

/// **UN BROUILLON EXPIRÉ DISPARAÎT AU PREMIER REGARD**, et le balayage retire
/// les autres.
#[test]
fn un_brouillon_expire_disparait() {
    let atelier = atelier("expiration");
    let brouillons = Brouillons::new(atelier.0.clone(), 1_000_000);
    let id = neuf(&brouillons);
    let demain = maintenant() + DUREE_S + 10;
    assert_eq!(
        brouillons.etat("marie", &id, demain),
        Err(Faute::Introuvable)
    );
    assert!(
        !atelier.0.join("marie").join(&id).exists(),
        "retiré au regard"
    );

    let autre = neuf(&brouillons);
    std::fs::create_dir_all(atelier.0.join("marie").join("sans-corps")).expect("créé");
    brouillons.balayer_tout(demain);
    assert!(!atelier.0.join("marie").join(&autre).exists());
    assert!(!atelier.0.join("marie").join("sans-corps").exists());
    // Une racine absente se balaie sans tomber.
    Brouillons::new(atelier.0.join("absente"), 1).balayer_tout(demain);
}

/// **LE MESSAGE COMPOSÉ EST UN `multipart/mixed` CORRECT**, et chaque pièce s'y
/// relit à l'octet près — nom accentué compris, en RFC 2231.
#[test]
fn le_message_compose_se_relit() {
    let atelier = atelier("composition");
    let brouillons = Brouillons::new(atelier.0.clone(), 10_000_000);
    let id = neuf(&brouillons);
    let donnees: Vec<u8> = (0..5_000_u32).map(|i| (i % 251) as u8).collect();
    brouillons
        .declarer(
            "marie",
            &id,
            "reçu été.bin",
            "application/octet-stream",
            5_000,
            maintenant(),
        )
        .expect("déclarée");
    brouillons
        .poser("marie", &id, 1, (0, 4_999, 5_000), &donnees, maintenant())
        .expect("d'un coup");
    brouillons
        .declarer("marie", &id, "notes.txt", "text/plain", 3, maintenant())
        .expect("déclarée");
    brouillons
        .poser("marie", &id, 2, (0, 2, 3), b"abc", maintenant())
        .expect("posée");
    let (corps, pieces) = brouillons
        .a_composer("marie", &id, maintenant())
        .expect("prêt");
    let mut compose = Vec::new();
    assert!(composer(&corps, &pieces, "=_frontiere_=", &mut |morceau| {
        compose.extend_from_slice(morceau);
        true
    }));
    let texte = String::from_utf8_lossy(&compose).into_owned();
    assert!(texte.starts_with("From: marie@example.com\r\n"), "{texte}");
    assert!(
        texte.contains(
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"=_frontiere_=\""
        ),
        "{texte}"
    );
    assert_eq!(
        texte
            .matches("Content-Type: text/plain; charset=utf-8")
            .count(),
        1
    );
    assert!(texte.contains("Content-Transfer-Encoding: 8bit\r\n\r\nbonjour\r\n"));
    assert!(
        texte.contains("filename*=UTF-8''re%C3%A7u%20%C3%A9t%C3%A9.bin"),
        "{texte}"
    );
    assert!(texte.contains("Content-Disposition: attachment; filename=\"notes.txt\""));
    assert!(texte.ends_with("\r\n--=_frontiere_=--\r\n"));
    assert!(texte.lines().all(|ligne| ligne.len() <= 998));

    // Chaque pièce se relit à l'octet près.
    let parties: Vec<&str> = texte.split("--=_frontiere_=").collect();
    let base64_de = |partie: &str| {
        let (_, corps) = partie.split_once("\r\n\r\n").expect("en-tête");
        decoder(corps.as_bytes())
    };
    assert_eq!(base64_de(parties[2]), donnees);
    assert_eq!(base64_de(parties[3]), b"abc");
    // Les lignes font soixante-seize caractères, sauf la dernière.
    let (_, lignes) = parties[2].split_once("\r\n\r\n").expect("en-tête");
    let longueurs: Vec<usize> = lignes
        .split("\r\n")
        .filter(|l| !l.is_empty())
        .map(str::len)
        .collect();
    assert!(
        longueurs[..longueurs.len() - 1].iter().all(|l| *l == 76),
        "{longueurs:?}"
    );

    // Sans pièce, le corps tel quel ; une frontière présente dans le corps, ou
    // un écrivain qui refuse, et l'on s'arrête.
    let mut seul = Vec::new();
    assert!(composer(&corps, &[], "x", &mut |m| {
        seul.extend_from_slice(m);
        true
    }));
    assert_eq!(seul, corps);
    assert!(!composer(&corps, &pieces, "bonjour", &mut |_| true));
    assert!(!composer(&corps, &pieces, "=_f_=", &mut |_| false));
    assert!(!composer(b"pas un message", &pieces, "=_f_=", &mut |_| {
        true
    }));
}
