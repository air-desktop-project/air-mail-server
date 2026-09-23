// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le magasin d'appareils garantit, et ce qu'il refuse.
//!
//! # CE QUI N'EST PAS ÉPROUVÉ ICI, ET POURQUOI
//!
//! La veille du disque, le verrou entre programmes, l'ordre « on écrit d'abord,
//! on publie ensuite » : ils vivent dans [`crate::magasin`] et sont éprouvés par
//! les essais du magasin de comptes. Les rejouer ici éprouverait le même code
//! deux fois et laisserait croire, le jour où l'un des deux serait retiré, qu'il
//! reste couvert.
//!
//! Ce fichier n'éprouve donc que ce qui est **propre aux appareils** : la
//! recherche par compte, et le fait que les invariantes du décodeur remontent
//! bien jusqu'à l'écrivain.

use std::path::PathBuf;

use ams_auth::Cle;
use ams_config::Device;

use super::{Appareils, Faute};

/// L'appareil de ce compte qui porte cet identifiant.
///
/// **LE COMPTE ENTRE DANS LA RECHERCHE**, et ce n'est pas décoratif : c'est
/// exactement la question que pose la révocation, et l'omettre laisserait un
/// compte retirer l'appareil d'un autre en devinant un identifiant.
fn trouver(magasin: &Appareils, login: &str, id: &str) -> Option<Device> {
    magasin
        .du_compte(login)
        .into_iter()
        .find(|appareil| appareil.id == id)
}

/// Un répertoire d'essai, effacé quand il tombe.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Ouvre un répertoire d'essai à soi.
fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(std::format!(
        "ams-appareils-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Une clef publique P-256 valide, figée en octets — le point `7 · G`.
///
/// **PAS D'ALÉA DANS UN ESSAI**, et pas de dépendance de signature dans une
/// caisse qui ne fait que ranger.
const CLE_VALIDE: [u8; 65] = [
    0x04, 0x1e, 0x18, 0x53, 0x2f, 0xd4, 0x75, 0x4c, 0x02, 0xf3, 0x04, 0x1d, 0x9c, 0x75, 0xce, 0xb3,
    0x3b, 0x83, 0xff, 0xd8, 0x1a, 0xc7, 0xce, 0x4f, 0xe8, 0x82, 0xcc, 0xb1, 0xc9, 0x8b, 0xc5, 0x89,
    0x6e, 0xa4, 0x6c, 0x31, 0x1c, 0x4e, 0x2f, 0xf4, 0x0d, 0xd9, 0x6a, 0x36, 0x53, 0xe6, 0xe4, 0x54,
    0x45, 0xd3, 0x2d, 0xfe, 0x48, 0x6e, 0xce, 0xd7, 0x5c, 0x7a, 0x90, 0xc6, 0xa1, 0x88, 0x81, 0xc0,
    0xa3,
];

/// Un appareil d'essai.
fn appareil(login: &str, id: &str) -> Device {
    Device {
        login: String::from(login),
        id: String::from(id),
        name: std::format!("appareil {id}"),
        public_key: Cle::lire(&CLE_VALIDE).expect("une clef d'épreuve valide"),
        enrolled: 1_790_000_000,
        last_seen: 0,
    }
}

/// Un magasin ouvert sur un fichier neuf.
fn magasin(atelier: &Atelier, appareils: Vec<Device>) -> Appareils {
    Appareils::new(atelier.0.join("appareils.bin"), appareils)
}

/// **UN ENRÔLEMENT SE VOIT ET SE POSE.**
#[tokio::test(flavor = "multi_thread")]
async fn un_enrolement_se_voit_et_se_pose() {
    let atelier = atelier("pose");
    let magasin = magasin(&atelier, std::vec![appareil("marc", "a1")]);
    assert_eq!(magasin.vue().len(), 1);

    magasin
        .modifier(|appareils| {
            appareils.push(appareil("marc", "b2"));
            Ok(())
        })
        .expect("modifiable");

    assert_eq!(magasin.vue().len(), 2, "la vue suivante le voit");

    // Et le disque aussi : c'est lui qui fait foi au prochain démarrage.
    let octets = std::fs::read(atelier.0.join("appareils.bin")).expect("posé");
    assert_eq!(
        ams_config::decode_devices(&octets)
            .expect("relisible")
            .len(),
        2
    );
}

/// **UN COMPTE NE VOIT QUE SES APPAREILS.**
///
/// C'est la seule chose qui empêche une liste d'appareils de devenir l'annuaire
/// des appareils de tout le monde.
#[tokio::test(flavor = "multi_thread")]
async fn un_compte_ne_voit_que_ses_appareils() {
    let atelier = atelier("cloison");
    let magasin = magasin(
        &atelier,
        std::vec![
            appareil("marc", "a1"),
            appareil("jeanne", "b2"),
            appareil("marc", "c3"),
        ],
    );

    let a_marc = magasin.du_compte("marc");
    assert_eq!(a_marc.len(), 2);
    assert!(a_marc.iter().all(|appareil| appareil.login == "marc"));
    // **L'ORDRE DU MAGASIN EST CONSERVÉ** : c'est ce qui rend une liste stable
    // d'un appel à l'autre, et donc affichable sans sauter.
    assert_eq!(a_marc[0].id, "a1");
    assert_eq!(a_marc[1].id, "c3");

    assert_eq!(magasin.du_compte("jeanne").len(), 1);
}

/// **UN COMPTE SANS APPAREIL REND UNE LISTE VIDE, ET NON UNE ERREUR.**
///
/// C'est l'état de tout compte avant son premier enrôlement. Le confondre avec
/// « ce compte n'existe pas » ferait répondre 404 à qui vient précisément
/// enrôler.
#[tokio::test(flavor = "multi_thread")]
async fn un_compte_sans_appareil_rend_une_liste_vide() {
    let atelier = atelier("vide");
    let magasin = magasin(&atelier, std::vec![appareil("marc", "a1")]);
    assert!(magasin.du_compte("jeanne").is_empty());
    assert!(magasin.du_compte("").is_empty());
}

/// **ON NE TROUVE L'APPAREIL D'UN AUTRE, MÊME EN CONNAISSANT SON IDENTIFIANT.**
///
/// Un identifiant est unique dans tout le magasin ; le chercher seul suffirait à
/// le trouver. Exiger le compte est ce qui empêche un compte de révoquer
/// l'appareil d'un autre en devinant.
#[tokio::test(flavor = "multi_thread")]
async fn l_appareil_d_un_autre_reste_introuvable() {
    let atelier = atelier("trouver");
    let magasin = magasin(
        &atelier,
        std::vec![appareil("marc", "a1"), appareil("jeanne", "b2")],
    );

    assert_eq!(
        trouver(&magasin, "marc", "a1").expect("le sien").id,
        "a1",
        "le sien se trouve"
    );
    assert!(
        trouver(&magasin, "marc", "b2").is_none(),
        "celui de jeanne ne se trouve pas sous le compte de marc"
    );
    assert!(trouver(&magasin, "marc", "inconnu").is_none());
    assert!(trouver(&magasin, "inconnu", "a1").is_none());
}

/// **UN IDENTIFIANT EN DOUBLE EST REFUSÉ PAR L'ÉCRITURE**, et non découvert au
/// prochain démarrage.
///
/// C'est tout l'intérêt de réencoder puis relire avant de poser : la règle vit
/// dans le décodeur, et l'écrivain n'a pas à la redire.
#[tokio::test(flavor = "multi_thread")]
async fn un_identifiant_en_double_est_refuse_a_l_ecriture() {
    let atelier = atelier("double");
    let magasin = magasin(&atelier, std::vec![appareil("marc", "a1")]);

    let issue = magasin.modifier(|appareils| {
        appareils.push(appareil("jeanne", "a1"));
        Ok(())
    });
    assert!(
        matches!(issue, Err(Faute::Refuse(_))),
        "attendu un refus du décodeur, obtenu {issue:?}"
    );

    // ET LA VUE N'A PAS BOUGÉ : une modification refusée ne laisse rien
    // derrière elle.
    assert_eq!(magasin.vue().len(), 1);
    assert!(trouver(&magasin, "jeanne", "a1").is_none());
}

/// **UN APPAREIL QUI N'EXISTE PAS SE DIT AVEC SON NOM.**
///
/// « Introuvable » tout court, dans un serveur qui tient deux magasins, oblige
/// l'exploitant à deviner lequel.
#[tokio::test(flavor = "multi_thread")]
async fn un_appareil_absent_se_nomme() {
    let atelier = atelier("absent");
    let magasin = magasin(&atelier, std::vec![appareil("marc", "a1")]);

    let issue = magasin.modifier(|appareils| {
        let place = appareils
            .iter()
            .position(|connu| connu.id == "jamais-vu")
            .ok_or(super::INTROUVABLE)?;
        appareils.remove(place);
        Ok(())
    });
    let Err(faute) = issue else {
        panic!("un appareil absent ne devait pas se retirer");
    };
    assert_eq!(faute.to_string(), "cet appareil n'existe pas");
}

/// **UNE RÉVOCATION RETIRE CELUI-LÀ, ET LUI SEUL.**
#[tokio::test(flavor = "multi_thread")]
async fn une_revocation_ne_retire_que_le_sien() {
    let atelier = atelier("revoque");
    let magasin = magasin(
        &atelier,
        std::vec![
            appareil("marc", "a1"),
            appareil("marc", "b2"),
            appareil("jeanne", "c3"),
        ],
    );

    magasin
        .modifier(|appareils| {
            let place = appareils
                .iter()
                .position(|connu| connu.login == "marc" && connu.id == "a1")
                .ok_or(super::INTROUVABLE)?;
            appareils.remove(place);
            Ok(())
        })
        .expect("révocable");

    assert!(trouver(&magasin, "marc", "a1").is_none());
    assert!(trouver(&magasin, "marc", "b2").is_some());
    assert!(trouver(&magasin, "jeanne", "c3").is_some());
}

/// **LA CLEF TRAVERSE LE DISQUE SANS CHANGER.**
///
/// Sans cela, une clef enrôlée un jour cesserait de vérifier ses propres
/// signatures après un redémarrage, et l'on chercherait le défaut dans la
/// cryptographie.
#[tokio::test(flavor = "multi_thread")]
async fn la_clef_traverse_le_disque_sans_changer() {
    let atelier = atelier("clef");
    let magasin = magasin(&atelier, std::vec![]);

    magasin
        .modifier(|appareils| {
            appareils.push(appareil("marc", "a1"));
            Ok(())
        })
        .expect("modifiable");

    // On rouvre sur le MÊME fichier, comme le ferait un redémarrage.
    let chemin = atelier.0.join("appareils.bin");
    let relu =
        ams_config::decode_devices(&std::fs::read(&chemin).expect("lisible")).expect("relisible");
    let rouvert = Appareils::new(chemin, relu);

    assert_eq!(
        trouver(&rouvert, "marc", "a1")
            .expect("toujours là")
            .public_key
            .octets(),
        CLE_VALIDE
    );
}

/// **UN MAGASIN QUI N'EXISTE PAS ENCORE SE CRÉE À LA PREMIÈRE ÉCRITURE.**
///
/// C'est le cas du tout premier enrôlement sur un serveur neuf : exiger que le
/// fichier existe déjà obligerait l'installation à le fabriquer vide.
#[tokio::test(flavor = "multi_thread")]
async fn un_magasin_absent_se_cree_au_premier_enrolement() {
    let atelier = atelier("neuf");
    let chemin = atelier.0.join("appareils.bin");
    assert!(!chemin.exists());

    let magasin = Appareils::new(chemin.clone(), std::vec![]);
    magasin
        .modifier(|appareils| {
            appareils.push(appareil("marc", "a1"));
            Ok(())
        })
        .expect("modifiable");

    assert!(chemin.exists());
    assert_eq!(magasin.du_compte("marc").len(), 1);
}
