// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Où un `COPY` dépose réellement, et où un `MOVE` laisse le message.
//!
//! # POURQUOI CES ESSAIS EXISTENT
//!
//! `copy_to` et `undo_copies` comparaient le nom de la destination à la
//! constante `INBOX`, puis écrivaient dans la boîte OUVERTE. C'était juste tant
//! qu'`INBOX` était la seule boîte ; les dossiers sont arrivés, et cette
//! prémisse est devenue fausse sans que rien ne le dise. Aucun essai ne
//! regardait OÙ le message atterrit — la session, elle, ne peut pas le savoir :
//! elle ne voit qu'un `Option<u32>`.
//!
//! **On vérifie donc le disque, et pas la réponse.** Le défaut rendait un UID,
//! et ce n'était pas celui d'un message arrivé à destination.

use super::{BoitesImap, INBOX};
use ams_auth::Account;
use ams_proto_imap::Flags;
use ams_session::imap::{Creation, Deposit as _, Mailbox as _, Mailboxes as _};
use ams_store::Maildir;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const HOTE: &[u8] = b"mail.example.com";
const COMPTE: &[u8] = b"marie";

/// Un répertoire qui s'efface quand l'essai finit.
struct Ephemere(PathBuf);

impl Ephemere {
    fn nouveau(quoi: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |depuis| depuis.as_nanos());
        let chemin = std::env::temp_dir().join(std::format!(
            "ams-imap-{quoi}-{unique}-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&chemin).expect("créable");
        Self(chemin)
    }
}

impl Drop for Ephemere {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Le compte `marie`, sa boîte d'arrivée, et le service IMAP qui les sert.
fn service(racine: &Path) -> BoitesImap {
    let boite = Maildir::open(racine.join("marie"), HOTE, ams_store::fresh_uid_validity())
        .expect("ouvrable");
    let mut carte = BTreeMap::new();
    carte.insert(String::from("marie"), Arc::new(boite));
    let comptes = Arc::new(crate::comptes::Comptes::new(
        racine.join("comptes.bin"),
        std::vec![Account {
            login: String::from("marie"),
            hash: String::new(),
            addresses: std::vec![String::from("marie@example.com")],
        }],
    ));
    let boites = Arc::new(crate::delivery::Boites::new(
        carte,
        racine.to_path_buf(),
        HOTE.to_vec(),
        comptes,
    ));
    BoitesImap::new(boites, HOTE)
}

/// Dépose un message dans la boîte nommée, et rend son UID.
fn deposer(service: &BoitesImap, boite: &[u8], corps: &[u8]) -> u32 {
    let mut depot = service.append(COMPTE, boite).expect("boîte ouvrable");
    assert!(depot.write(corps), "le dépôt accepte les octets");
    depot.commit(Flags::NONE, None).expect("dépôt validé")
}

/// Combien de messages la boîte nommée porte, LU SUR LE DISQUE.
///
/// On ne demande pas au serveur : c'est lui qu'on juge.
fn combien(racine: &Path, boite: Option<&str>) -> usize {
    let repertoire = match boite {
        Some(nom) => racine.join("marie").join(std::format!(".{nom}")),
        None => racine.join("marie"),
    };
    ["new", "cur"]
        .iter()
        .filter_map(|sous| std::fs::read_dir(repertoire.join(sous)).ok())
        .map(|entrees| entrees.flatten().count())
        .sum()
}

/// Une copie vers un DOSSIER y arrive, et ne touche pas la source.
#[test]
fn une_copie_vers_un_dossier_y_arrive() {
    let atelier = Ephemere::nouveau("copie-dossier");
    let service = service(&atelier.0);
    deposer(&service, INBOX, b"From: a@b.test\r\n\r\nun\r\n");
    assert_eq!(service.create(COMPTE, b"Archives"), Creation::Faite);

    let mut ouverte = service.open(COMPTE, INBOX).expect("INBOX ouvrable");
    assert_eq!(ouverte.exists(), 1);
    let uid = ouverte.copy_to(1, b"Archives").expect("copie faite");

    assert!(uid > 0, "la copie porte un UID de la destination");
    assert_eq!(
        combien(&atelier.0, Some("Archives")),
        1,
        "le message est DANS le dossier nommé"
    );
    assert_eq!(
        combien(&atelier.0, None),
        1,
        "et la source n'a pas grossi — c'est là que le défaut le déposait"
    );
}

/// Une copie vers `INBOX` depuis un dossier arrive dans `INBOX`.
///
/// C'est le cas que l'ancienne garde LAISSAIT PASSER : le nom était bien
/// `INBOX`, donc la comparaison réussissait — et le dépôt se faisait quand même
/// dans la boîte ouverte, qui était le dossier.
#[test]
fn une_copie_vers_inbox_depuis_un_dossier_arrive_dans_inbox() {
    let atelier = Ephemere::nouveau("copie-inbox");
    let service = service(&atelier.0);
    assert_eq!(service.create(COMPTE, b"Brouillons"), Creation::Faite);
    deposer(&service, b"Brouillons", b"From: a@b.test\r\n\r\nun\r\n");

    let mut ouverte = service
        .open(COMPTE, b"Brouillons")
        .expect("dossier ouvrable");
    assert_eq!(ouverte.exists(), 1);
    ouverte.copy_to(1, INBOX).expect("copie faite");

    assert_eq!(
        combien(&atelier.0, None),
        1,
        "le message est arrivé dans INBOX"
    );
    assert_eq!(
        combien(&atelier.0, Some("Brouillons")),
        1,
        "et le dossier n'en porte toujours qu'un"
    );
}

/// Un `MOVE` vers un dossier ne perd pas le message.
///
/// C'est la conséquence qui coûtait cher : la copie manquait sa destination, le
/// retrait de la source réussissait, et le message n'était plus nulle part où le
/// client puisse le voir.
#[test]
fn un_deplacement_ne_perd_pas_le_message() {
    let atelier = Ephemere::nouveau("deplacement");
    let service = service(&atelier.0);
    assert_eq!(service.create(COMPTE, b"Rangees"), Creation::Faite);
    deposer(&service, b"Rangees", b"From: a@b.test\r\n\r\nun\r\n");

    let mut ouverte = service.open(COMPTE, b"Rangees").expect("dossier ouvrable");
    ouverte.copy_to(1, INBOX).expect("copie faite");
    assert!(ouverte.remove(1), "la source est retirée");

    assert_eq!(combien(&atelier.0, None), 1, "INBOX porte le message");
    assert_eq!(
        combien(&atelier.0, Some("Rangees")),
        0,
        "et le dossier ne le porte plus"
    );
}

/// Une destination qui n'existe pas ne copie rien, et n'écrit nulle part.
#[test]
fn une_destination_absente_ne_copie_rien() {
    let atelier = Ephemere::nouveau("absente");
    let service = service(&atelier.0);
    deposer(&service, INBOX, b"From: a@b.test\r\n\r\nun\r\n");

    let mut ouverte = service.open(COMPTE, INBOX).expect("INBOX ouvrable");
    assert!(
        ouverte.copy_to(1, b"JamaisCreee").is_none(),
        "un dossier qui n'existe pas n'est pas une destination"
    );
    assert_eq!(combien(&atelier.0, None), 1, "et rien n'a été déposé");
}

/// Un nom qui tenterait de sortir de la racine n'ouvre rien.
///
/// La session refuse déjà ce nom ; on le vérifie ICI parce que c'est ce code-ci
/// qui touche le système de fichiers.
#[test]
fn un_nom_qui_remonte_ne_copie_nulle_part() {
    let atelier = Ephemere::nouveau("evasion");
    let service = service(&atelier.0);
    deposer(&service, INBOX, b"From: a@b.test\r\n\r\nun\r\n");

    let mut ouverte = service.open(COMPTE, INBOX).expect("INBOX ouvrable");
    for nom in [
        b"../evade".as_slice(),
        b"..".as_slice(),
        b"/etc/passwd".as_slice(),
    ] {
        assert!(
            ouverte.copy_to(1, nom).is_none(),
            "`{}` ne devient pas un chemin",
            String::from_utf8_lossy(nom)
        );
    }
    assert_eq!(combien(&atelier.0, None), 1);
}

/// Défaire une copie la retire de la DESTINATION.
///
/// L'ancienne version défaisait dans la boîte ouverte quand le nom était
/// `INBOX`, et ne défaisait rien du tout pour tout autre nom.
#[test]
fn defaire_retire_de_la_destination() {
    let atelier = Ephemere::nouveau("defaire");
    let service = service(&atelier.0);
    deposer(&service, INBOX, b"From: a@b.test\r\n\r\nun\r\n");
    assert_eq!(service.create(COMPTE, b"Corbeille"), Creation::Faite);

    let mut ouverte = service.open(COMPTE, INBOX).expect("INBOX ouvrable");
    let uid = ouverte.copy_to(1, b"Corbeille").expect("copie faite");
    assert_eq!(combien(&atelier.0, Some("Corbeille")), 1);

    ouverte.undo_copies(b"Corbeille", uid, uid);
    assert_eq!(
        combien(&atelier.0, Some("Corbeille")),
        0,
        "la copie est retirée de la destination"
    );
    assert_eq!(combien(&atelier.0, None), 1, "et l'original est intact");
}
