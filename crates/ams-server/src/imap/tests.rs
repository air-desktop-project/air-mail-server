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
use ams_proto_imap::{Flags, SpecialUse};
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
    BoitesImap::new(boites, HOTE, None)
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
    assert_eq!(
        service.create(COMPTE, b"Archives", SpecialUse::NONE),
        Creation::Faite
    );

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
    assert_eq!(
        service.create(COMPTE, b"Brouillons", SpecialUse::NONE),
        Creation::Faite
    );
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
    assert_eq!(
        service.create(COMPTE, b"Rangees", SpecialUse::NONE),
        Creation::Faite
    );
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
    assert_eq!(
        service.create(COMPTE, b"Corbeille", SpecialUse::NONE),
        Creation::Faite
    );

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

// ── LES ATTRIBUTS D'USAGE, SUR LE DISQUE (RFC 6154) ─────────────────────────

/// **UN USAGE SURVIT AU REDÉMARRAGE**, et c'est tout ce qui compte ici.
///
/// La session ne sait pas si le magasin retient : elle rend ce qu'on lui donne.
/// Ce que cet essai vérifie, c'est le fichier — un second service monté sur la
/// même racine doit lire ce que le premier a écrit.
#[test]
fn un_usage_designe_survit_au_redemarrage() {
    let atelier = Ephemere::nouveau("usage-survit");
    {
        let service = service(&atelier.0);
        assert_eq!(
            service.create(COMPTE, b"Brouillons", SpecialUse::DRAFTS),
            Creation::Faite
        );
    }
    // UN SECOND SERVICE, sur la même racine : c'est le redémarrage.
    let apres = service(&atelier.0);
    let mut place = [0_u8; 256];
    let mut vues: std::vec::Vec<(std::string::String, bool)> = std::vec::Vec::new();
    for rang in 0..8 {
        let Some(listing) = apres.name(COMPTE, rang, &mut place) else {
            break;
        };
        vues.push((
            std::string::String::from_utf8_lossy(listing.name).into_owned(),
            listing.special.contains(SpecialUse::DRAFTS),
        ));
    }
    assert!(
        vues.contains(&(std::string::String::from("Brouillons"), true)),
        "l'usage n'a pas survécu : {vues:?}"
    );
    assert!(
        vues.contains(&(std::string::String::from("INBOX"), false)),
        "et il ne déteint pas sur les voisines : {vues:?}"
    );
}

/// **UN USAGE NE VAUT QUE POUR UNE BOÎTE, ET RIEN N'EST CRÉÉ EN CHEMIN** (§3).
///
/// Le refus doit tomber AVANT le répertoire : créer d'abord et refuser ensuite
/// laisserait une boîte que le client n'a pas demandée, et qu'il ne saurait pas
/// devoir effacer.
#[test]
fn un_usage_deja_pris_ne_cree_rien() {
    let atelier = Ephemere::nouveau("usage-pris");
    let service = service(&atelier.0);
    assert_eq!(
        service.create(COMPTE, b"Brouillons", SpecialUse::DRAFTS),
        Creation::Faite
    );
    assert_eq!(
        service.create(COMPTE, b"Autre", SpecialUse::DRAFTS),
        Creation::UsageDejaPris
    );
    assert!(
        !atelier.0.join("marie").join(".Autre").exists(),
        "un répertoire est né d'une création refusée"
    );
    // Le même nom SANS l'usage passe : c'est ce que `[USEATTR]` promet.
    assert_eq!(
        service.create(COMPTE, b"Autre", SpecialUse::NONE),
        Creation::Faite
    );
}

/// **CE QU'ON NE COMPREND PAS DANS LE FICHIER EST SAUTÉ, PAS DEVINÉ.**
///
/// Ce fichier vit dans la racine du compte, où un administrateur peut l'ouvrir.
/// Une ligne sans tabulation, un usage qu'on ne sert pas, un nom qui remonte :
/// on passe. Et un usage réclamé deux fois va à la PREMIÈRE ligne — arbitraire,
/// mais déterministe : deux serveurs sur le même magasin doivent lire pareil.
#[test]
fn un_fichier_d_usages_abime_ne_fait_pas_deviner() {
    let atelier = Ephemere::nouveau("usage-abime");
    let service = service(&atelier.0);
    assert_eq!(
        service.create(COMPTE, b"Bonne", SpecialUse::NONE),
        Creation::Faite
    );
    assert_eq!(
        service.create(COMPTE, b"Seconde", SpecialUse::NONE),
        Creation::Faite
    );
    std::fs::write(
        atelier.0.join("marie").join("ams-usages"),
        // Une ligne sans tabulation, un attribut virtuel, un nom qui remonte,
        // puis deux prétendants au même usage.
        "pas de tabulation ici\n\\All\tTout\n\\Sent\t../evade\n\\Drafts\tBonne\n\\Drafts\tSeconde\n",
    )
    .expect("écriture");

    let mut place = [0_u8; 256];
    let mut porteuses = std::vec::Vec::new();
    for rang in 0..16 {
        let Some(listing) = service.name(COMPTE, rang, &mut place) else {
            break;
        };
        if listing.special.any() {
            porteuses.push(std::string::String::from_utf8_lossy(listing.name).into_owned());
        }
    }
    assert_eq!(
        porteuses,
        std::vec![std::string::String::from("Bonne")],
        "seule la première ligne bien formée et non conflictuelle doit valoir"
    );
}

/// **RENOMMER `INBOX` NE FAIT RESSERVIR AUCUN UID** — ni dans la boîte qui
/// reçoit le courrier, ni dans `INBOX` qui reste.
///
/// §6.3.6 de RFC 9051 : renommer `INBOX` déplace son courrier dans une boîte
/// neuve et la laisse, vide. Les messages gardent leurs UID ; c'est licite,
/// puisque la boîte neuve a son propre `UIDVALIDITY`. Ce qui ne le serait pas :
/// qu'un message déposé ensuite dans l'une ou l'autre reprenne un UID déjà
/// servi SOUS LE MÊME `UIDVALIDITY`.
#[test]
fn renommer_inbox_ne_fait_resservir_aucun_uid() {
    let racine = Ephemere::nouveau("renommer-inbox");
    let service = service(&racine.0);
    let deplaces: Vec<u32> = (0..3)
        .map(|rang| {
            deposer(
                &service,
                INBOX,
                std::format!("Subject: {rang}\r\n\r\nx\r\n").as_bytes(),
            )
        })
        .collect();
    let plus_grand = *deplaces.iter().max().expect("trois");
    let validite_inbox = service.open(COMPTE, INBOX).expect("INBOX").uid_validity();

    assert_eq!(
        service.rename(COMPTE, INBOX, b"Ancien"),
        ams_session::imap::Renaming::Faite
    );
    assert_eq!(combien(&racine.0, None), 0, "INBOX est vidée");
    assert_eq!(
        combien(&racine.0, Some("Ancien")),
        3,
        "le courrier est parti"
    );

    // La boîte neuve : un autre `UIDVALIDITY`, et un dépôt au-delà des UID reçus.
    let ancien = service.open(COMPTE, b"Ancien").expect("Ancien");
    assert_ne!(ancien.uid_validity(), validite_inbox);
    let dans_ancien = deposer(&service, b"Ancien", b"Subject: neuf\r\n\r\nx\r\n");
    assert!(
        dans_ancien > plus_grand,
        "un UID déjà porté dans la boîte neuve est resservi : {dans_ancien} ≤ {plus_grand}"
    );

    // INBOX : même `UIDVALIDITY`, et ses UID ne redescendent pas.
    let dans_inbox = deposer(&service, INBOX, b"Subject: arrive\r\n\r\nx\r\n");
    assert!(
        dans_inbox > plus_grand,
        "INBOX resservirait un UID sous le même UIDVALIDITY : {dans_inbox} ≤ {plus_grand}"
    );
    assert_eq!(
        service.open(COMPTE, INBOX).expect("INBOX").uid_validity(),
        validite_inbox
    );
}

/// **UNE SESSION VOIT CE QU'UNE AUTRE A FAIT** — un message lu, un message
/// retiré — et le rend un à un, pour que la session l'annonce.
///
/// Jusqu'en 0.2.19, le rafraîchissement n'ajoutait que les nouveaux, et se
/// taisait dès qu'un message manquait au milieu : un Thunderbird ouvert ne
/// voyait ni l'un ni l'autre avant de resélectionner la boîte.
#[test]
fn une_session_voit_ce_qu_une_autre_a_fait() {
    let racine = Ephemere::nouveau("autre-session");
    let service = service(&racine.0);
    let uids: Vec<u32> = (0..3)
        .map(|rang| {
            deposer(
                &service,
                INBOX,
                std::format!("Subject: {rang}\r\n\r\nx\r\n").as_bytes(),
            )
        })
        .collect();
    let mut ici = service.open(COMPTE, INBOX).expect("ouvrable");
    assert_eq!(ici.exists(), 3);
    // Rien n'a bougé : rien à dire.
    ici.refresh();
    assert_eq!(ici.vanished(), None);
    assert_eq!(ici.flags_changed(), None);

    // **UNE AUTRE SESSION** lit le premier et retire le troisième. Le système de
    // fichiers date ses répertoires à la milliseconde près au mieux : on laisse
    // passer de quoi que l'empreinte change.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let mut ailleurs = service.open(COMPTE, INBOX).expect("ouvrable");
    assert!(
        ailleurs
            .store_flags(1, ams_proto_imap::StoreMode::Add, Flags::SEEN)
            .is_some()
    );
    assert!(ailleurs.remove(3));

    // Le regard suivant le voit, SANS RENUMÉROTER tant que rien n'est annoncé.
    assert_eq!(ici.refresh(), 3, "rien ne renumérote avant l'annonce");
    assert_eq!(ici.vanished(), Some(3), "le troisième a disparu");
    assert_eq!(ici.vanished(), None);
    assert_eq!(ici.exists(), 2);
    assert_eq!(ici.flags_changed(), Some(1), "le premier a été lu ailleurs");
    assert!(ici.info(1).expect("présent").flags.contains(Flags::SEEN));
    assert_eq!(ici.flags_changed(), None, "chacun ne se dit qu'une fois");
    assert_eq!(
        ici.info(2).map(|info| info.uid),
        uids.get(1).copied(),
        "le deuxième garde son UID"
    );
}

// ── L'espace `Partagés` : la boîte d'autrui, dans la mesure de ses droits ────

/// `marie` et `support`, et une table où `support` a délégué sa boîte à
/// `marie` avec ces droits.
fn service_partage(
    racine: &Path,
    droits: ams_config::Rights,
) -> (BoitesImap, Arc<crate::delegations::Delegations>) {
    let mut carte = BTreeMap::new();
    let mut comptes = Vec::new();
    for login in ["marie", "support"] {
        let boite = Maildir::open(racine.join(login), HOTE, ams_store::fresh_uid_validity())
            .expect("ouvrable");
        carte.insert(String::from(login), Arc::new(boite));
        comptes.push(Account {
            login: String::from(login),
            hash: String::new(),
            addresses: std::vec![std::format!("{login}@example.com")],
        });
    }
    let comptes = Arc::new(crate::comptes::Comptes::new(
        racine.join("comptes.bin"),
        comptes,
    ));
    let boites = Arc::new(crate::delivery::Boites::new(
        carte,
        racine.to_path_buf(),
        HOTE.to_vec(),
        comptes,
    ));
    let table = Arc::new(crate::delegations::Delegations::new(
        racine.join("delegations.bin"),
        std::vec![ams_config::Delegation {
            delegate: String::from("marie"),
            owner: String::from("support"),
            rights: droits,
        }],
    ));
    (
        BoitesImap::new(boites, HOTE, Some(Arc::clone(&table))),
        table,
    )
}

/// Tous les noms que `LIST` rendrait, avec « ouvrable ? ».
fn liste(service: &BoitesImap, user: &[u8]) -> Vec<(String, bool)> {
    let mut noms = Vec::new();
    for rang in 0.. {
        let mut place = [0_u8; 512];
        let Some(vue) = service.name(user, rang, &mut place) else {
            break;
        };
        noms.push((
            String::from_utf8_lossy(vue.name).into_owned(),
            vue.selectable,
        ));
    }
    noms
}

const SA_BOITE: &[u8] = "Partagés/support/INBOX".as_bytes();

/// **LA BOÎTE D'AUTRUI PARAÎT SOUS `Partagés`, AVEC SES NŒUDS**, pour qui la
/// reçoit — et pour lui seul.
#[test]
fn la_boite_d_autrui_parait_sous_partages() {
    let atelier = Ephemere::nouveau("partage-liste");
    let (service, _) = service_partage(&atelier.0, ams_config::Rights::READ);
    let noms = liste(&service, b"marie");
    for (attendu, ouvrable) in [
        ("INBOX", true),
        ("Partagés", false),
        ("Partagés/support", false),
        ("Partagés/support/INBOX", true),
    ] {
        assert!(
            noms.contains(&(String::from(attendu), ouvrable)),
            "{attendu} manque : {noms:?}"
        );
    }
    assert!(service.shares(b"marie"));
    // `support` n'a rien reçu : ni espace, ni annonce.
    assert_eq!(
        liste(&service, b"support"),
        std::vec![(String::from("INBOX"), true)]
    );
    assert!(!service.shares(b"support"));
}

/// **EN LECTURE SEULE, RIEN NE S'ÉCRIT** : la boîte s'ouvre sans drapeau
/// permanent — la session en fait `[READ-ONLY]` —, et le dépôt, la création,
/// la copie vers elle sont refusés.
#[test]
fn en_lecture_seule_la_boite_s_ouvre_et_rien_ne_s_ecrit() {
    let atelier = Ephemere::nouveau("partage-lecture");
    let (service, _) = service_partage(&atelier.0, ams_config::Rights::READ);
    let mut depot = service.append(b"support", INBOX).expect("sa propre boîte");
    assert!(depot.write(b"From: a@b.test\r\n\r\nun\r\n"));
    depot.commit(Flags::NONE, None).expect("validé");

    let mut ouverte = service.open(b"marie", SA_BOITE).expect("lisible");
    assert_eq!(ouverte.exists(), 1);
    assert_eq!(ouverte.permanent_flags(), Flags::NONE);
    assert!(
        ouverte
            .store_flags(1, ams_proto_imap::StoreMode::Add, Flags::SEEN)
            .is_none()
    );
    assert!(!ouverte.expunge(1));
    assert!(service.append(b"marie", SA_BOITE).is_none());
    assert_eq!(
        service.create(
            b"marie",
            "Partagés/support/Neuve".as_bytes(),
            SpecialUse::NONE
        ),
        Creation::Refusee
    );
    // Copier DEPUIS elle vers chez soi est une lecture : permis.
    assert!(ouverte.copy_to(1, INBOX).is_some());
    // Copier VERS elle depuis chez soi est une écriture : refusé.
    let mut a_soi = service.open(b"marie", INBOX).expect("sa boîte");
    assert!(a_soi.copy_to(1, SA_BOITE).is_none());
}

/// **AVEC LE DROIT D'ÉCRIRE, ON ÉCRIT CHEZ LE TITULAIRE** — et nulle part
/// ailleurs : la boîte créée l'est dans SA racine.
#[test]
fn avec_l_ecriture_on_ecrit_chez_le_titulaire() {
    let atelier = Ephemere::nouveau("partage-ecriture");
    let (service, _) = service_partage(&atelier.0, ams_config::Rights::WRITE);
    let neuve = "Partagés/support/Traité".as_bytes();
    assert_eq!(
        service.create(b"marie", neuve, SpecialUse::NONE),
        Creation::Faite
    );
    assert!(
        atelier
            .0
            .join("support")
            .join(".Traité")
            .join("cur")
            .is_dir()
    );
    assert!(!atelier.0.join("marie").join(".Traité").exists());
    // Ses usages restent les siens : on ne les pose pas chez autrui.
    assert_eq!(
        service.create(
            b"marie",
            "Partagés/support/Envoi".as_bytes(),
            SpecialUse::SENT
        ),
        Creation::Refusee
    );

    let mut depot = service.append(b"marie", neuve).expect("écrivable");
    assert!(depot.write(b"From: a@b.test\r\n\r\nun\r\n"));
    depot.commit(Flags::NONE, None).expect("validé");
    let mut ouverte = service.open(b"marie", neuve).expect("ouvrable");
    assert_ne!(ouverte.permanent_flags(), Flags::NONE);
    assert!(
        ouverte
            .store_flags(1, ams_proto_imap::StoreMode::Add, Flags::SEEN)
            .is_some()
    );

    // Renommer chez lui : oui. D'un compte à l'autre : jamais.
    assert_eq!(
        service.rename(b"marie", neuve, "Partagés/support/Classé".as_bytes()),
        ams_session::imap::Renaming::Faite
    );
    assert_eq!(
        service.rename(b"marie", "Partagés/support/Classé".as_bytes(), b"Vole"),
        ams_session::imap::Renaming::Refusee
    );
    assert_eq!(
        service.delete(b"marie", "Partagés/support/Classé".as_bytes()),
        ams_session::imap::Deletion::Faite
    );
    // Son INBOX ne s'efface pas plus que la nôtre.
    assert_eq!(
        service.delete(b"marie", SA_BOITE),
        ams_session::imap::Deletion::Refusee
    );
}

/// **SANS DÉLÉGATION, L'ESPACE NE MÈNE NULLE PART** — ni vers autrui, ni vers
/// soi-même, ni par ses nœuds.
#[test]
fn sans_delegation_l_espace_ne_mene_nulle_part() {
    let atelier = Ephemere::nouveau("partage-rien");
    let (service, _) = service_partage(&atelier.0, ams_config::Rights::READ);
    for nom in [
        "Partagés/marie/INBOX",
        "Partagés",
        "Partagés/support",
        "Partagés/inconnu/INBOX",
    ] {
        assert!(service.open(b"marie", nom.as_bytes()).is_none(), "{nom}");
    }
    // `support` n'a rien reçu de `marie`.
    assert!(
        service
            .open(b"support", "Partagés/marie/INBOX".as_bytes())
            .is_none()
    );
    // Et l'on ne crée pas un dossier personnel à la place de l'espace.
    assert_eq!(
        service.create(b"marie", "Partagés".as_bytes(), SpecialUse::NONE),
        Creation::Refusee
    );
    assert_eq!(
        service.delete(b"marie", "Partagés/support".as_bytes()),
        ams_session::imap::Deletion::Absente
    );
}

/// **UNE DÉLÉGATION RETIRÉE FERME L'ÉCRITURE TOUT DE SUITE**, même dans une
/// boîte déjà ouverte ; et elle ne s'ouvre plus.
#[test]
fn une_delegation_retiree_ferme_l_ecriture_tout_de_suite() {
    let atelier = Ephemere::nouveau("partage-retrait");
    let (service, table) = service_partage(&atelier.0, ams_config::Rights::WRITE);
    let ouverte = service.open(b"marie", SA_BOITE).expect("ouvrable");
    assert_ne!(ouverte.permanent_flags(), Flags::NONE);
    table
        .modifier(|tenues| {
            tenues.clear();
            Ok(())
        })
        .expect("retirée");
    assert_eq!(ouverte.permanent_flags(), Flags::NONE);
    assert!(service.open(b"marie", SA_BOITE).is_none());
    assert!(!service.shares(b"marie"));
}

/// **S'ABONNER À LA BOÎTE D'AUTRUI SE PEUT**, puisqu'elle se liste : c'est ce
/// qui la fait paraître dans un client qui n'affiche que ses abonnements.
#[test]
fn on_s_abonne_a_la_boite_d_autrui() {
    let atelier = Ephemere::nouveau("partage-abonnement");
    let (service, _) = service_partage(&atelier.0, ams_config::Rights::READ);
    assert_eq!(
        service.subscribe(b"marie", SA_BOITE),
        ams_session::imap::Subscription::Faite
    );
    assert!(service.is_subscribed(b"marie", SA_BOITE));
    assert_eq!(
        service.subscribe(b"marie", "Partagés/inconnu/INBOX".as_bytes()),
        ams_session::imap::Subscription::Absente
    );
}

/// **UN DOSSIER PERSONNEL NOMMÉ `Partagés` EST MASQUÉ** : l'espace l'emporte.
#[test]
fn un_dossier_personnel_nomme_partages_est_masque() {
    let atelier = Ephemere::nouveau("partage-masque");
    let service = service(&atelier.0);
    Maildir::open(
        atelier.0.join("marie").join(".Partagés"),
        HOTE,
        ams_store::fresh_uid_validity(),
    )
    .expect("créé à la main");
    assert_eq!(
        liste(&service, COMPTE),
        std::vec![(String::from("INBOX"), true)]
    );
}
