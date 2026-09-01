// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un magasin modifiable garantit, et ce qu'il refuse.

use std::path::PathBuf;

use ams_auth::Account;

use super::{Comptes, Faute};

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
        "ams-comptes-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Une empreinte licite, calculée une fois.
fn empreinte() -> String {
    ams_auth::hash_password(b"ouvre-toi", b"seize octets ici").expect("hachable")
}

/// Un compte d'essai.
fn compte(login: &str, adresses: &[&str]) -> Account {
    Account {
        login: String::from(login),
        hash: empreinte(),
        addresses: adresses.iter().map(|a| String::from(*a)).collect(),
    }
}

/// Une façon de casser le magasin, pour éprouver ce qu'il refuse.
type Casser = fn(&mut Vec<Account>);

/// Un magasin ouvert sur un fichier neuf.
fn magasin(atelier: &Atelier, comptes: Vec<Account>) -> Comptes {
    Comptes::new(atelier.0.join("comptes.bin"), comptes)
}

/// **CE QU'ON MODIFIE EST VU PAR LA LECTURE SUIVANTE**, et écrit sur le disque.
#[tokio::test(flavor = "multi_thread")]
async fn une_modification_se_voit_et_se_pose() {
    let atelier = atelier("pose");
    let magasin = magasin(&atelier, std::vec![compte("marc", &["marc@exemple.test"])]);
    assert_eq!(magasin.vue().len(), 1);

    magasin
        .modifier(|comptes| {
            comptes.push(compte("jeanne", &["jeanne@exemple.test"]));
            Ok(())
        })
        .expect("modifiable");

    assert_eq!(magasin.vue().len(), 2, "la vue suivante le voit");
    // Et le disque aussi : on le relit comme le démarrage le ferait.
    let octets = std::fs::read(atelier.0.join("comptes.bin")).expect("écrit");
    let relu = ams_config::decode_accounts(&octets).expect("relisible");
    assert_eq!(relu.len(), 2, "le disque porte la même chose");
}

/// **UN INSTANTANÉ NE CHANGE PAS SOUS LES PIEDS DE CELUI QUI LE TIENT.**
///
/// Un `RCPT` accepté ne doit pas devenir un `RCPT` refusé au milieu du `DATA`
/// parce qu'un administrateur passait par là.
#[tokio::test(flavor = "multi_thread")]
async fn un_instantane_ne_bouge_pas() {
    let atelier = atelier("instantane");
    let magasin = magasin(&atelier, std::vec![compte("marc", &["marc@exemple.test"])]);

    let avant = magasin.vue();
    magasin
        .modifier(|comptes| {
            comptes.clear();
            Ok(())
        })
        .expect("modifiable");

    assert_eq!(avant.len(), 1, "celui qui tenait la vue la garde entière");
    assert_eq!(magasin.vue().len(), 0, "et la suivante voit le changement");
}

/// **IL EST IMPOSSIBLE D'ÉCRIRE UN MAGASIN SUR LEQUEL LE SERVEUR NE REDÉMARRERAIT
/// PAS.**
///
/// Toute modification est réencodée puis relue par le décodeur du démarrage. Ce
/// qu'on refuse d'écrire est exactement ce qu'on refuserait de relire — et cela
/// donne gratuitement toutes les invariantes du magasin, sans les redire ici.
#[tokio::test(flavor = "multi_thread")]
async fn ce_que_le_demarrage_refuserait_ne_s_ecrit_pas() {
    let atelier = atelier("invariantes");
    let magasin = magasin(&atelier, std::vec![compte("marc", &["marc@exemple.test"])]);

    let refus: [(&str, Casser); 4] = [
        // Un nom qui deviendrait un chemin.
        ("nom illicite", |comptes| {
            comptes.push(compte("../ailleurs", &[]));
        }),
        // Deux empreintes pour un nom : une question sans réponse.
        ("nom en double", |comptes| {
            comptes.push(compte("marc", &["autre@exemple.test"]));
        }),
        // Une adresse, une boîte : deux comptes qui la déclarent feraient partir
        // la moitié du courrier au mauvais endroit.
        ("adresse partagée", |comptes| {
            comptes.push(compte("jeanne", &["marc@exemple.test"]));
        }),
        // Une empreinte que le plancher refuse.
        ("empreinte faible", |comptes| {
            comptes.push(Account {
                login: String::from("jeanne"),
                hash: String::from("pas-une-empreinte"),
                addresses: std::vec::Vec::new(),
            });
        }),
    ];

    for (quoi, casser) in refus {
        let issue = magasin.modifier(|comptes| {
            casser(comptes);
            Ok(())
        });
        assert!(
            matches!(issue, Err(Faute::Refuse(_))),
            "« {quoi} » devait être refusé"
        );
        assert_eq!(magasin.vue().len(), 1, "et rien n'a bougé : {quoi}");
    }
}

/// **UNE MODIFICATION QUI SE REFUSE ELLE-MÊME NE TOUCHE À RIEN.**
#[tokio::test(flavor = "multi_thread")]
async fn une_modification_qui_renonce_ne_pose_rien() {
    let atelier = atelier("renonce");
    let magasin = magasin(&atelier, std::vec![compte("marc", &["marc@exemple.test"])]);
    let issue = magasin.modifier(|comptes| {
        comptes.clear();
        Err(Faute::Introuvable)
    });
    assert!(matches!(issue, Err(Faute::Introuvable)));
    assert_eq!(magasin.vue().len(), 1);
    assert!(
        !atelier.0.join("comptes.bin").exists(),
        "et rien n'a été écrit"
    );
}

/// **ON ÉCRIT D'ABORD, ON PUBLIE ENSUITE.**
///
/// Si le disque refuse, la vue en mémoire n'a pas bougé et le serveur continue de
/// servir la vérité qui est sur le disque. L'ordre inverse ferait servir un compte
/// qui disparaîtrait au prochain démarrage, sans que rien ne l'ait dit.
#[tokio::test(flavor = "multi_thread")]
async fn un_disque_qui_refuse_ne_publie_rien() {
    let atelier = atelier("disque");
    // Un chemin dont le répertoire n'existe pas : l'écriture ne peut pas aboutir.
    let magasin = Comptes::new(
        atelier.0.join("nulle-part").join("comptes.bin"),
        std::vec![compte("marc", &["marc@exemple.test"])],
    );
    let issue = magasin.modifier(|comptes| {
        comptes.push(compte("jeanne", &["jeanne@exemple.test"]));
        Ok(())
    });
    assert!(matches!(issue, Err(Faute::Ecriture(_))));
    assert_eq!(
        magasin.vue().len(),
        1,
        "la vue en mémoire n'a pas bougé d'un pouce"
    );
}

/// **LE FICHIER EST ÉCRIT EN `0600`, DÈS SON OUVERTURE.**
///
/// Le serveur refuse de démarrer sur un magasin lisible par tout le monde ; en
/// écrire un ainsi rendrait le serveur incapable de redémarrer sur ce qu'il vient
/// lui-même d'écrire.
#[tokio::test(flavor = "multi_thread")]
async fn le_fichier_pose_n_est_lisible_que_par_son_maitre() {
    use std::os::unix::fs::PermissionsExt as _;

    let atelier = atelier("permissions");
    let magasin = magasin(&atelier, std::vec::Vec::new());
    magasin
        .modifier(|comptes| {
            comptes.push(compte("marc", &["marc@exemple.test"]));
            Ok(())
        })
        .expect("modifiable");

    let mode = std::fs::metadata(atelier.0.join("comptes.bin"))
        .expect("écrit")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "ni le groupe ni les autres : {mode:o}");
}

/// **AUCUN PROVISOIRE NE TRAÎNE**, ni après un succès, ni après un échec.
///
/// Un provisoire oublié serait un fichier de comptes de plus, avec un nom que
/// personne ne lit et un contenu que personne ne relit.
#[tokio::test(flavor = "multi_thread")]
async fn aucun_fichier_provisoire_ne_traine() {
    let atelier = atelier("provisoire");
    let magasin = magasin(&atelier, std::vec::Vec::new());
    magasin
        .modifier(|comptes| {
            comptes.push(compte("marc", &["marc@exemple.test"]));
            Ok(())
        })
        .expect("modifiable");

    let restants: std::vec::Vec<_> = std::fs::read_dir(&atelier.0)
        .expect("lisible")
        .flatten()
        .map(|entree| entree.file_name().to_string_lossy().into_owned())
        .filter(|nom| nom.ends_with(".tmp"))
        .collect();
    assert!(restants.is_empty(), "il en reste : {restants:?}");
}
