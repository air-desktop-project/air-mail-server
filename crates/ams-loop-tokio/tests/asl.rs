// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'attache : ce qu'elle garantit **sans** annuaire en face.
//!
//! # LA PROPRIÉTÉ QUI COMPTE LE PLUS EST CELLE-CI
//!
//! `protocole.md` §1.4 du dépôt ASL : **un annuaire injoignable ne doit pas
//! empêcher un daemon de démarrer.** Un service de découverte en panne rendrait
//! sinon indisponibles tous les daemons qui en dépendent — la faute exacte que
//! ce genre de composant existe pour ne pas commettre.
//!
//! Elle s'éprouve donc sans rien en face : on pointe l'attache vers une adresse
//! où personne n'écoute, et on exige qu'elle rende la main tout de suite.
//!
//! # CE QUI N'EST PAS ÉPROUVÉ ICI, ET POURQUOI
//!
//! L'annonce elle-même. Elle demande un annuaire qui parle QUIC et HTTP/3, et
//! qui serve `/v1/defi` et `/v1/annonce` — c'est-à-dire un vrai annuaire, ou un
//! faux qui dirait ce que nous croyons qu'un annuaire dit. L'écoute de ce
//! dépôt-ci ne sert pas ces routes.
//!
//! Ce que ces essais garantissent est le reste : que le serveur démarre, que
//! l'attache ne mente pas sur son état, et qu'un retrait rende la main.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ams_loop_tokio::{AnnuaireAsl, AttacheAsl};

/// Une identité de machine d'essai.
fn identite() -> asl_client::Identite {
    let machine = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x71; 16]);
    asl_client::Identite::nouvelle(machine, [0x3c; 32]).expect("une machine")
}

/// Un annuaire où personne n'écoute.
///
/// **LE PORT 1 DU BOUCLAGE** : il est sous 1024, donc aucun essai de ce dépôt
/// ne peut l'avoir pris — ils n'ont pas le droit de s'y lier. C'est ce qui rend
/// cet essai immune à la course de `port_libre()` qui frappe ses voisins.
fn personne() -> AnnuaireAsl {
    let adresse: SocketAddr = "127.0.0.1:1".parse().expect("une adresse");
    AnnuaireAsl {
        adresse,
        identite: asl_id::Identifiant::depuis_entropie(asl_id::Genre::Annuaire, [0x0a; 16]),
    }
}

/// **UN ANNUAIRE INJOIGNABLE NE RETARDE PAS LE DÉMARRAGE.**
///
/// C'est la propriété de §1.4, et elle se mesure : `annoncer` ne fait aucune
/// entrée-sortie, donc elle rend la main en moins de temps qu'une poignée de
/// main QUIC ne met à échouer.
#[tokio::test(flavor = "current_thread")]
async fn un_annuaire_injoignable_ne_retarde_pas_le_demarrage() {
    let depart = Instant::now();
    let attache = AttacheAsl::annoncer(
        std::vec![personne()],
        identite(),
        std::vec![std::vec![b'{', b'}']],
        10,
    )
    .expect("un annuaire déclaré suffit");
    let rendu = depart.elapsed();

    assert!(
        rendu < Duration::from_millis(200),
        "`annoncer` doit rendre la main tout de suite, pas en {rendu:?}"
    );
    // **ET ELLE NE PRÉTEND PAS ÊTRE ATTACHÉE** : rien n'a encore abouti, et
    // dire le contraire ferait croire à une annonce que personne ne tient.
    assert!(!attache.etat().attachee);
    assert_eq!(attache.etat().attaches, 0);
    assert_eq!(attache.etat().cadence_s, 0, "aucun bail n'a été accordé");

    attache.retirer().await;
}

/// **SANS ANNUAIRE, C'EST UNE CONFIGURATION ET NON UNE PANNE.**
///
/// Elle est rendue dans la main de l'appelant plutôt que réessayée : une
/// attache sans annuaire tournerait en rond en silence, et son porteur croirait
/// qu'elle cherche.
#[tokio::test(flavor = "current_thread")]
async fn sans_annuaire_l_attache_se_refuse() {
    let faute = AttacheAsl::annoncer(std::vec![], identite(), std::vec![], 10)
        .expect_err("rien à joindre se refuse");
    assert!(
        faute.to_string().contains("rien ne s'annoncerait"),
        "le refus doit dire la conséquence : {faute}"
    );
}

/// **UNE LISTE D'ANNONCES VIDE EST ACCEPTÉE.**
///
/// Une machine peut vouloir une connexion authentifiée auprès de l'annuaire
/// sans rien annoncer elle-même. C'est au serveur de le DIRE au démarrage,
/// parce que c'est presque toujours un oubli — mais ce n'est pas une faute de
/// configuration, et l'attache n'a pas à en juger.
#[tokio::test(flavor = "current_thread")]
async fn une_liste_d_annonces_vide_est_acceptee() {
    let attache = AttacheAsl::annoncer(std::vec![personne()], identite(), std::vec![], 10)
        .expect("ne rien annoncer est licite");
    attache.retirer().await;
}

/// **LE RETRAIT REND LA MAIN, MÊME QUAND RIEN N'A ABOUTI.**
///
/// Attendre sans borne donnerait à un pair muet le pouvoir de retarder l'arrêt
/// de ce serveur. La borne est de deux secondes ; on exige largement moins que
/// le double.
#[tokio::test(flavor = "current_thread")]
async fn le_retrait_rend_la_main_meme_sans_rien_avoir_tenu() {
    let attache = AttacheAsl::annoncer(
        std::vec![personne(), personne()],
        identite(),
        std::vec![],
        10,
    )
    .expect("deux annuaires déclarés");

    let depart = Instant::now();
    attache.retirer().await;
    let rendu = depart.elapsed();
    assert!(
        rendu < Duration::from_secs(4),
        "le retrait doit être borné, pas {rendu:?}"
    );
}

/// **LÂCHER L'ATTACHE INTERROMPT SA TÂCHE.**
///
/// La connexion EST le bail : la destruction de cette structure est le retrait,
/// et c'est ce qui évite le pire des deux mondes — une annonce que plus
/// personne ne tient et que l'annuaire continue de publier.
#[tokio::test(flavor = "current_thread")]
async fn lacher_l_attache_interrompt_sa_tache() {
    let attache = AttacheAsl::annoncer(std::vec![personne()], identite(), std::vec![], 10)
        .expect("un annuaire déclaré");
    drop(attache);
    // Rien à affirmer de plus qu'une absence de panique et de fuite : ce que
    // cet essai garde est que `Drop` existe et abandonne la tâche. Sans lui,
    // elle tournerait après la fin de son porteur.
    tokio::time::sleep(Duration::from_millis(50)).await;
}
