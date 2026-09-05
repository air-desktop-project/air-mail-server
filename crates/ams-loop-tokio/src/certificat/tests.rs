// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le porteur de certificat doit tenir.
//!
//! **AUCUN MATÉRIEL RÉEL ICI**, et ce n'est pas un renoncement : fabriquer un
//! certificat demande `openssl`, donc un processus, donc l'étage 3 tout entier.
//! Ce que ces essais éprouvent est la MÉCANIQUE — qu'un remplacement change ce
//! qu'on rend, et que les poignées de main en cours gardent l'ancien. Le
//! matériel vrai passe par `tests/certificat.rs`, qui monte une vraie poignée de
//! main.

use super::Certificat;
use rustls::sign::CertifiedKey;
use std::sync::Arc;

/// Un matériel reconnaissable à sa chaîne, sans rien signer.
///
/// `CertifiedKey::new` n'exige pas que la clé corresponde — c'est `from_der` qui
/// le vérifie, et c'est lui que `ams_tls::certified_key` emploie. Ici, on veut
/// deux objets DISTINCTS et rien de plus.
fn materiel(marque: u8) -> CertifiedKey {
    #[derive(Debug)]
    struct SansSignature;

    impl rustls::sign::SigningKey for SansSignature {
        fn choose_scheme(
            &self,
            _offered: &[rustls::SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            None
        }
        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            rustls::SignatureAlgorithm::ED25519
        }
    }

    CertifiedKey::new(
        std::vec![rustls::pki_types::CertificateDer::from(std::vec![marque])],
        Arc::new(SansSignature),
    )
}

/// La marque du premier certificat de la chaîne, pour distinguer deux matériels.
fn marque(materiel: &CertifiedKey) -> u8 {
    materiel
        .cert
        .first()
        .and_then(|der| der.first())
        .copied()
        .unwrap_or(0)
}

#[test]
fn le_porteur_rend_le_materiel_qu_on_lui_a_donne() {
    let porteur = Certificat::neuf(materiel(1));
    let rendu = porteur.actuel.read().expect("verrou").clone();
    assert_eq!(marque(&rendu), 1);
}

/// **UN REMPLACEMENT CHANGE CE QUE LES POIGNÉES DE MAIN SUIVANTES VOIENT.**
#[test]
fn un_remplacement_change_ce_qui_est_rendu() {
    let porteur = Certificat::neuf(materiel(1));
    porteur.remplacer(materiel(2));
    let rendu = porteur.actuel.read().expect("verrou").clone();
    assert_eq!(marque(&rendu), 2);
}

/// **UNE POIGNÉE DE MAIN EN COURS GARDE SON MATÉRIEL.**
///
/// Elle en tient un `Arc`, et il vit aussi longtemps qu'elle. Une connexion ne
/// change pas de certificat au milieu — ce qui serait une façon très sûre de la
/// faire échouer.
#[test]
fn une_poignee_de_main_en_cours_garde_l_ancien() {
    let porteur = Certificat::neuf(materiel(1));
    // Ce que la poignée de main a pris, avant le remplacement.
    let en_cours = porteur.actuel.read().expect("verrou").clone();

    porteur.remplacer(materiel(2));

    assert_eq!(marque(&en_cours), 1, "l'ancien matériel a changé sous elle");
    let suivante = porteur.actuel.read().expect("verrou").clone();
    assert_eq!(marque(&suivante), 2);
}

/// **UN VERROU EMPOISONNÉ NE FAIT PAS PERDRE LE CERTIFICAT.**
///
/// Il ne signifierait qu'une chose : un fil a paniqué en le tenant. La donnée
/// qu'il protège est un `Arc` — rien ne peut l'avoir laissée à moitié écrite —
/// et refuser de la rendre condamnerait le serveur à ne plus servir de TLS du
/// tout, pour une panique qui n'a rien à voir.
#[test]
fn un_verrou_empoisonne_ne_fait_pas_perdre_le_certificat() {
    let porteur = Arc::new(Certificat::neuf(materiel(1)));
    let empoisonneur = Arc::clone(&porteur);
    // On empoisonne le verrou : un fil panique en le tenant.
    let _ = std::thread::spawn(move || {
        let _garde = empoisonneur.actuel.write().expect("verrou");
        panic!("on empoisonne");
    })
    .join();

    assert!(
        porteur.actuel.is_poisoned(),
        "le verrou devait être empoisonné"
    );
    // ET LE SERVICE CONTINUE : on lit, et on remplace.
    porteur.remplacer(materiel(2));
    let rendu = porteur
        .actuel
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(marque(&rendu), 2);
}
