// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce banc éprouve les trois propriétés que ce module existe pour tenir : le
//! vérificateur s'ouvre avec la bonne clé, ne s'ouvre pas autrement, et ne
//! change pas de compte en chemin.

use super::{
    CLE_SCELLEMENT_OCTETS, Cles, Error, ITERATIONS, NONCE_OCTETS, SEL_OCTETS, deriver, ouvrir,
    sel_factice,
};
use ams_sasl::{CLE_OCTETS, client_key, derive_salted_password, server_key, stored_key};

const CLEF: [u8; CLE_SCELLEMENT_OCTETS] = [7; CLE_SCELLEMENT_OCTETS];
const SEL: [u8; SEL_OCTETS] = [3; SEL_OCTETS];
const NONCE: [u8; NONCE_OCTETS] = [9; NONCE_OCTETS];
/// Un compte d'itérations bas : ce banc éprouve le scellement, pas le coût de
/// PBKDF2, et 32 768 tours multipliés par le nombre d'essais coûteraient des
/// secondes pour ne rien prouver de plus.
const TOURS: u32 = 4_096;

#[test]
fn ce_qui_est_scelle_est_bien_les_deux_cles_de_la_rfc() {
    let v = deriver(b"pencil", "jean", SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    let ouvertes = ouvrir(&v, &CLEF).expect("ouverture");

    // Les mêmes clés, calculées à côté par le chemin de `ams-sasl`.
    let salted = derive_salted_password(b"pencil", &SEL, TOURS);
    assert_eq!(
        ouvertes,
        Cles {
            stored: stored_key(&client_key(&salted)),
            server: server_key(&salted),
        },
        "le scellement n'a pas rendu les clés qu'il avait reçues"
    );
    // Le sel et les itérations restent lisibles : le `server-first` les annonce.
    assert_eq!(v.sel, SEL);
    assert_eq!(v.iterations, TOURS);
    // Et le scellé ne porte AUCUNE des deux clés en clair.
    let salted = derive_salted_password(b"pencil", &SEL, TOURS);
    for cle in [stored_key(&client_key(&salted)), server_key(&salted)] {
        assert!(
            !v.scelle.windows(CLE_OCTETS).any(|fenetre| fenetre == cle),
            "une clé se lit en clair dans le scellé"
        );
    }
}

#[test]
fn une_mauvaise_clef_n_ouvre_pas() {
    let v = deriver(b"pencil", "jean", SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    let mut autre = CLEF;
    *autre.first_mut().expect("clé") ^= 1;
    assert_eq!(ouvrir(&v, &autre), Err(Error::Sceau));
}

#[test]
fn un_verificateur_deplace_d_un_compte_a_l_autre_n_ouvre_pas() {
    // **C'EST CE QUE LES DONNÉES ASSOCIÉES ACHÈTENT.** Sans elles, qui peut
    // écrire le magasin sans connaître la clé donnerait à `contact` le
    // vérificateur d'un compte dont il connaît le mot de passe.
    let mut v = deriver(b"pencil", "jean", SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    // On déplace l'entrée : le scellé reste, le login change. C'est exactement
    // ce qu'un intrus qui peut écrire le fichier sans avoir la clé ferait.
    v.login = std::string::String::from("contact");
    assert_eq!(ouvrir(&v, &CLEF), Err(Error::Sceau));
}

#[test]
fn un_scelle_altere_n_ouvre_pas() {
    let v = deriver(b"pencil", "jean", SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    for rang in [0, CLE_OCTETS, v.scelle.len().saturating_sub(1)] {
        let mut abime = v.clone();
        if let Some(octet) = abime.scelle.get_mut(rang) {
            *octet ^= 1;
        }
        assert_eq!(
            ouvrir(&abime, &CLEF),
            Err(Error::Sceau),
            "un octet retourné au rang {rang} a été accepté"
        );
    }
    // Un nonce changé ne s'ouvre pas davantage.
    let mut autre_nonce = v.clone();
    *autre_nonce.nonce.first_mut().expect("nonce") ^= 1;
    assert_eq!(ouvrir(&autre_nonce, &CLEF), Err(Error::Sceau));
}

#[test]
fn un_clair_de_mauvaise_taille_est_refuse() {
    // Le seul chemin qui mène à `Taille` est un scellé LICITE dont le clair
    // n'a pas soixante-quatre octets : on le fabrique exprès, puisque `deriver`
    // ne peut pas en produire.
    let court = super::sceller(b"trop court", b"jean", &NONCE, &CLEF).expect("scellement");
    let v = super::Verificateur {
        login: std::string::String::from("jean"),
        sel: SEL,
        iterations: TOURS,
        nonce: NONCE,
        scelle: court,
    };
    assert_eq!(ouvrir(&v, &CLEF), Err(Error::Taille));
}

#[test]
fn le_sel_factice_est_stable_distinct_et_imprevisible() {
    // Stable : deux appels rendent le même — sans quoi deux tentatives
    // suffiraient à distinguer un compte inconnu d'un vrai.
    assert_eq!(sel_factice(b"absent", &CLEF), sel_factice(b"absent", &CLEF));
    // Distinct d'un compte à l'autre.
    assert_ne!(sel_factice(b"absent", &CLEF), sel_factice(b"autre", &CLEF));
    // Et il dépend de la clé : qui ne l'a pas ne peut pas le prévoir.
    let mut autre = CLEF;
    *autre.last_mut().expect("clé") ^= 1;
    assert_ne!(
        sel_factice(b"absent", &CLEF),
        sel_factice(b"absent", &autre)
    );
}

#[test]
fn le_compte_d_iterations_du_produit_depasse_le_minimum_de_la_rfc() {
    const { assert!(ITERATIONS >= ams_sasl::ITERATIONS_MIN) };
    const {
        assert!(
            ITERATIONS == 32_768,
            "la valeur est un choix, pas un hasard"
        )
    };
}

#[test]
fn les_erreurs_se_disent_et_se_distinguent() {
    assert_ne!(Error::Sceau, Error::Taille);
    for erreur in [Error::Sceau, Error::Taille] {
        assert!(!std::format!("{erreur:?}").is_empty());
        let copie = erreur;
        assert_eq!(erreur, copie);
    }
    // Les deux types rendus se comparent et se déboguent, comme partout.
    let v = deriver(b"pencil", "jean", SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    assert_eq!(v.clone(), v);
    assert!(!std::format!("{v:?}").is_empty());
    let cles = ouvrir(&v, &CLEF).expect("ouverture");
    assert_eq!(cles, cles);
    assert!(!std::format!("{cles:?}").is_empty());
}
