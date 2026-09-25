// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce banc éprouve les trois propriétés que ce module existe pour tenir : le
//! vérificateur s'ouvre avec la bonne clé, ne s'ouvre pas autrement, et ne
//! change pas de compte en chemin.

use super::{
    CLE_SCELLEMENT_OCTETS, Cles, Error, ITERATIONS, NONCE_OCTETS, SEL_OCTETS, deriver, lier,
    ouvrir, sel_factice,
};
use ams_sasl::{CLE_OCTETS, client_key, derive_salted_password, server_key, stored_key};

const CLEF: [u8; CLE_SCELLEMENT_OCTETS] = [7; CLE_SCELLEMENT_OCTETS];
const SEL: [u8; SEL_OCTETS] = [3; SEL_OCTETS];
const NONCE: [u8; NONCE_OCTETS] = [9; NONCE_OCTETS];
/// Un compte d'itérations bas : ce banc éprouve le scellement, pas le coût de
/// PBKDF2, et 32 768 tours multipliés par le nombre d'essais coûteraient des
/// secondes pour ne rien prouver de plus.
const TOURS: u32 = 4_096;
/// L'empreinte `argon2id` que le compte porte — sa forme importe peu ici : la
/// liaison la condense sans la lire.
const EMPREINTE: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2VsIGRlIGplYW4$ZW1wcmVpbnRl";

#[test]
fn ce_qui_est_scelle_est_bien_les_deux_cles_de_la_rfc() {
    let v = deriver(b"pencil", "jean", EMPREINTE, SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    let ouvertes = ouvrir(&v, EMPREINTE, &CLEF).expect("ouverture");

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
    let v = deriver(b"pencil", "jean", EMPREINTE, SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    let mut autre = CLEF;
    *autre.first_mut().expect("clé") ^= 1;
    assert_eq!(ouvrir(&v, EMPREINTE, &autre), Err(Error::Sceau));
}

#[test]
fn un_verificateur_deplace_d_un_compte_a_l_autre_n_ouvre_pas() {
    // **C'EST CE QUE LES DONNÉES ASSOCIÉES ACHÈTENT.** Sans elles, qui peut
    // écrire le magasin sans connaître la clé donnerait à `contact` le
    // vérificateur d'un compte dont il connaît le mot de passe.
    let mut v =
        deriver(b"pencil", "jean", EMPREINTE, SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    // On déplace l'entrée : le scellé reste, le login change. C'est exactement
    // ce qu'un intrus qui peut écrire le fichier sans avoir la clé ferait.
    v.login = std::string::String::from("contact");
    assert_eq!(ouvrir(&v, EMPREINTE, &CLEF), Err(Error::Sceau));
}

#[test]
fn un_scelle_altere_n_ouvre_pas() {
    let v = deriver(b"pencil", "jean", EMPREINTE, SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    for rang in [0, CLE_OCTETS, v.scelle.len().saturating_sub(1)] {
        let mut abime = v.clone();
        if let Some(octet) = abime.scelle.get_mut(rang) {
            *octet ^= 1;
        }
        assert_eq!(
            ouvrir(&abime, EMPREINTE, &CLEF),
            Err(Error::Sceau),
            "un octet retourné au rang {rang} a été accepté"
        );
    }
    // Un nonce changé ne s'ouvre pas davantage.
    let mut autre_nonce = v.clone();
    *autre_nonce.nonce.first_mut().expect("nonce") ^= 1;
    assert_eq!(ouvrir(&autre_nonce, EMPREINTE, &CLEF), Err(Error::Sceau));
}

#[test]
fn un_clair_de_mauvaise_taille_est_refuse() {
    // Le seul chemin qui mène à `Taille` est un scellé LICITE dont le clair
    // n'a pas soixante-quatre octets : on le fabrique exprès, puisque `deriver`
    // ne peut pas en produire.
    let court = super::sceller(
        b"trop court",
        &super::donnees_liees("jean", EMPREINTE),
        &NONCE,
        &CLEF,
    )
    .expect("scellement");
    let v = super::Verificateur {
        login: std::string::String::from("jean"),
        sel: SEL,
        iterations: TOURS,
        nonce: NONCE,
        scelle: court,
        lie: true,
    };
    assert_eq!(ouvrir(&v, EMPREINTE, &CLEF), Err(Error::Taille));
    // Et la liaison d'un ancien vérificateur au clair trop court se refuse de
    // même : elle doit l'ouvrir d'abord.
    let ancien_court = super::sceller(b"trop court", b"jean", &NONCE, &CLEF).expect("scellement");
    let ancien = super::Verificateur {
        scelle: ancien_court,
        lie: false,
        ..v
    };
    assert_eq!(
        lier(&ancien, EMPREINTE, AUTRE_NONCE, &CLEF),
        Err(Error::Taille)
    );
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
    assert_ne!(Error::Sceau, Error::NonLie);
    for erreur in [Error::Sceau, Error::Taille, Error::NonLie] {
        assert!(!std::format!("{erreur:?}").is_empty());
        let copie = erreur;
        assert_eq!(erreur, copie);
    }
    // Les deux types rendus se comparent et se déboguent, comme partout.
    let v = deriver(b"pencil", "jean", EMPREINTE, SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    assert_eq!(v.clone(), v);
    assert!(!std::format!("{v:?}").is_empty());
    let cles = ouvrir(&v, EMPREINTE, &CLEF).expect("ouverture");
    assert_eq!(cles, cles);
    assert!(!std::format!("{cles:?}").is_empty());
}

/// Un autre nonce, pour les rescellements.
const AUTRE_NONCE: [u8; NONCE_OCTETS] = [11; NONCE_OCTETS];

/// **UN MOT DE PASSE CHANGÉ ÉTEINT SON VÉRIFICATEUR.**
///
/// C'est la raison d'être de la liaison : jusqu'en 0.2.15, changer un mot de
/// passe par l'API laissait l'ancien ouvrir la boîte par SCRAM. Le compte porte
/// désormais une autre empreinte, et l'ancien vérificateur ne s'ouvre plus —
/// quel que soit le chemin qui a changé le mot de passe.
#[test]
fn un_mot_de_passe_change_eteint_son_verificateur() {
    let v = deriver(b"pencil", "jean", EMPREINTE, SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    assert!(v.lie);
    assert!(ouvrir(&v, EMPREINTE, &CLEF).is_ok());
    let nouvelle = "$argon2id$v=19$m=19456,t=2,p=1$YXV0cmUgc2Vs$YXV0cmUgZW1wcmVpbnRl";
    assert_eq!(ouvrir(&v, nouvelle, &CLEF), Err(Error::Sceau));
}

/// **UN VÉRIFICATEUR D'AVANT LA 0.2.16 NE S'OUVRE PLUS**, tant qu'on ne l'a pas
/// lié — et une fois lié, il s'ouvre sous l'empreinte donnée, et sous elle
/// seule.
#[test]
fn un_ancien_verificateur_se_lie_une_fois_pour_toutes() {
    // Un vérificateur tel que les versions précédentes l'écrivaient : scellé
    // sous le seul login.
    let lie = deriver(b"pencil", "jean", EMPREINTE, SEL, TOURS, NONCE, &CLEF).expect("dérivation");
    let cles = ouvrir(&lie, EMPREINTE, &CLEF).expect("ouverture");
    let mut clair = std::vec::Vec::new();
    clair.extend_from_slice(&cles.stored);
    clair.extend_from_slice(&cles.server);
    let ancien = super::Verificateur {
        scelle: super::sceller(&clair, b"jean", &NONCE, &CLEF).expect("scellement"),
        lie: false,
        ..lie.clone()
    };
    assert_eq!(ouvrir(&ancien, EMPREINTE, &CLEF), Err(Error::NonLie));

    let relie = lier(&ancien, EMPREINTE, AUTRE_NONCE, &CLEF).expect("liaison");
    assert!(relie.lie);
    assert_eq!(
        relie.nonce, AUTRE_NONCE,
        "le rescellement tire un nonce neuf"
    );
    assert_eq!(relie.sel, ancien.sel);
    assert_eq!(relie.iterations, ancien.iterations);
    assert_eq!(ouvrir(&relie, EMPREINTE, &CLEF), Ok(cles));
    assert_eq!(
        ouvrir(&relie, "une autre empreinte", &CLEF),
        Err(Error::Sceau)
    );

    // Lier un vérificateur DÉJÀ lié le rend tel quel : une migration relancée
    // ne doit pas échouer.
    assert_eq!(
        lier(&lie, "peu importe", AUTRE_NONCE, &CLEF),
        Ok(lie.clone())
    );

    // Et un ancien qui ne s'ouvre pas sous son login ne se lie pas.
    let mut abime = ancien;
    abime.login = std::string::String::from("contact");
    assert_eq!(
        lier(&abime, EMPREINTE, AUTRE_NONCE, &CLEF),
        Err(Error::Sceau)
    );
}

/// **LE LOGIN ET L'EMPREINTE NE SE RECOLLENT PAS** : l'octet nul qui les
/// sépare ne peut pas apparaître dans un login.
#[test]
fn les_donnees_liees_separent_le_login_de_l_empreinte() {
    let donnees = super::donnees_liees("jean", EMPREINTE);
    assert!(donnees.starts_with(b"jean\0"));
    assert_eq!(donnees.len(), 4 + 1 + 32);
    assert_ne!(
        super::donnees_liees("jean", EMPREINTE),
        super::donnees_liees("jea", EMPREINTE)
    );
}
