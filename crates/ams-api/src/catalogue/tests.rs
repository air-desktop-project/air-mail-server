// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le catalogue décrit-il exactement ce que le routage sert ?

use ams_proto_http::Method;

use super::CATALOGUE;
use crate::route::{VERSION, resolve};

/// Un tampon confortable pour décoder un chemin.
const PLACE: usize = 1_024;

/// La valeur qu'on met à la place d'un paramètre, par nom.
///
/// **ELLES DOIVENT PASSER LE ROUTAGE**, et c'est tout ce qu'on leur demande :
/// un entier sans zéro de tête pour ce qui est numérique, un segment non vide
/// pour le reste.
fn temoin(nom: &str) -> &'static str {
    match nom {
        "boite" => "INBOX",
        "uid" | "n" => "1",
        "partie" => "1.2",
        "id" => "br",
        "compte" => "ada",
        "delegue" => "bob",
        "source" => "198.51.100.7",
        autre => panic!("le gabarit porte un paramètre sans témoin : {autre}"),
    }
}

/// Instancie un gabarit : chaque `{nom}` devient son témoin.
fn concret(gabarit: &str) -> std::string::String {
    let mut sortie = std::string::String::new();
    let mut reste = gabarit;
    while let Some(debut) = reste.find('{') {
        sortie.push_str(&reste[..debut]);
        let apres = &reste[debut.saturating_add(1)..];
        let fin = apres.find('}').expect("une accolade ouverte se ferme");
        sortie.push_str(temoin(&apres[..fin]));
        reste = &apres[fin.saturating_add(1)..];
    }
    sortie.push_str(reste);
    sortie
}

/// Les rangs du catalogue sont exactement `0..len`, chacun une fois.
///
/// **C'EST LA GARDE CONTRE L'OUBLI** : une ressource ajoutée à l'énumération et
/// non décrite ici fait échouer cet essai, après avoir déjà fait échouer la
/// compilation de `rang`.
#[test]
fn les_rangs_couvrent_tout_le_catalogue() {
    let mut vus = std::vec![false; CATALOGUE.len()];
    for entree in CATALOGUE {
        let rang = entree.exemplaire.rang();
        assert!(
            rang < CATALOGUE.len(),
            "{} porte le rang {rang}, hors du catalogue ({} entrées) : une ressource a été ajoutée sans être décrite",
            entree.gabarit,
            CATALOGUE.len()
        );
        assert!(
            !vus[rang],
            "le rang {rang} est pris deux fois, la seconde par {}",
            entree.gabarit
        );
        vus[rang] = true;
    }
    let manquants: std::vec::Vec<usize> = vus
        .iter()
        .enumerate()
        .filter_map(|(rang, vu)| (!vu).then_some(rang))
        .collect();
    assert!(
        manquants.is_empty(),
        "ces rangs ne sont décrits par aucune entrée : {manquants:?}"
    );
}

/// Le catalogue est rangé par rang croissant.
///
/// Ce n'est pas de l'esthétique : le document OpenAPI sort dans cet ordre, et un
/// ordre stable est ce qui rend son `diff` lisible.
#[test]
fn le_catalogue_est_dans_l_ordre_des_rangs() {
    for (attendu, entree) in CATALOGUE.iter().enumerate() {
        assert_eq!(
            entree.exemplaire.rang(),
            attendu,
            "{} n'est pas à sa place",
            entree.gabarit
        );
    }
}

/// Chaque gabarit, instancié, se résout sur la ressource qu'il décrit.
///
/// **C'EST CE QUI INTERDIT AU GABARIT DE MENTIR.** Un chemin écrit ici que le
/// routage n'accepte pas — un segment de trop, un nom mal orthographié — échoue.
#[test]
fn chaque_gabarit_se_resout_sur_sa_ressource() {
    for entree in CATALOGUE {
        let chemin = concret(entree.gabarit);
        let mut place = [0_u8; PLACE];
        let resolu = resolve(Method::Options, chemin.as_bytes(), &mut place)
            .unwrap_or_else(|_| panic!("{} ne se résout pas ({chemin})", entree.gabarit));
        assert_eq!(
            resolu.resource.rang(),
            entree.exemplaire.rang(),
            "{} se résout sur une autre ressource",
            entree.gabarit
        );
    }
}

/// Chaque gabarit commence par la version, et elle est obligatoire.
#[test]
fn chaque_gabarit_porte_la_version() {
    for entree in CATALOGUE {
        let attendu = std::format!("/{VERSION}/");
        assert!(
            entree.gabarit.starts_with(&attendu),
            "{} ne commence pas par /{VERSION}/",
            entree.gabarit
        );
    }
}

/// Chaque résumé est une phrase : non vide, capitale au début, point à la fin.
///
/// Il part dans le document OpenAPI, que des humains lisent.
#[test]
fn chaque_resume_est_une_phrase() {
    for entree in CATALOGUE {
        let resume = entree.resume;
        assert!(!resume.is_empty(), "{} n'a pas de résumé", entree.gabarit);
        let premier = resume.chars().next().expect("le résumé n'est pas vide");
        assert!(
            premier.is_uppercase(),
            "{} : le résumé ne commence pas par une capitale",
            entree.gabarit
        );
        assert!(
            resume.ends_with('.'),
            "{} : le résumé ne finit pas par un point",
            entree.gabarit
        );
    }
}

/// Deux entrées ne décrivent jamais le même chemin.
#[test]
fn les_gabarits_sont_distincts() {
    for (rang, entree) in CATALOGUE.iter().enumerate() {
        for autre in CATALOGUE.iter().skip(rang.saturating_add(1)) {
            assert_ne!(
                entree.gabarit, autre.gabarit,
                "ce chemin est décrit deux fois"
            );
        }
    }
}

/// Chaque ressource sert au moins une méthode.
///
/// Une ressource qui n'en servirait aucune serait une entrée du document qu'on
/// ne peut pas emprunter.
#[test]
fn chaque_ressource_sert_une_methode() {
    for entree in CATALOGUE {
        assert!(
            !entree.exemplaire.allowed().is_empty(),
            "{} ne sert aucune méthode",
            entree.gabarit
        );
    }
}
