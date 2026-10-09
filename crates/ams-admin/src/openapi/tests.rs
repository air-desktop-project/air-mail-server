// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le document décrit-il l'API telle qu'elle est servie ?

use ams_api::CATALOGUE;
use ams_proto_http::Method;

use super::{Objet, VERBES, document, echapper, identifiant, parametres_acceptes, verbe};

/// Ce que le document dit sous ce chemin, et rien d'autre.
///
/// Les chemins sortent dans l'ordre du catalogue : la tranche d'un chemin va de
/// sa clé jusqu'à la prochaine clé de chemin.
fn bloc(document: &str, gabarit: &str) -> String {
    let cle = format!("\"{gabarit}\": {{");
    let debut = document
        .find(&cle)
        .unwrap_or_else(|| panic!("{gabarit} ne figure pas dans le document"));
    let apres = &document[debut.saturating_add(cle.len())..];
    let fin = CATALOGUE
        .iter()
        .filter_map(|autre| apres.find(&format!("\"{}\": {{", autre.gabarit)))
        .min()
        .unwrap_or(apres.len());
    String::from(&apres[..fin])
}

/// Le document s'ouvre et se ferme, et ses accolades s'équilibrent.
///
/// Ce n'est pas un analyseur JSON — le dépôt n'en porte pas, et c'est voulu.
/// `scripts/check-openapi.sh` fait relire le document par `python3` ; ici, on
/// vérifie ce qui se vérifie sans dépendance.
#[test]
fn le_document_s_equilibre() {
    let document = document();
    assert!(
        document.starts_with("{\n"),
        "le document n'ouvre pas un objet"
    );
    assert!(document.ends_with("}\n"), "le document ne se ferme pas");
    let mut profondeur = 0_i64;
    let mut dans_une_chaine = false;
    let mut echappe = false;
    for caractere in document.chars() {
        match (dans_une_chaine, echappe, caractere) {
            (true, true, _) => echappe = false,
            (true, false, '\\') => echappe = true,
            (true, false, '"') => dans_une_chaine = false,
            (true, false, _) => {}
            (false, _, '"') => dans_une_chaine = true,
            (false, _, '{' | '[') => profondeur = profondeur.saturating_add(1),
            (false, _, '}' | ']') => {
                profondeur = profondeur.saturating_sub(1);
                assert!(profondeur >= 0, "une fermeture de trop");
            }
            (false, _, _) => {}
        }
    }
    assert_eq!(profondeur, 0, "le document ne se referme pas entièrement");
    assert!(!dans_une_chaine, "une chaîne reste ouverte");
}

/// La version d'OpenAPI et celle du serveur sont dites.
#[test]
fn le_document_se_nomme() {
    let document = document();
    assert!(document.contains("\"openapi\": \"3.1.0\""));
    assert!(document.contains(env!("CARGO_PKG_VERSION")));
}

/// Chaque chemin du catalogue figure dans le document.
#[test]
fn chaque_chemin_y_figure() {
    let document = document();
    for entree in CATALOGUE {
        assert!(
            document.contains(&format!("\"{}\": {{", entree.gabarit)),
            "{} manque au document",
            entree.gabarit
        );
    }
}

/// Chaque méthode servie figure sous son chemin, et aucune autre.
///
/// **C'EST L'ESSAI QUI VAUT LE PLUS** : il compare le document à
/// `Resource::allowed`, c'est-à-dire à ce que le serveur répondra dans `Allow`.
#[test]
fn chaque_methode_servie_y_figure_et_pas_une_de_plus() {
    let document = document();
    for entree in CATALOGUE {
        let tranche = bloc(&document, entree.gabarit);
        for method in VERBES {
            let attendu =
                entree.exemplaire.allowed().contains(&method) || matches!(method, Method::Options);
            assert_eq!(
                tranche.contains(&format!("\"{}\": {{", verbe(method))),
                attendu,
                "{} : {} devrait {}être décrite",
                entree.gabarit,
                verbe(method),
                if attendu { "" } else { "ne pas " }
            );
        }
    }
}

/// `OPTIONS` est décrite partout, et son `Allow` porte sa valeur exacte.
///
/// # L'ESSAI QUI A CHANGÉ DE SENS DEUX FOIS EN UN JOUR
///
/// Il exigeait d'abord la présence d'`OPTIONS`, sur la foi de deux commentaires
/// de `route.rs`. Une requête a montré **501** et aucun en-tête : il a été
/// retourné pour en exiger l'ABSENCE. Puis la session a servi `OPTIONS` et les
/// deux conducteurs ont porté l'`Allow` jusqu'au fil — et il exige de nouveau
/// leur présence.
///
/// Ce qui a décidé, chaque fois, c'est ce qu'une requête montre. Jamais ce qu'un
/// commentaire affirme.
#[test]
fn options_est_decrite_avec_son_allow() {
    let document = document();
    for entree in CATALOGUE {
        let tranche = bloc(&document, entree.gabarit);
        assert!(
            tranche.contains("\"options\": {"),
            "{} : OPTIONS n'est pas décrite",
            entree.gabarit
        );
        // La valeur exacte, celle que la session écrit.
        let mut place = [0_u8; ams_api::ALLOW_OCTETS_MAX];
        let permises = entree.exemplaire.allow(&mut place);
        let attendu = core::str::from_utf8(permises).expect("de l'ASCII");
        assert!(
            tranche.contains(&format!("\"const\": \"{attendu}\"")),
            "{} : l'`Allow` annoncé n'est pas {attendu:?}",
            entree.gabarit
        );
        assert!(
            attendu.ends_with("OPTIONS"),
            "{} : `Allow` devrait nommer OPTIONS",
            entree.gabarit
        );
    }
    // Le refus porte l'en-tête aussi, sans valeur : elle dépend du chemin.
    assert!(
        document.contains("\"Allow\": {"),
        "le refus devrait déclarer l'en-tête `Allow`"
    );
}

/// Les portes d'entrée déclarent `security: []`, et elles seules.
///
/// Une liste vide est la façon dont OpenAPI dit « celle-ci remplace la sécurité
/// du document par rien » : sans elle, un explorateur exigerait un jeton pour
/// aller en chercher un.
#[test]
fn seules_les_portes_d_entree_n_exigent_rien() {
    let document = document();
    for entree in CATALOGUE {
        let tranche = bloc(&document, entree.gabarit);
        let porte = entree.exemplaire.scope(Method::Post).is_none();
        assert_eq!(
            tranche.contains("\"security\": []"),
            porte,
            "{} : la sécurité vide est au mauvais endroit",
            entree.gabarit
        );
    }
}

/// Les portes d'entrée sont les quatre qu'on croit.
///
/// Si une cinquième apparaissait, ou si l'une de ces quatre se mettait à exiger
/// un jeton, c'est ici qu'on l'apprendrait.
#[test]
fn les_portes_d_entree_sont_au_nombre_de_quatre() {
    let portes: Vec<&str> = CATALOGUE
        .iter()
        .filter(|entree| entree.exemplaire.scope(Method::Post).is_none())
        .map(|entree| entree.gabarit)
        .collect();
    assert_eq!(
        portes,
        [
            "/v1/tokens",
            "/v1/sessions/challenge",
            "/v1/sessions",
            "/v1/devices"
        ]
    );
}

/// La portée exigée est dite, et c'est celle que le type rend.
#[test]
fn la_portee_exigee_est_dite() {
    let document = document();
    for (gabarit, attendu) in [
        ("/v1/bans", "admin:read"),
        ("/v1/bans/{source}", "admin:write"),
        ("/v1/mailboxes", "mail:read"),
        ("/v1/submissions", "submit:write"),
        ("/v1/health", "observe:read"),
        ("/v1/me/audit", "sans portée particulière"),
    ] {
        let tranche = bloc(&document, gabarit);
        assert!(
            tranche.contains(attendu),
            "{gabarit} devrait exiger {attendu}"
        );
    }
}

/// Les paramètres de chemin sont déclarés, et typés.
#[test]
fn les_parametres_de_chemin_sont_declares() {
    let document = document();
    let tranche = bloc(
        &document,
        "/v1/mailboxes/{boite}/messages/{uid}/parts/{partie}",
    );
    for nom in ["boite", "uid", "partie"] {
        assert!(
            tranche.contains(&format!("\"name\": \"{nom}\"")),
            "{nom} n'est pas déclaré"
        );
    }
    assert!(
        tranche.contains("\"type\": \"integer\""),
        "l'UID n'est pas un entier"
    );
    let tranche = bloc(&document, "/v1/health");
    assert!(
        !tranche.contains("\"parameters\""),
        "/v1/health n'a pas de paramètre"
    );
}

/// La sonde rend ce que la règle dit, et le document le porte.
///
/// **LES VALEURS ATTENDUES SONT ÉCRITES ICI**, et c'est le propos : si
/// `requete_permise` changeait, cet essai le dirait plutôt que de suivre en
/// silence.
#[test]
fn la_sonde_trouve_ce_que_la_regle_dit() {
    let attendu: &[(&str, &[(&str, bool)])] = &[
        (
            "/v1/mailboxes/{boite}/changes",
            &[("since", true), ("limit", false)],
        ),
        (
            "/v1/mailboxes/{boite}/messages",
            &[("before", false), ("limit", false)],
        ),
        ("/v1/me/audit", &[("limit", false)]),
        ("/v1/accounts/{compte}/audit", &[("limit", false)]),
        ("/v1/health", &[]),
        ("/v1/mailboxes", &[]),
    ];
    for (gabarit, voulu) in attendu {
        let entree = CATALOGUE
            .iter()
            .find(|entree| entree.gabarit == *gabarit)
            .unwrap_or_else(|| panic!("{gabarit} n'est pas au catalogue"));
        let trouve = parametres_acceptes(entree);
        assert_eq!(
            trouve.as_slice(),
            *voulu,
            "{gabarit} : la sonde et la règle ne disent pas la même chose"
        );
    }
}

/// Un paramètre exigé s'écrit en entier ; un paramètre facultatif se référence.
#[test]
fn un_parametre_exige_s_ecrit_en_entier() {
    let document = document();
    let tranche = bloc(&document, "/v1/mailboxes/{boite}/changes");
    assert!(
        tranche.contains("\"required\": true"),
        "`since` devrait être déclaré exigé"
    );
    assert!(
        tranche.contains("EXIGÉ ici."),
        "le document devrait dire qu'il est exigé"
    );
    let tranche = bloc(&document, "/v1/mailboxes/{boite}/messages");
    assert!(
        tranche.contains("#/components/parameters/limit"),
        "`limit` devrait être référencé"
    );
}

/// Un composant de paramètre n'est déclaré que s'il est référencé.
#[test]
fn aucun_composant_orphelin() {
    let document = document();
    let composants = document
        .split("\"parameters\": {")
        .nth(1)
        .expect("les composants déclarent des paramètres");
    for nom in ["before", "limit"] {
        assert!(
            composants.contains(&format!("\"{nom}\": {{")),
            "{nom} devrait être un composant"
        );
        assert!(
            document.contains(&format!("#/components/parameters/{nom}")),
            "{nom} est déclaré sans être référencé"
        );
    }
    // `since` n'est accepté que là où il est EXIGÉ : il s'écrit en entier, et
    // son composant serait du document mort.
    assert!(
        !document.contains("#/components/parameters/since"),
        "`since` ne devrait pas être référencé"
    );
}

/// Les identifiants d'opération sont distincts, et bien formés.
#[test]
fn les_identifiants_sont_distincts_et_bien_formes() {
    let mut vus: Vec<String> = Vec::new();
    for entree in CATALOGUE {
        for method in VERBES {
            if !entree.exemplaire.allowed().contains(&method) && !matches!(method, Method::Options)
            {
                continue;
            }
            let nom = identifiant(entree.gabarit, method);
            assert!(!vus.contains(&nom), "l'identifiant {nom} sort deux fois");
            assert!(
                !nom.contains("__") && !nom.ends_with('_'),
                "l'identifiant {nom} est mal formé"
            );
            assert!(
                nom.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "l'identifiant {nom} porte autre chose que des lettres, des chiffres et des tirets bas"
            );
            vus.push(nom);
        }
    }
    assert!(vus.len() >= CATALOGUE.len() * 2, "trop peu d'opérations");
}

/// Un identifiant connu, écrit en entier, pour que sa forme soit lisible ici.
#[test]
fn un_identifiant_se_lit() {
    assert_eq!(
        identifiant("/v1/mailboxes/{boite}/messages/{uid}/raw", Method::Get),
        "get_v1_mailboxes_boite_messages_uid_raw"
    );
    assert_eq!(
        identifiant("/v1/me/app-passwords", Method::Post),
        "post_v1_me_app_passwords"
    );
}

/// Les types de refus sont énumérés, chacun une fois.
#[test]
fn les_types_de_refus_sont_distincts() {
    let document = document();
    for reason in ams_api::Reason::TOUS {
        let kind = reason.kind();
        let combien = document.matches(&format!("\"{kind}\"")).count();
        assert_eq!(combien, 1, "{kind} sort {combien} fois");
    }
}

/// Le refus suit RFC 9457, et le type de média est le bon.
#[test]
fn le_refus_suit_la_rfc_9457() {
    let document = document();
    assert!(document.contains("application/problem+json"));
    assert!(document.contains("#/components/schemas/Probleme"));
    for champ in ["\"type\"", "\"title\"", "\"status\""] {
        assert!(
            document.contains(champ),
            "{champ} manque au schéma du refus"
        );
    }
}

/// Le document dit ce qu'il ne décrit pas.
///
/// C'est la clause d'honnêteté : les codes de succès et les schémas de corps ne
/// sont pas dans la table de routage, et le document ne doit pas laisser croire
/// qu'ils y sont.
#[test]
fn le_document_avoue_ses_manques() {
    let document = document();
    assert!(
        document.contains("\"2XX\": {"),
        "les succès devraient être par plage"
    );
    assert!(
        document.contains("schémas de corps"),
        "le document ne dit pas ce qu'il ne décrit pas"
    );
}

/// Le document est indenté, pour que son `diff` soit lisible.
#[test]
fn le_document_est_indente() {
    let document = document();
    assert!(
        document.lines().count() > 1_000,
        "le document tient sur trop peu de lignes pour être indenté"
    );
    assert!(
        document.contains("\n  \"paths\": {"),
        "les champs de premier niveau ne sont pas indentés de deux espaces"
    );
}

/// Chaque verbe a son nom en minuscules, et ils sont tous distincts.
#[test]
fn les_verbes_se_nomment() {
    let mut vus: Vec<&str> = Vec::new();
    for method in VERBES {
        let nom = verbe(method);
        assert_eq!(nom, nom.to_lowercase(), "{nom} n'est pas en minuscules");
        assert!(!vus.contains(&nom), "{nom} sort deux fois");
        vus.push(nom);
    }
    assert_eq!(vus.len(), 7, "il y a sept méthodes");
}

/// L'échappement couvre ce que §7 de RFC 8259 exige.
#[test]
fn l_echappement_couvre_la_rfc_8259() {
    assert_eq!(echapper("sans rien"), "sans rien");
    assert_eq!(echapper("un \"guillemet\""), "un \\\"guillemet\\\"");
    assert_eq!(echapper("une \\ barre"), "une \\\\ barre");
    assert_eq!(echapper("deux\nlignes"), "deux\\nlignes");
    assert_eq!(echapper("un\rretour"), "un\\rretour");
    assert_eq!(echapper("une\ttabulation"), "une\\ttabulation");
    assert_eq!(echapper("un\u{1}pilotage"), "un\\u0001pilotage");
    // L'UTF-8 passe tel quel : §8.1 veut de l'UTF-8, pas de l'ASCII.
    assert_eq!(echapper("un é et un —"), "un é et un —");
}

/// Un objet vide rend `{}`, et non une paire d'accolades sur deux lignes.
#[test]
fn un_objet_vide_rend_deux_accolades() {
    assert_eq!(Objet::new(1).fermer(), "{}");
}

/// Un objet rend ses champs dans l'ordre où on les pose.
///
/// L'ordre stable est ce qui rend le `diff` du document lisible : un document
/// dont les clés bougeraient à chaque exécution ferait échouer la barrière sans
/// qu'aucune route ait changé.
#[test]
fn un_objet_garde_l_ordre_de_ses_champs() {
    let mut objet = Objet::new(1);
    objet.texte("premier", "a");
    objet.texte("second", "b");
    assert_eq!(
        objet.fermer(),
        "{\n  \"premier\": \"a\",\n  \"second\": \"b\"\n}"
    );
}
