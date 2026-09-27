//! Ce que l'extraction du domaine d'auteur doit tenir.

use super::author_domain;
use crate::Error;

fn domaine(valeur: &str) -> Result<&str, Error> {
    author_domain(valeur.as_bytes()).map(|octets| core::str::from_utf8(octets).expect("ASCII"))
}

#[test]
fn les_deux_formes_ordinaires_se_lisent() {
    // Avec un nom d'affichage, et sans.
    assert_eq!(
        domaine(" Joe SixPack <joe@football.example.com>"),
        Ok("football.example.com")
    );
    assert_eq!(domaine(" joe@example.com"), Ok("example.com"));
    assert_eq!(domaine("joe@example.com"), Ok("example.com"));
    assert_eq!(domaine(" <joe@example.com>"), Ok("example.com"));
}

#[test]
fn le_pliage_ne_gene_pas() {
    // La valeur arrive ENCORE PLIÉE : le domaine, lui, ne se plie pas — un
    // `dot-atom` n'admet pas de blanc interne.
    assert_eq!(
        domaine(" Joe SixPack\r\n <joe@example.com>"),
        Ok("example.com")
    );
    assert_eq!(domaine(" joe@example.com\r\n "), Ok("example.com"));
}

#[test]
fn un_nom_d_affichage_entre_guillemets_ne_trompe_pas() {
    // Il peut porter des chevrons, des virgules et des arobases : ce sont des
    // caractères comme les autres tant qu'on est entre guillemets.
    assert_eq!(
        domaine(" \"SixPack, Joe <joe@ailleurs.test>\" <joe@example.com>"),
        Ok("example.com")
    );
    // Et une contre-oblique protège le guillemet suivant.
    assert_eq!(
        domaine(" \"Joe \\\" SixPack\" <joe@example.com>"),
        Ok("example.com")
    );
}

#[test]
fn une_partie_locale_entre_guillemets_peut_porter_un_arobase() {
    // C'EST LE DERNIER `@` QUI COMPTE : `"a@b"@example.com` a pour domaine
    // `example.com`, et prendre le premier rendrait `b"@example.com`.
    assert_eq!(domaine(" \"a@b\"@example.com"), Ok("example.com"));
    assert_eq!(domaine(" <\"a@b\"@example.com>"), Ok("example.com"));
}

#[test]
fn les_commentaires_se_traversent() {
    // RFC 5322 §3.2.2 : ils peuvent se placer à peu près partout, et
    // s'imbriquer.
    assert_eq!(domaine(" (le vrai) joe@example.com"), Ok("example.com"));
    assert_eq!(domaine(" joe@example.com (le vrai)"), Ok("example.com"));
    assert_eq!(
        domaine(" (un (commentaire) imbriqué) <joe@example.com>"),
        Ok("example.com")
    );
    // Un commentaire peut porter des chevrons et des virgules sans que cela
    // compte pour des adresses.
    assert_eq!(
        domaine(" (a, b <x@y.test>) joe@example.com"),
        Ok("example.com")
    );
}

#[test]
fn un_commentaire_qui_coupe_le_domaine_fait_refuser() {
    // Recoller les morceaux demanderait un tampon, et cette crate n'alloue pas.
    // Refuser vaut mieux que rendre un domaine qu'on a fabriqué.
    assert_eq!(domaine(" joe@(vrai)example.com"), Err(Error::NoAddress));
    assert_eq!(domaine(" joe@example(x).com"), Err(Error::NoAddress));
}

// ── CE QUI FAIT REFUSER ─────────────────────────────────────────────────────

#[test]
fn plusieurs_adresses_font_refuser() {
    // RFC 7489 §6.6.1 : avec deux auteurs, il y a deux domaines, deux
    // politiques, et rien pour dire laquelle s'applique. Choisir la première
    // reviendrait à laisser l'expéditeur choisir laquelle on vérifie.
    assert_eq!(
        domaine(" joe@example.com, marie@example.net"),
        Err(Error::MultipleAddresses)
    );
    assert_eq!(
        domaine(" Joe <joe@example.com>, Marie <marie@example.net>"),
        Err(Error::MultipleAddresses)
    );
    // Deux chevrons ouverts, même sans virgule.
    assert_eq!(
        domaine(" <a@example.com> <b@example.net>"),
        Err(Error::MultipleAddresses)
    );
}

#[test]
fn une_adresse_illisible_fait_refuser() {
    for mechant in [
        "",
        " ",
        " Joe SixPack",
        " joe@",
        " @example.com",
        " @example.com ",
        " (juste un commentaire) ",
        " <joe@example.com",
        " <>",
        " joe@example.com>",
    ] {
        assert!(
            domaine(mechant).is_err(),
            "« {mechant} » aurait dû être refusé"
        );
    }
    // `@example.com` seul : la partie locale manque. Rendre son domaine ferait
    // vérifier la politique d'un domaine que personne n'a écrit comme auteur.
    assert_eq!(domaine(" @example.com"), Err(Error::NoAddress));
}

#[test]
fn un_guillemet_ou_un_commentaire_jamais_fermes_font_refuser() {
    // Ce qui suit n'a plus de sens : mieux vaut le dire que deviner.
    assert_eq!(domaine(" \"Joe <joe@example.com>"), Err(Error::NoAddress));
    assert_eq!(domaine(" (Joe <joe@example.com>"), Err(Error::NoAddress));
}

#[test]
fn un_litteral_d_adresse_n_est_pas_un_domaine_pour_dmarc() {
    // `joe@[192.0.2.1]` ne désigne aucune zone : il n'y a pas de politique à
    // aller y chercher, et le rendre ferait interroger n'importe quoi.
    assert_eq!(domaine(" joe@[192.0.2.1]"), Ok("[192.0.2.1]"));
}

#[test]
fn un_domaine_avec_un_blanc_fait_refuser() {
    assert_eq!(domaine(" joe@exa mple.com"), Err(Error::NoAddress));
    assert_eq!(domaine(" <joe@exa mple.com>"), Err(Error::NoAddress));
}

#[test]
fn une_contre_oblique_protege_la_parenthese_qui_suit() {
    // RFC 5322 §3.2.1 : dans un commentaire, `\)` est une paire échappée — elle
    // ne ferme rien. Le manquer ferait sortir du commentaire trop tôt, et lire
    // comme une adresse ce qui n'en est pas.
    assert_eq!(
        domaine(" joe@example.com (une parenthese \\) fermee)"),
        Ok("example.com")
    );
    assert_eq!(
        domaine(" (un \\) commentaire) joe@example.com"),
        Ok("example.com")
    );
    assert_eq!(
        domaine(" (le \\) vrai) <joe@example.com>"),
        Ok("example.com")
    );
    // Et une contre-oblique qui protège la parenthèse FINALE laisse le
    // commentaire ouvert : ce qui suit n'a plus de sens.
    assert_eq!(
        domaine(" joe@example.com (ouvert \\)"),
        Err(Error::NoAddress)
    );
}

/// Les éléments d'une liste, sous une forme qu'un essai lit.
fn elements(valeur: &str) -> std::vec::Vec<std::string::String> {
    super::address_elements(valeur.as_bytes())
        .map(|element| std::string::String::from_utf8_lossy(element).into_owned())
        .collect()
}

/// L'adresse nue, sous une forme qu'un essai lit.
fn nue(valeur: &str) -> Option<std::string::String> {
    super::bare_address(valeur.as_bytes())
        .map(|adresse| std::string::String::from_utf8_lossy(adresse).into_owned())
}

/// **UNE VIRGULE N'EN EST UNE QU'AU PREMIER NIVEAU.**
///
/// Entre guillemets, dans un commentaire ou entre chevrons, elle appartient au
/// texte. Couper dessus ferait deux destinataires d'un seul, et le message
/// partirait à une adresse que personne n'a écrite.
#[test]
fn une_virgule_protegee_ne_coupe_pas() {
    assert_eq!(
        elements("\"Dupont, Jean\" <jean@example.test>, marie@example.test"),
        ["\"Dupont, Jean\" <jean@example.test>", "marie@example.test"]
    );
    assert_eq!(
        elements("jean@example.test (chez lui, le soir), marie@example.test"),
        [
            "jean@example.test (chez lui, le soir)",
            "marie@example.test"
        ]
    );
}

/// **UN GROUPE SE TRAVERSE** (§3.4 de RFC 5322).
///
/// Son nom n'est pas une adresse et ne doit pas passer pour un destinataire ; ses
/// membres, eux, en sont.
#[test]
fn un_groupe_rend_ses_membres_et_non_son_nom() {
    let vus = elements("amis: jean@example.test, marie@example.test;");
    assert_eq!(vus, ["amis", "jean@example.test", "marie@example.test"]);
    // Le nom du groupe ne porte pas d'arobase : c'est `bare_address` qui
    // l'écarte, et l'itérateur n'a pas à en décider.
    assert_eq!(nue("amis"), None);
}

/// **UN ÉLÉMENT VIDE N'EST PAS UN DESTINATAIRE.**
///
/// Une virgule de trop est une faute de frappe ordinaire, et rendre un élément
/// vide obligerait chaque appelant à s'en défendre.
#[test]
fn les_elements_vides_ne_se_rendent_pas() {
    assert_eq!(elements(""), std::vec::Vec::<std::string::String>::new());
    assert_eq!(
        elements(" , ,\t"),
        std::vec::Vec::<std::string::String>::new()
    );
    assert_eq!(
        elements("jean@example.test,, marie@example.test"),
        ["jean@example.test", "marie@example.test"]
    );
}

/// **UN PLI NE COUPE PAS UNE LISTE**, il la traverse.
///
/// §2.2.3 : une liste tient sur plusieurs lignes, et chaque morceau appartient à
/// la valeur. C'est `trim_ascii` qui retire ce que le pli laisse en bordure.
#[test]
fn un_pli_ne_coupe_pas_une_liste() {
    assert_eq!(
        elements("jean@example.test,\r\n marie@example.test"),
        ["jean@example.test", "marie@example.test"]
    );
}

/// **CE QU'ON REND NUE EST UNE ADRESSE, ET RIEN QUI NE FASSE QUE L'ENTOURER.**
///
/// `sole_address` sert d'abord à trouver un domaine : sans chevrons, elle rend la
/// valeur entière. C'est juste pour ce qu'elle sert, et faux pour désigner une
/// boîte ou pour afficher.
#[test]
fn une_adresse_nue_ne_porte_que_l_adresse() {
    assert_eq!(
        nue(" \"Jean Dupont\" <jean@example.test> "),
        Some(std::string::String::from("jean@example.test"))
    );
    assert_eq!(nue(" jean@example.test "), Some("jean@example.test".into()));
    for valeur in [
        "jean @ example.test",
        "jean@example.test (chez lui)",
        "pas-d-arobase",
        "   ",
        "",
        "jean@example.test, marie@example.test",
    ] {
        assert_eq!(nue(valeur), None, "« {valeur} »");
    }
}

// ── LES ADRESSES NOMMÉES ────────────────────────────────────────────────────

use super::{NamedAddress, named_addresses, write_addr_spec, write_display_name};

fn nommees(valeur: &str) -> std::vec::Vec<(std::string::String, std::string::String)> {
    named_addresses(valeur.as_bytes())
        .map(|NamedAddress { name, address }| {
            (
                std::string::String::from_utf8_lossy(name).into_owned(),
                std::string::String::from_utf8_lossy(address).into_owned(),
            )
        })
        .collect()
}

fn paire(nom: &str, adresse: &str) -> (std::string::String, std::string::String) {
    (nom.into(), adresse.into())
}

#[test]
fn chaque_adresse_rend_son_nom_et_son_adresse() {
    assert_eq!(
        nommees("\"Dupont, Jean\" <jean@example.test>, marie@example.test"),
        [
            paire("\"Dupont, Jean\" ", "jean@example.test"),
            paire("", "marie@example.test"),
        ]
    );
    // Un chevron que rien ne ferme garde tout ce qui suit.
    assert_eq!(
        nommees("Jean <jean@example.test"),
        [paire("Jean ", "jean@example.test")]
    );
    // Un chevron vide reste vide.
    assert_eq!(nommees("Jean <>"), [paire("Jean ", "")]);
    // Un chevron dans un commentaire n'en est pas un.
    assert_eq!(
        nommees("jean@example.test (<rien>)"),
        [paire("", "jean@example.test (<rien>)")]
    );
}

/// **LE NOM D'UN GROUPE N'EST L'ADRESSE DE PERSONNE.**
#[test]
fn les_groupes_se_traversent_sans_leur_nom() {
    assert_eq!(
        nommees("amis: jean@example.test, marie@example.test;, paul@example.test"),
        [
            paire("", "jean@example.test"),
            paire("", "marie@example.test"),
            paire("", "paul@example.test"),
        ]
    );
    assert!(nommees("undisclosed-recipients:;").is_empty());
    assert!(nommees(" , ,").is_empty());
}

fn nom(brut: &str) -> std::string::String {
    let mut travail = [0_u8; 256];
    let mut sortie = [0_u8; 512];
    let ecrits = write_display_name(brut.as_bytes(), &mut travail, &mut sortie).expect("tient");
    std::string::String::from_utf8(sortie[..ecrits].to_vec()).expect("UTF-8")
}

/// Ce qu'un nom VAUT : guillemets, échappements, commentaires et plis défaits,
/// mots encodés décodés.
#[test]
fn un_nom_d_affichage_se_rend_pour_ce_qu_il_vaut() {
    assert_eq!(nom("\"Dupont, Jean\" "), "Dupont, Jean");
    assert_eq!(nom("  Jean   Dupont  "), "Jean Dupont");
    assert_eq!(nom("Jean (le vrai) Dupont"), "Jean Dupont");
    assert_eq!(nom("\"Jean \\\"Jojo\\\" Dupont\""), "Jean \"Jojo\" Dupont");
    assert_eq!(nom("\"Jean\r\n Dupont\""), "Jean Dupont");
    assert_eq!(nom("\"Jean\tDupont\""), "Jean Dupont");
    assert_eq!(nom("Jean\r\n Dupont"), "Jean Dupont");
    assert_eq!(nom("=?utf-8?Q?Jos=C3=A9?= Dupont"), "José Dupont");
    // Entre guillemets aussi, bien que §5 de RFC 2047 l'interdise.
    assert_eq!(nom("\"=?utf-8?B?Sm9zw6k=?=\""), "José");
    // Une chaîne que rien ne ferme garde son dernier octet.
    assert_eq!(nom("\"Jean"), "Jean");
    assert_eq!(nom("\""), "");
    // Un échappement en toute fin vaut une barre.
    assert_eq!(nom("\"Jean\\"), "Jean\\");
    // Rien que des commentaires et du blanc : pas de nom.
    assert_eq!(nom(" (rien) "), "");
    assert_eq!(nom(""), "");
}

#[test]
fn un_nom_trop_long_pour_ses_tampons_le_dit() {
    let mut petit = [0_u8; 3];
    let mut sortie = [0_u8; 64];
    assert_eq!(
        write_display_name(b"Jean Dupont", &mut petit, &mut sortie),
        Err(Error::BufferTooSmall)
    );
    // Entre guillemets aussi.
    assert_eq!(
        write_display_name(b"\"Jean Dupont\"", &mut petit, &mut sortie),
        Err(Error::BufferTooSmall)
    );
    // Le blanc qu'on réinsère compte aussi.
    let mut juste = [0_u8; 4];
    assert_eq!(
        write_display_name(b"Jean D", &mut juste, &mut sortie),
        Err(Error::BufferTooSmall)
    );
    let mut travail = [0_u8; 64];
    assert_eq!(
        write_display_name(b"Jean Dupont", &mut travail, &mut petit),
        Err(Error::BufferTooSmall)
    );
}

fn adresse(brut: &str) -> std::string::String {
    let mut sortie = [0_u8; 256];
    let ecrits = write_addr_spec(brut.as_bytes(), &mut sortie).expect("tient");
    std::string::String::from_utf8(sortie[..ecrits].to_vec()).expect("UTF-8")
}

/// Ce qui ne fait qu'entourer l'adresse s'en va ; une chaîne citée reste.
#[test]
fn une_adresse_se_rend_sans_ce_qui_l_entoure() {
    assert_eq!(adresse("jean@example.test"), "jean@example.test");
    assert_eq!(
        adresse(" jean (le vrai) @ example.test "),
        "jean@example.test"
    );
    assert_eq!(adresse("jean@\r\n example.test"), "jean@example.test");
    assert_eq!(
        adresse("\"jean dupont\"@example.test"),
        "\"jean dupont\"@example.test"
    );
    assert_eq!(adresse(""), "");
    let mut petit = [0_u8; 3];
    assert_eq!(
        write_addr_spec(b"jean@x", &mut petit),
        Err(Error::BufferTooSmall)
    );
}
