// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que les attributs d'usage doivent tenir.

use super::SpecialUse;
use crate::Error;

/// Rend les usages écrits, pour comparer à une chaîne.
fn ecrit(usages: SpecialUse) -> std::string::String {
    let mut place = [0_u8; 64];
    let rendu = usages.write(&mut place).expect("écrivable");
    std::string::String::from_utf8(rendu.to_vec()).expect("de l'ASCII")
}

#[test]
fn les_cinq_se_lisent_et_se_reecrivent() {
    for (nom, attendu) in [
        (&b"\\Archive"[..], SpecialUse::ARCHIVE),
        (b"\\Drafts", SpecialUse::DRAFTS),
        (b"\\Junk", SpecialUse::JUNK),
        (b"\\Sent", SpecialUse::SENT),
        (b"\\Trash", SpecialUse::TRASH),
    ] {
        let lu = SpecialUse::parse_one(nom).expect("servi");
        assert_eq!(lu, attendu, "{nom:?}");
        assert_eq!(
            ecrit(lu),
            std::string::String::from_utf8_lossy(nom),
            "l'écriture doit redonner le nom lu"
        );
    }
}

/// **LA CASSE NE DISTINGUE PAS UN ATTRIBUT** : §2 les écrit avec une majuscule,
/// et un client qui écrit `\drafts` demande la même chose.
#[test]
fn la_casse_ne_distingue_pas() {
    assert_eq!(SpecialUse::parse_one(b"\\drafts"), Some(SpecialUse::DRAFTS));
    assert_eq!(SpecialUse::parse_one(b"\\TRASH"), Some(SpecialUse::TRASH));
}

/// **`\All` ET `\Flagged` SE REFUSENT COMME UN NOM INCONNU**, et c'est le cœur
/// de ce module : ils désignent une boîte VIRTUELLE, que ce serveur n'a pas.
#[test]
fn les_boites_virtuelles_se_refusent() {
    for virtuel in [&b"\\All"[..], b"\\Flagged", b"\\all", b"\\flagged"] {
        assert_eq!(
            SpecialUse::parse_one(virtuel),
            None,
            "{virtuel:?} promettrait une boîte qui n'existe pas"
        );
    }
    // **ET LE REFUS NE SE DIT PAS COMME UNE FAUTE DE GRAMMAIRE.** `\All` est un
    // `use-attr` bien écrit de §2 : le client ne s'est pas trompé, et §3 veut
    // donc `NO [USEATTR]` plutôt qu'un `BAD` qui l'enverrait relire sa syntaxe.
    assert_eq!(SpecialUse::parse_list(b"\\All"), Err(Error::UnsupportedUse));
    assert_eq!(
        SpecialUse::parse_list(b"\\Flagged"),
        Err(Error::UnsupportedUse)
    );
    // Ce qui n'est PAS un `use-attr`, en revanche, est bien une faute.
    for faute in [&b"Drafts"[..], b"\\", b"n'importe quoi"] {
        assert_eq!(
            SpecialUse::parse_list(faute),
            Err(Error::MalformedList),
            "{faute:?}"
        );
    }
}

#[test]
fn un_nom_inconnu_se_refuse() {
    for inconnu in [
        &b"\\Inconnu"[..],
        b"Drafts",  // sans la barre oblique inverse
        b"\\Draft", // le drapeau de message, qui n'est pas l'usage
        b"",
    ] {
        assert_eq!(SpecialUse::parse_one(inconnu), None, "{inconnu:?}");
    }
}

/// **UNE LISTE VIDE EST UNE FAUTE** : `USE ()` ne demande rien tout en ayant
/// l'air de demander.
#[test]
fn une_liste_vide_se_refuse() {
    for vide in [&b""[..], b" ", b"   "] {
        assert_eq!(SpecialUse::parse_list(vide), Err(Error::MalformedList));
    }
}

#[test]
fn une_liste_en_porte_plusieurs() {
    let deux = SpecialUse::parse_list(b"\\Drafts \\Sent").expect("servie");
    assert!(deux.contains(SpecialUse::DRAFTS));
    assert!(deux.contains(SpecialUse::SENT));
    assert!(!deux.contains(SpecialUse::TRASH));
    // L'ORDRE DE LA RÉPONSE NE SUIT PAS CELUI DE LA DEMANDE : il est stable.
    assert_eq!(ecrit(deux), "\\Drafts \\Sent");
    let autre = SpecialUse::parse_list(b"\\Sent \\Drafts").expect("servie");
    assert_eq!(ecrit(autre), ecrit(deux));
}

/// Un nom refusé au milieu refuse la liste entière — et non les précédents.
#[test]
fn un_nom_refuse_refuse_la_liste() {
    assert_eq!(
        SpecialUse::parse_list(b"\\Drafts \\All \\Sent"),
        Err(Error::UnsupportedUse)
    );
    assert_eq!(
        SpecialUse::parse_list(b"\\Drafts pasunattribut \\Sent"),
        Err(Error::MalformedList)
    );
}

#[test]
fn aucun_usage_ne_s_ecrit_pas() {
    assert!(!SpecialUse::NONE.any());
    assert_eq!(ecrit(SpecialUse::NONE), "");
    assert!(SpecialUse::DRAFTS.any());
}

/// **`contains` DEMANDE TOUT CE QU'ON LUI DONNE**, et non un seul bit.
#[test]
fn contains_demande_tout() {
    let deux = SpecialUse::DRAFTS.with(SpecialUse::SENT);
    assert!(deux.contains(SpecialUse::DRAFTS));
    assert!(deux.contains(deux));
    assert!(!SpecialUse::DRAFTS.contains(deux));
    // `NONE` est contenu partout : c'est ce qui rend `contains` transitif.
    assert!(SpecialUse::NONE.contains(SpecialUse::NONE));
    assert!(deux.contains(SpecialUse::NONE));
}

/// Un tampon trop court se refuse plutôt que d'écrire à moitié.
#[test]
fn un_tampon_trop_court_se_refuse() {
    let deux = SpecialUse::DRAFTS.with(SpecialUse::SENT);
    for taille in 0..ecrit(deux).len() {
        let mut place = std::vec![0_u8; taille];
        assert!(
            deux.write(&mut place).is_err(),
            "{taille} octets ont suffi à écrire {}",
            ecrit(deux)
        );
    }
}

// ── LE PARAMÈTRE DE `CREATE` (§3) ───────────────────────────────────────────

use super::parse_create_params;

#[test]
fn un_create_sans_parametre_ne_demande_aucun_usage() {
    for rien in [&b""[..], b"  ", b"\t"] {
        assert_eq!(parse_create_params(rien), Ok(SpecialUse::NONE), "{rien:?}");
    }
}

#[test]
fn un_create_avec_usage_le_rend() {
    assert_eq!(
        parse_create_params(b"(USE (\\Drafts))"),
        Ok(SpecialUse::DRAFTS)
    );
    // Les espaces de part et d'autre ne changent rien, et `USE` est insensible
    // à la casse comme tout mot-clef de §9.
    assert_eq!(
        parse_create_params(b"  ( use ( \\Sent \\Archive ) )  "),
        Ok(SpecialUse::SENT.with(SpecialUse::ARCHIVE))
    );
}

/// **CE QU'ON NE COMPREND PAS SE REFUSE**, plutôt que de créer une boîte en
/// ignorant ce que le client a demandé d'elle.
#[test]
fn un_parametre_mal_forme_se_refuse() {
    for mauvais in [
        &b"(USE (\\Drafts)"[..],     // parenthèse non refermée
        b"USE (\\Drafts)",           // sans la parenthèse du paramètre
        b"(USAGE (\\Drafts))",       // un item qu'on ne sert pas
        b"(USE \\Drafts)",           // sans la liste
        b"(USE ())",                 // une liste vide
        b"(USE (Drafts))",           // pas un `use-attr`
        b"(USE (\\Drafts)) (X (1))", // un second item
        b"()",                       // rien du tout, mais des parenthèses
    ] {
        assert_eq!(
            parse_create_params(mauvais),
            Err(Error::MalformedList),
            "{mauvais:?}"
        );
    }
}

/// **UN ATTRIBUT BIEN ÉCRIT QU'ON NE SERT PAS N'EST PAS UNE FAUTE DE FORME**,
/// et le `CREATE` doit pouvoir le dire autrement (§3 : `NO [USEATTR]`).
#[test]
fn un_attribut_non_servi_se_distingue_d_une_faute() {
    for connu in [
        &b"(USE (\\All))"[..],
        b"(USE (\\Flagged))",
        b"(USE (\\Drafts \\All))",
    ] {
        assert_eq!(
            parse_create_params(connu),
            Err(Error::UnsupportedUse),
            "{connu:?}"
        );
    }
}
