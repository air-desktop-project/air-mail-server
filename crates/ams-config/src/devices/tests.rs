//! Ce que le magasin d'appareils accepte, et ce qu'il refuse au chargement.

use super::{Device, ID_OCTETS_MAX, NOM_OCTETS_MAX, decode_devices, encode_devices};
use crate::ams_devices_capnp::devices;
use crate::codec::Error;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use ams_auth::{CLE_OCTETS, Cle};

/// Une clef publique P-256 valide, figée en octets.
///
/// # POURQUOI DES OCTETS ET PAS UNE GÉNÉRATION
///
/// Deux raisons. D'abord **pas d'aléa dans un essai** : celui qui tire au sort
/// échoue un jour sur mille, et ce jour-là personne ne sait pourquoi. Ensuite,
/// cette caisse **range** des clefs ; elle n'a pas à savoir en fabriquer, et lui
/// donner de quoi signer pour ses essais lui ferait porter une dépendance qu'elle
/// n'utilise nulle part ailleurs.
///
/// Ce sont les coordonnées du point `7 · G` sur la courbe, en forme non
/// compressée (§2.3.3 de SEC 1) — la même clef d'épreuve que celle des essais
/// de `ams_auth::appareil`.
const CLE_VALIDE: [u8; CLE_OCTETS] = [
    0x04, 0x1e, 0x18, 0x53, 0x2f, 0xd4, 0x75, 0x4c, 0x02, 0xf3, 0x04, 0x1d, 0x9c, 0x75, 0xce, 0xb3,
    0x3b, 0x83, 0xff, 0xd8, 0x1a, 0xc7, 0xce, 0x4f, 0xe8, 0x82, 0xcc, 0xb1, 0xc9, 0x8b, 0xc5, 0x89,
    0x6e, 0xa4, 0x6c, 0x31, 0x1c, 0x4e, 0x2f, 0xf4, 0x0d, 0xd9, 0x6a, 0x36, 0x53, 0xe6, 0xe4, 0x54,
    0x45, 0xd3, 0x2d, 0xfe, 0x48, 0x6e, 0xce, 0xd7, 0x5c, 0x7a, 0x90, 0xc6, 0xa1, 0x88, 0x81, 0xc0,
    0xa3,
];

/// Une seconde, différente : de quoi vérifier qu'un magasin ne mélange pas deux
/// appareils.
const AUTRE_CLE: [u8; CLE_OCTETS] = [
    0x04, 0x71, 0x35, 0xfa, 0x4f, 0xd9, 0x3a, 0x09, 0xdc, 0xe9, 0x8b, 0xbf, 0x68, 0x1b, 0x4b, 0xfc,
    0xf5, 0x0e, 0x7c, 0x0d, 0x63, 0x54, 0xe6, 0x2a, 0xfb, 0x0b, 0xff, 0x2a, 0x34, 0x29, 0x61, 0x78,
    0x65, 0xed, 0x4c, 0x1f, 0x02, 0xdd, 0xb9, 0x02, 0x3e, 0xe5, 0x6a, 0x55, 0x7e, 0x51, 0x5d, 0x6a,
    0x9d, 0xc6, 0x6c, 0x11, 0xf2, 0x20, 0x96, 0x0d, 0xe5, 0x94, 0x33, 0x4d, 0xf5, 0x88, 0x77, 0x67,
    0x24,
];

/// Les deux clefs d'épreuve sont bien des points de la courbe.
///
/// **CET ESSAI GARDE LES AUTRES** : si ces octets cessaient d'être valides, tous
/// les essais qui s'appuient dessus échoueraient pour une raison qui n'est pas
/// la leur, et l'on chercherait le défaut au mauvais endroit.
#[test]
fn les_clefs_d_epreuve_sont_des_points() {
    assert!(Cle::lire(&CLE_VALIDE).is_ok());
    assert!(Cle::lire(&AUTRE_CLE).is_ok());
    assert_ne!(CLE_VALIDE, AUTRE_CLE);
}

fn appareil(login: &str, id: &str, clef: &[u8; CLE_OCTETS]) -> Device {
    Device {
        login: String::from(login),
        id: String::from(id),
        name: alloc::format!("appareil {id}"),
        public_key: Cle::lire(clef).expect("une clef d'épreuve valide"),
        enrolled: 1_790_000_000,
        last_seen: 1_790_003_600,
    }
}

/// **UN MAGASIN ÉCRIT SE RELIT À L'IDENTIQUE.**
///
/// Sans cela, une clef enrôlée un jour ne serait plus la même après un
/// aller-retour par le disque — et toutes ses signatures échoueraient sans que
/// rien ne dise pourquoi.
#[test]
fn un_magasin_ecrit_se_relit_a_l_identique() {
    let original = alloc::vec![
        appareil("jean", "a1", &CLE_VALIDE),
        appareil("paul", "b2", &AUTRE_CLE),
    ];
    let relu = decode_devices(&encode_devices(&original).expect("encodable")).expect("relisible");

    assert_eq!(relu.len(), 2);
    for (avant, apres) in original.iter().zip(relu.iter()) {
        assert_eq!(avant.login, apres.login);
        assert_eq!(avant.id, apres.id);
        assert_eq!(avant.name, apres.name);
        assert_eq!(avant.enrolled, apres.enrolled);
        assert_eq!(avant.last_seen, apres.last_seen);
        // **LA CLEF SURTOUT** : c'est elle qui ouvre les sessions.
        assert_eq!(avant.public_key.octets(), apres.public_key.octets());
    }
    // Et les deux appareils ne se sont pas confondus en chemin.
    assert_eq!(relu[0].public_key.octets(), CLE_VALIDE);
    assert_eq!(relu[1].public_key.octets(), AUTRE_CLE);
}

/// Un magasin vide est licite : c'est l'état d'un serveur où personne n'a encore
/// enrôlé, et refuser de le lire empêcherait le premier enrôlement.
#[test]
fn un_magasin_vide_se_relit() {
    let relu = decode_devices(&encode_devices(&[]).expect("encodable")).expect("relisible");
    assert!(relu.is_empty());
}

/// **UN APPAREIL QUI N'A JAMAIS OUVERT DE SESSION PORTE ZÉRO**, et cela traverse
/// l'encodage : c'est ce zéro qui dit à l'utilisateur lequel révoquer sans
/// risque.
#[test]
fn un_appareil_jamais_vu_garde_son_zero() {
    let mut neuf = appareil("jean", "a1", &CLE_VALIDE);
    neuf.last_seen = 0;
    let relu = decode_devices(&encode_devices(&[neuf]).expect("encodable")).expect("relisible");
    assert_eq!(relu[0].last_seen, 0);
}

/// Écrit un magasin **brut**, sans passer par [`encode_devices`] — le seul moyen
/// de fabriquer ce que l'encodeur refuserait d'écrire, et donc d'éprouver ce que
/// le décodeur refuse.
fn brut(cas: &[(&str, &str, &str, &[u8])]) -> Vec<u8> {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<devices::Builder<'_>>();
        let mut liste = ecrit.init_devices(u32::try_from(cas.len()).unwrap_or(u32::MAX));
        for (rang, (login, id, nom, clef)) in cas.iter().enumerate() {
            let mut case = liste
                .reborrow()
                .get(u32::try_from(rang).unwrap_or(u32::MAX));
            case.set_login(login);
            case.set_id(id);
            case.set_name(nom);
            case.set_public_key(clef);
            case.set_enrolled(1);
            case.set_last_seen(0);
        }
    }
    capnp::serialize::write_message_to_words(&message)
}

/// **DEUX APPAREILS NE PARTAGENT PAS UN IDENTIFIANT.**
///
/// Révoquer l'un reviendrait à ne pas savoir lequel des deux on vient de
/// retirer — et le second l'emporterait ou pas, en silence.
#[test]
fn deux_appareils_de_meme_identifiant_sont_refuses() {
    let octets = brut(&[
        ("jean", "a1", "premier", &CLE_VALIDE),
        ("paul", "a1", "second", &AUTRE_CLE),
    ]);
    assert_eq!(
        decode_devices(&octets).err(),
        Some(Error::DuplicateDevice("a1".to_string()))
    );
}

/// Deux appareils **de comptes différents** avec des identifiants différents,
/// eux, passent : c'est le cas courant.
#[test]
fn deux_appareils_distincts_passent() {
    let octets = brut(&[
        ("jean", "a1", "premier", &CLE_VALIDE),
        ("paul", "b2", "second", &AUTRE_CLE),
    ]);
    assert_eq!(decode_devices(&octets).expect("licite").len(), 2);
}

/// **UNE CLEF QUI N'EST PAS UN POINT N'EST PAS UNE CLEF.**
///
/// L'accepter ouvrirait les attaques par courbe invalide. Le refus nomme
/// l'appareil, parce qu'un magasin de trente lignes sans nom oblige à tout
/// relire.
#[test]
fn une_clef_qui_n_est_pas_un_point_est_refusee() {
    // La bonne taille, le bon préfixe, des coordonnées qui ne sont sur rien.
    let mut fausse = [0_u8; CLE_OCTETS];
    fausse[0] = 0x04;
    fausse[1] = 1;
    assert_eq!(
        decode_devices(&brut(&[("jean", "a1", "faux", &fausse)])).err(),
        Some(Error::BadDeviceKey("a1".to_string()))
    );
}

/// **ET UNE CLEF DE MAUVAISE TAILLE NON PLUS.**
///
/// Zéro octet, c'est le champ absent d'un fichier écrit à la main ; trente-deux,
/// c'est une clef Ed25519 qu'on aurait rangée là ; soixante-quatre, la forme
/// sans préfixe ; soixante-six, un octet de trop.
#[test]
fn une_clef_de_mauvaise_taille_est_refusee() {
    for taille in [0_usize, 32, 33, 64, 66] {
        let remplissage = alloc::vec![4_u8; taille];
        assert_eq!(
            decode_devices(&brut(&[("jean", "a1", "court", &remplissage)])).err(),
            Some(Error::BadDeviceKey("a1".to_string())),
            "taille {taille}"
        );
    }
}

/// **UN IDENTIFIANT VIDE NE DÉSIGNE RIEN**, et le laisser passer donnerait une
/// URL de révocation qui ne révoque rien.
#[test]
fn un_identifiant_vide_est_refuse() {
    assert_eq!(
        decode_devices(&brut(&[("jean", "", "sans nom", &CLE_VALIDE)])).err(),
        Some(Error::Empty("device id"))
    );
}

/// **LES BORNES TIENNENT, ET À L'OCTET PRÈS.**
///
/// Un identifiant plus long qu'un segment d'URL serait un appareil
/// inatteignable ; un nom sans borne serait un roman dans un magasin.
#[test]
fn les_bornes_de_longueur_tiennent() {
    let id_long: String = core::iter::repeat_n('x', ID_OCTETS_MAX + 1).collect();
    assert_eq!(
        decode_devices(&brut(&[("jean", &id_long, "nom", &CLE_VALIDE)])).err(),
        Some(Error::TooLong("device id"))
    );

    let nom_long: String = core::iter::repeat_n('y', NOM_OCTETS_MAX + 1).collect();
    assert_eq!(
        decode_devices(&brut(&[("jean", "a1", &nom_long, &CLE_VALIDE)])).err(),
        Some(Error::TooLong("device name"))
    );

    // **ET À LA BORNE EXACTE, CELA PASSE** : une borne qu'on ne peut pas
    // atteindre est une borne mal écrite.
    let id_juste: String = core::iter::repeat_n('x', ID_OCTETS_MAX).collect();
    let nom_juste: String = core::iter::repeat_n('y', NOM_OCTETS_MAX).collect();
    let relu = decode_devices(&brut(&[("jean", &id_juste, &nom_juste, &CLE_VALIDE)]))
        .expect("la borne exacte est licite");
    assert_eq!(relu[0].id.len(), ID_OCTETS_MAX);
    assert_eq!(relu[0].name.len(), NOM_OCTETS_MAX);
}

/// **UN NOM VIDE EST LICITE**, lui : un appareil qu'on n'a pas nommé reste un
/// appareil, et refuser l'enrôlement pour cela serait une pédanterie.
#[test]
fn un_nom_vide_est_licite() {
    let relu = decode_devices(&brut(&[("jean", "a1", "", &CLE_VALIDE)])).expect("licite");
    assert_eq!(relu.len(), 1);
    assert!(relu[0].name.is_empty());
}

/// **UN COMPTE QUE `check_login` REFUSE EST REFUSÉ ICI AUSSI.**
///
/// Le même contrôle que pour le magasin de comptes, et pour la même raison : ce
/// nom devient un nom de répertoire, et c'est une frontière de sécurité. Un
/// magasin d'appareils qui serait plus permissif que celui des comptes ouvrirait
/// par la porte de derrière ce que l'autre ferme.
#[test]
fn un_compte_irrecevable_est_refuse() {
    for mauvais in ["", "../evasion", "a/b", "jean\0"] {
        assert!(
            matches!(
                decode_devices(&brut(&[(mauvais, "a1", "nom", &CLE_VALIDE)])),
                Err(Error::WeakAccount { .. })
            ),
            "`{mauvais}` aurait dû être refusé"
        );
    }
}

/// **DES OCTETS QUI NE SONT PAS UN MESSAGE NE SE LISENT PAS.**
#[test]
fn des_octets_quelconques_sont_refuses() {
    assert!(decode_devices(b"ceci n'est pas un message Cap'n Proto").is_err());
    assert!(decode_devices(&[]).is_err());
}

/// **UN TEXTE QUI N'EST PAS DE L'UTF-8 FAIT REFUSER LE FICHIER**, plutôt que de
/// se faire remplacer en silence par des losanges.
#[test]
fn un_texte_hors_utf8_fait_refuser() {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<devices::Builder<'_>>();
        let mut liste = ecrit.init_devices(1);
        let mut case = liste.reborrow().get(0);
        case.set_login(capnp::text::Reader(b"je\xffan"));
        case.set_id("a1");
        case.set_name("nom");
        case.set_public_key(&CLE_VALIDE);
    }
    let octets = capnp::serialize::write_message_to_words(&message);
    assert_eq!(decode_devices(&octets).err(), Some(Error::NotUtf8));
}

/// **LES TROIS REFUS PROPRES AUX APPAREILS SE DISENT EN FRANÇAIS**, et nomment
/// ce qui a cédé : un message qui dit « trop long » sans dire quel champ oblige
/// à relire le fichier entier.
#[test]
fn les_refus_se_lisent() {
    use alloc::string::ToString as _;

    let double = Error::DuplicateDevice("a1".to_string()).to_string();
    assert!(double.contains("a1"), "{double}");

    let clef = Error::BadDeviceKey("a1".to_string()).to_string();
    assert!(clef.contains("a1"), "{clef}");

    let borne = Error::TooLong("device id").to_string();
    assert!(borne.contains("device id"), "{borne}");
}

/// La trace d'un appareil montre ce qu'il faut pour le retrouver, et **pas la
/// clef en entier** : soixante-cinq octets dans un journal n'apprennent rien et
/// encombrent tout.
#[test]
fn un_appareil_se_debogue_sans_deballer_sa_clef() {
    let rendu = alloc::format!("{:?}", appareil("jean", "a1", &CLE_VALIDE));
    assert!(rendu.contains("jean"), "{rendu}");
    assert!(rendu.contains("a1"), "{rendu}");
    assert!(rendu.contains("Cle(<P-256>)"), "{rendu}");
}

/// **UN APPAREIL COPIÉ EST LE MÊME APPAREIL, CLEF COMPRISE.**
///
/// Le magasin du serveur en fait des copies à chaque lecture : il rend un
/// instantané plutôt qu'un emprunt, pour ne pas tenir son verrou pendant qu'on
/// s'en sert. Une copie dont la clef différerait ferait échouer les signatures
/// une lecture sur deux.
#[test]
fn un_appareil_copie_est_le_meme() {
    let original = appareil("jean", "a1", &CLE_VALIDE);
    let copie = original.clone();
    assert_eq!(copie.login, original.login);
    assert_eq!(copie.id, original.id);
    assert_eq!(copie.name, original.name);
    assert_eq!(copie.enrolled, original.enrolled);
    assert_eq!(copie.last_seen, original.last_seen);
    assert_eq!(copie.public_key.octets(), original.public_key.octets());
}

/// **UN FICHIER CORROMPU NE FAIT JAMAIS PANIQUER LE SERVEUR.**
///
/// # CE BALAYAGE N'EST PAS QU'UNE ÉPREUVE DE ROBUSTESSE
///
/// Chaque octet du magasin, retourné de trois façons. Ce que cela traverse, ce
/// sont les bras d'erreur du lecteur Cap'n Proto — `get_login`, `get_id`,
/// `get_name`, `get_public_key` —, qu'aucun magasin bien formé n'emprunte et
/// qu'aucun essai ciblé ne saurait atteindre autrement : ils ne se déclenchent
/// que sur un pointeur que le message ne contient pas.
///
/// **LES DEUX COMPTES IMPORTENT.** Zéro refus dirait que la corruption passe
/// inaperçue ; zéro acceptation dirait que le balayage n'atteint jamais le
/// chemin nominal, et qu'il n'éprouve donc pas ce qu'il prétend.
#[test]
fn un_fichier_corrompu_ne_fait_jamais_paniquer_le_serveur() {
    let sain = encode_devices(&[appareil("jean", "a1", &CLE_VALIDE)]).expect("encodable");
    let mut refuses = 0_u32;
    let mut acceptes = 0_u32;
    for position in 0..sain.len() {
        for masque in [0xFF_u8, 0x01, 0x80] {
            let mut corrompu = sain.clone();
            corrompu[position] ^= masque;
            match decode_devices(&corrompu) {
                Ok(_) => acceptes = acceptes.saturating_add(1),
                Err(_) => refuses = refuses.saturating_add(1),
            }
        }
    }
    assert!(refuses > 0, "aucune corruption n'a été détectée");
    assert!(
        acceptes > 0,
        "toutes les corruptions ont été refusées : le balayage ne traverse pas le chemin nominal"
    );
}
