//! Fuzz : l'encodage d'une réponse SMTP — **un vrai aller-retour**.
//!
//! Une réponse contient souvent ce que le client vient d'envoyer : « 550 5.1.1
//! `<x@y.z>` : destinataire inconnu ». Un CR ou un LF qui y passerait laisserait
//! le client écrire une ligne de réponse ENTIÈRE de son choix, et donc mentir à
//! ce qui lit la connexion derrière lui — un relais, un client, un journal.
//!
//! Cette cible ne se contente donc pas de vérifier que l'encodeur ne panique pas :
//! elle **ré-analyse sa sortie** et exige d'y retrouver, à l'octet près, ce qui y
//! était entré. Un encodeur qui perdrait, tronquerait ou fusionnerait une ligne
//! échouerait ici, et c'est la seule propriété qui les attrape toutes.
//!
//! Le texte des lignes est tiré **arbitrairement**, CR et LF compris : c'est
//! précisément l'entrée hostile qu'on veut voir refusée.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use ams_proto_smtp::{Code, Limits, encode, encoded_len};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Une entrée : un code, des lignes, un tampon, et des bornes.
#[derive(Debug, Arbitrary)]
struct Entree {
    code: u16,
    lignes: Vec<Vec<u8>>,
    taille_tampon: u16,
    max_reply_octets: usize,
}

fuzz_target!(|entree: Entree| {
    let Some(code) = Code::new(entree.code) else {
        return;
    };
    let limits = Limits {
        max_reply_octets: entree.max_reply_octets,
        ..Limits::DEFAULT
    };
    let lignes: Vec<&[u8]> = entree.lignes.iter().map(Vec::as_slice).collect();
    let mut tampon = vec![0_u8; usize::from(entree.taille_tampon)];

    let Ok(ecrit) = encode(&mut tampon, code, &lignes, &limits) else {
        return;
    };

    // 1. LA TAILLE ANNONCÉE EST CELLE QUI EST ÉCRITE.
    //
    // `encoded_len` est le contrat sur lequel l'écriture se dispense de toute
    // vérification : s'il ment, l'écriture indexe hors du tampon.
    let annonce = encoded_len(&lignes, &limits).expect("mesurable puisque encodé");
    assert_eq!(ecrit.len(), annonce, "taille annoncée ≠ taille écrite");

    // 2. LA SORTIE SE TERMINE PAR CRLF.
    assert!(ecrit.ends_with(b"\r\n"), "réponse sans CRLF final");

    // 3. ALLER-RETOUR : ré-analyser la sortie rend EXACTEMENT l'entrée.
    let corps = ecrit.strip_suffix(b"\r\n").expect("CRLF final vérifié");
    let relues: Vec<&[u8]> = corps.split(|&b| b == b'\n').collect();
    assert_eq!(
        relues.len(),
        lignes.len(),
        "le découpage en lignes ne se retrouve pas : {ecrit:?}"
    );

    let chiffres = format!("{:03}", code.value());
    for (rang, relue) in relues.iter().enumerate() {
        // Le découpage sur `\n` laisse le `\r` en queue de chaque ligne SAUF la
        // dernière, dont le CRLF final a été retiré plus haut. Un dépouillage
        // inconditionnel traite les deux cas.
        let relue = relue.strip_suffix(b"\r").unwrap_or(relue);

        let (code_lu, reste) = relue.split_at(3.min(relue.len()));
        assert_eq!(
            code_lu,
            chiffres.as_bytes(),
            "code absent de la ligne {rang}"
        );

        let (separateur, texte) = reste.split_at(1.min(reste.len()));
        // 4. LE SÉPARATEUR DIT SI LA RÉPONSE CONTINUE.
        //
        // Un tiret sur la dernière ligne ferait attendre le pair indéfiniment ;
        // une espace sur une ligne intermédiaire lui ferait croire la réponse
        // finie, et lire la suivante comme une autre réponse.
        let attendu: &[u8] = if rang.saturating_add(1) == relues.len() {
            b" "
        } else {
            b"-"
        };
        assert_eq!(separateur, attendu, "séparateur faux à la ligne {rang}");

        // 5. LE TEXTE EST CELUI QUI EST ENTRÉ, À L'OCTET PRÈS.
        assert_eq!(texte, lignes[rang], "texte altéré à la ligne {rang}");

        // 6. AUCUN CR NI LF N'A SURVÉCU DANS UN TEXTE.
        assert!(
            !texte.contains(&b'\r') && !texte.contains(&b'\n'),
            "injection de réponse : {texte:?}"
        );

        // 7. LA LIGNE RESPECTE SA BORNE, CRLF COMPRIS.
        assert!(
            relue.len().saturating_add(2) <= limits.max_reply_octets,
            "ligne {rang} hors borne"
        );
    }
});
