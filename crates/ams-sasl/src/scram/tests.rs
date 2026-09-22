// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce banc éprouve SCRAM **contre la RFC**, et non contre lui-même.
//!
//! §3 de RFC 7677 donne un échange complet avec ses nonces fixés : mot de
//! passe, sel, itérations, et les quatre messages en clair. Tout y est
//! vérifiable octet par octet — c'est ce que la première moitié fait. La
//! seconde éprouve les refus, qui n'ont pas de vecteur parce qu'un message mal
//! formé n'en mérite pas.

use super::{
    CLE_OCTETS, Error, Gs2, ITERATIONS_MIN, MESSAGE_MAX, client_key, client_key_depuis_preuve,
    client_proof, derive_salted_password, desechapper, parse_client_final, parse_client_first,
    parse_iterations, server_key, server_signature, stored_key,
};
use crate::egales;

// ── LE VECTEUR DE RFC 7677 §3 ───────────────────────────────────────────────

/// Le mot de passe de l'exemple.
const MOT_DE_PASSE: &[u8] = b"pencil";
/// Le sel, tel que le `s=` du `server-first` le porte.
const SEL_B64: &[u8] = b"W22ZaJ0SNY7soEsUEjb6gQ==";
const ITERATIONS: u32 = 4_096;

/// **LES VALEURS DE LA RFC SE DÉCODENT, ELLES NE SE RETRANSCRIVENT PAS.**
///
/// La première version de ce banc portait le sel en octets, recopiés à la
/// main — avec un `0x2d` là où il fallait `0x6d`. L'essai a échoué, ce qui est
/// la bonne nouvelle ; mais il portait aussi une `SaltedPassword` « de la
/// RFC » que la RFC n'imprime pas, et celle-là aurait pu passer pour une
/// vérité. Tout ce qui suit vient donc du TEXTE de §3, décodé par notre propre
/// base64 — lui-même éprouvé sur les vecteurs de RFC 4648.
fn depuis_b64<const N: usize>(encode: &[u8]) -> [u8; N] {
    let mut octets = [0_u8; N];
    let ecrits = crate::decode_base64(encode, &mut octets).expect("base64 de la RFC");
    assert_eq!(ecrits, N, "la valeur de la RFC ne fait pas {N} octets");
    octets
}

const CLIENT_FIRST: &[u8] = b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
const SERVER_FIRST: &[u8] =
    b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const CLIENT_FINAL: &[u8] = b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
/// Le `server-final` de la RFC, en entier.
const SERVER_FINAL: &[u8] = b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

/// Le `AuthMessage` de l'exemple : les trois parts, séparées par des virgules.
fn auth_message(tampon: &mut [u8]) -> usize {
    let mut liaison = [0_u8; MESSAGE_MAX];
    let premier = parse_client_first(CLIENT_FIRST).expect("client-first du vecteur");
    let final_ = parse_client_final(CLIENT_FINAL, &mut liaison).expect("client-final du vecteur");
    let mut ecrits = 0;
    for part in [premier.bare, b",", SERVER_FIRST, b",", final_.sans_preuve] {
        for octet in part {
            *tampon.get_mut(ecrits).expect("tampon") = *octet;
            ecrits = ecrits.saturating_add(1);
        }
    }
    ecrits
}

#[test]
fn le_vecteur_de_la_rfc_7677_se_rejoue_en_entier() {
    // 1. `Hi(mot de passe, sel, 4096)` — c'est le calcul que le CLIENT fait.
    //    La RFC n'imprime pas `SaltedPassword` : ce qu'on vérifie, ce sont les
    //    deux valeurs qu'elle imprime, `p=` et `v=`. Si `Hi()` se trompe, elles
    //    ne tombent pas — c'est une preuve de bout en bout, et non d'étape.
    let sel: [u8; 16] = depuis_b64(SEL_B64);
    let salted = derive_salted_password(MOT_DE_PASSE, &sel, ITERATIONS);

    // 2. Les trois clés.
    let ck = client_key(&salted);
    let sk = server_key(&salted);
    let stored = stored_key(&ck);

    // 3. Le `AuthMessage`, reconstruit depuis les messages eux-mêmes.
    let mut tampon = [0_u8; MESSAGE_MAX];
    let longueur = auth_message(&mut tampon);
    let message = tampon.get(..longueur).expect("longueur");

    // 4. La preuve que le CLIENT calcule est celle que le `p=` de la RFC porte,
    //    et que notre analyse en a tirée.
    let preuve = client_proof(&ck, &stored, message);
    let mut liaison = [0_u8; MESSAGE_MAX];
    let lu = parse_client_final(CLIENT_FINAL, &mut liaison).expect("client-final");
    assert_eq!(preuve, lu.proof, "la preuve du vecteur n'est pas la nôtre");
    assert_eq!(
        lu.proof,
        depuis_b64::<CLE_OCTETS>(b"dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="),
        "le `p=` analysé n'est pas celui du texte de la RFC"
    );

    // 5. Et le SERVEUR retrouve `ClientKey` en défaisant le ou-exclusif.
    let retrouvee = client_key_depuis_preuve(&stored, message, &lu.proof);
    assert!(
        egales(&stored_key(&retrouvee), &stored),
        "le serveur n'a pas reconnu la preuve du vecteur"
    );

    // 6. La signature finale est celle que le `v=` de la RFC porte.
    let attendue: [u8; CLE_OCTETS] = depuis_b64(SERVER_FINAL.get(2..).expect("le `v=` de la RFC"));
    assert_eq!(
        server_signature(&sk, message),
        attendue,
        "le `v=` final n'est pas celui du vecteur"
    );
}

#[test]
fn une_preuve_fausse_ne_reconstitue_pas_la_cle_stockee() {
    let sel: [u8; 16] = depuis_b64(SEL_B64);
    let salted = derive_salted_password(MOT_DE_PASSE, &sel, ITERATIONS);
    let stored = stored_key(&client_key(&salted));
    let mut tampon = [0_u8; MESSAGE_MAX];
    let longueur = auth_message(&mut tampon);
    let message = tampon.get(..longueur).expect("longueur");
    let mut liaison = [0_u8; MESSAGE_MAX];
    let lu = parse_client_final(CLIENT_FINAL, &mut liaison).expect("client-final");

    // Un seul bit retourné dans la preuve, et rien ne doit plus correspondre.
    let mut fausse = lu.proof;
    *fausse.first_mut().expect("preuve") ^= 1;
    let retrouvee = client_key_depuis_preuve(&stored, message, &fausse);
    assert!(
        !egales(&stored_key(&retrouvee), &stored),
        "une preuve fausse a été acceptée"
    );

    // Et le même `AuthMessage` altéré d'un octet ne passe pas davantage.
    let mut autre = [0_u8; MESSAGE_MAX];
    autre
        .get_mut(..longueur)
        .expect("tampon")
        .copy_from_slice(message);
    *autre.first_mut().expect("message") ^= 1;
    let retrouvee = client_key_depuis_preuve(&stored, autre.get(..longueur).expect("l"), &lu.proof);
    assert!(
        !egales(&stored_key(&retrouvee), &stored),
        "un AuthMessage altéré a été accepté"
    );
}

#[test]
fn hi_compte_u1_dans_le_total() {
    // §5.2 de RFC 8018 : `i=1` rend U1 seul, c'est-à-dire un simple HMAC.
    assert_eq!(
        derive_salted_password(b"x", b"sel", 1),
        crate::hmac_sha256(b"x", b"sel\x00\x00\x00\x01"),
        "Hi(…, 1) doit être U1"
    );
    // Et deux itérations diffèrent d'une seule.
    assert_ne!(
        derive_salted_password(b"x", b"sel", 1),
        derive_salted_password(b"x", b"sel", 2)
    );
}

// ── L'ANALYSE : CE QUI PASSE ────────────────────────────────────────────────

#[test]
fn les_trois_entetes_gs2_se_lisent() {
    let cas = [
        (&b"n,,n=jean,r=abc"[..], Gs2::SansLiaison, &b"n,,"[..]),
        (b"y,,n=jean,r=abc", Gs2::LiaisonRefusee, b"y,,"),
        (
            b"p=tls-exporter,,n=jean,r=abc",
            Gs2::Liee,
            b"p=tls-exporter,,",
        ),
    ];
    for (message, attendu, brut) in cas {
        let lu = parse_client_first(message).expect("client-first");
        assert_eq!(lu.gs2, attendu);
        assert_eq!(lu.gs2_brut, brut);
        assert_eq!(lu.username, b"jean");
        assert_eq!(lu.nonce, b"abc");
        assert_eq!(lu.bare, b"n=jean,r=abc");
    }
}

#[test]
fn un_attribut_d_extension_apres_le_nonce_est_ignore() {
    // §5 : « les attributs inconnus doivent être ignorés ».
    let lu = parse_client_first(b"n,,n=jean,r=abc,x=quelque-chose").expect("client-first");
    assert_eq!(lu.nonce, b"abc", "le nonce s'arrête à la virgule");
}

#[test]
fn le_nom_echappe_se_lit_et_se_desechappe() {
    let lu = parse_client_first(b"n,,n=jean=2Cpaul=3Dx,r=abc").expect("client-first");
    assert_eq!(lu.username, b"jean=2Cpaul=3Dx", "le nom reste échappé");
    let mut clair = [0_u8; 32];
    let ecrits = desechapper(lu.username, &mut clair).expect("déséchappement");
    assert_eq!(clair.get(..ecrits), Some(&b"jean,paul=x"[..]));
}

#[test]
fn le_client_final_se_lit_avec_sa_liaison_et_sa_preuve() {
    let mut liaison = [0_u8; MESSAGE_MAX];
    let lu = parse_client_final(CLIENT_FINAL, &mut liaison).expect("client-final");
    // `biws` est le base64 de `n,,` — l'en-tête GS2, sans données de liaison.
    assert_eq!(lu.channel_binding, b"n,,");
    assert_eq!(
        lu.nonce,
        &b"rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"[..]
    );
    // Le `sans_preuve` s'arrête juste avant `,p=`.
    // Le `sans_preuve` s'arrête juste avant `,p=` : il finit sur le nonce, et
    // ne contient plus l'attribut de preuve. (Chercher un `p` seul serait faux :
    // le nonce de la RFC en porte un, et la première version de ce banc s'y est
    // laissé prendre.)
    assert!(lu.sans_preuve.ends_with(b"k0"), "le `,p=` doit être coupé");
    assert!(
        !lu.sans_preuve.windows(3).any(|fenetre| fenetre == b",p="),
        "aucun attribut de preuve ne subsiste"
    );
}

#[test]
fn les_iterations_se_lisent_et_se_refusent() {
    assert_eq!(parse_iterations(b"4096"), Ok(4_096));
    assert_eq!(parse_iterations(b"32768"), Ok(32_768));
    for mauvais in [
        &b""[..],
        b"0",
        b"04096", // un zéro en tête : §7 l'interdit
        b"4095",  // sous le minimum de RFC 7677 §3.1
        b"12a",
        b"99999999999999999999", // déborde
    ] {
        assert_eq!(
            parse_iterations(mauvais),
            Err(Error::Iterations),
            "« {} » aurait dû être refusé",
            core::str::from_utf8(mauvais).unwrap_or("?")
        );
    }
    const { assert!(ITERATIONS_MIN == 4_096, "le minimum vient de RFC 7677 §3.1") };
}

// ── L'ANALYSE : CE QUI NE PASSE PAS ─────────────────────────────────────────

#[test]
fn un_entete_gs2_inconnu_est_refuse() {
    for mauvais in [
        &b"z,,n=jean,r=abc"[..],
        b"n,n=jean,r=abc",             // la virgule vide manque
        b"p=tls-unique,,n=jean,r=abc", // une autre liaison : non
        b"n,a=autre,n=jean,r=abc",     // agir pour un tiers : non
        b"",
    ] {
        assert_eq!(parse_client_first(mauvais), Err(Error::Gs2));
    }
}

#[test]
fn un_client_first_incomplet_est_refuse() {
    assert_eq!(parse_client_first(b"n,,r=abc"), Err(Error::Malformed));
    assert_eq!(parse_client_first(b"n,,n=jean"), Err(Error::Malformed));
    assert_eq!(parse_client_first(b"n,,n=,r=abc"), Err(Error::Empty));
    assert_eq!(parse_client_first(b"n,,n=jean,r="), Err(Error::Empty));
    assert_eq!(parse_client_first(b"n,,n=je=an,r=abc"), Err(Error::Escape));
    assert_eq!(parse_client_first(b"n,,n=jean=2,r=abc"), Err(Error::Escape));
}

#[test]
fn un_message_trop_long_est_refuse_avant_d_etre_lu() {
    let long = [b'a'; MESSAGE_MAX + 1];
    assert_eq!(parse_client_first(&long), Err(Error::TooLong));
    let mut liaison = [0_u8; MESSAGE_MAX];
    assert_eq!(parse_client_final(&long, &mut liaison), Err(Error::TooLong));
}

#[test]
fn un_client_final_incomplet_est_refuse() {
    let mut liaison = [0_u8; MESSAGE_MAX];
    let cas = [
        (&b"r=abc,p=AAAA"[..], Error::Malformed), // pas de `c=`
        (b"c=biws,p=AAAA", Error::Malformed),     // pas de `r=`
        (b"c=biws,r=,p=AAAA", Error::Empty),
        (b"c=biws,r=abc", Error::Malformed),     // pas de `p=`
        (b"c=!!!!,r=abc,p=AAAA", Error::Base64), // liaison illisible
        (b"c=biws,r=abc,p=trop-court", Error::Base64), // base64 illisible
        // Et une preuve PARFAITEMENT lisible qui ne fait pas trente-deux
        // octets : `AAAA` en rend trois. C'est le cas que la LONGUEUR attrape,
        // et lui seul — l'autre échoue plus tôt, au décodage.
        (b"c=biws,r=abc,p=AAAA", Error::Base64),
        // **UN ATTRIBUT ENTRE LE NONCE ET LA PREUVE** : §7 veut `p=` en dernier,
        // et ce message en porte bien un — mais pas là où il doit être. La
        // garde qui le refuse est donc atteignable, contrairement aux trois
        // autres que ce module a retirées.
        (b"c=biws,r=abc,x=1,p=AAAA", Error::Malformed),
    ];
    for (message, attendu) in cas {
        assert_eq!(
            parse_client_final(message, &mut liaison),
            Err(attendu),
            "« {} »",
            core::str::from_utf8(message).unwrap_or("?")
        );
    }
}

#[test]
fn le_desechappement_refuse_ce_qu_il_ne_sait_pas_lire() {
    let mut sortie = [0_u8; 32];
    assert_eq!(desechapper(b"jean=", &mut sortie), Err(Error::Escape));
    assert_eq!(desechapper(b"jean=4X", &mut sortie), Err(Error::Escape));
    // Un tampon trop court se dit, plutôt que de tronquer en silence.
    let mut minuscule = [0_u8; 2];
    assert_eq!(desechapper(b"jean", &mut minuscule), Err(Error::TooLong));
}

#[test]
fn les_erreurs_se_disent_et_se_distinguent() {
    // C2 : chaque variante est atteinte, et deux variantes ne se confondent pas.
    let toutes = [
        Error::Malformed,
        Error::Gs2,
        Error::Empty,
        Error::Escape,
        Error::Iterations,
        Error::Base64,
        Error::TooLong,
    ];
    for (rang, une) in toutes.iter().enumerate() {
        assert!(
            !std::format!("{une:?}").is_empty(),
            "une variante ne se dit pas"
        );
        for autre in toutes.get(rang.saturating_add(1)..).unwrap_or_default() {
            assert_ne!(une, autre);
        }
    }
    // Copie et débogage, comme partout ailleurs dans ce dépôt.
    let une = Error::Gs2;
    let copie = une;
    assert_eq!(une, copie);
}
