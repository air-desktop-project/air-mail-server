//! Ce qu'un champ `DKIM-Signature` doit tenir.

use super::{Algorithm, Signature, nombre, sous_le_domaine};
use crate::Error;
use crate::canonical::{Canon, Canonicalization};

/// Une signature complète et cohérente, à laquelle on retire ou ajoute.
const ENTIERE: &[u8] = b"v=1; a=rsa-sha256; c=relaxed/simple; d=example.com; s=brisbane; \
                         h=from:to:subject:date; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; \
                         b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB4nujc7YopdG5";

fn lire(valeur: &[u8]) -> Result<Signature<'_>, Error> {
    Signature::parse(valeur)
}

#[test]
fn une_signature_ordinaire_se_lit() {
    let signature = lire(ENTIERE).expect("lisible");
    assert_eq!(signature.algorithm, Algorithm::RsaSha256);
    assert_eq!(
        signature.canonicalization,
        Canonicalization {
            header: Canon::Relaxed,
            body: Canon::Simple
        }
    );
    assert_eq!(signature.domain, b"example.com");
    assert_eq!(signature.selector, b"brisbane");
    assert_eq!(signature.identity, None);
    assert_eq!(signature.body_length, None);
    assert_eq!(signature.timestamp, None);
    assert_eq!(signature.expiration, None);
    let noms: std::vec::Vec<&[u8]> = signature.signed_headers().collect();
    assert_eq!(noms, [&b"from"[..], b"to", b"subject", b"date"]);
}

#[test]
fn les_etiquettes_facultatives_se_lisent() {
    let mut valeur = std::vec::Vec::from(ENTIERE);
    valeur.extend_from_slice(b"; i=jean@sous.example.com; l=42; t=1000; x=2000; q=dns/txt");
    let signature = lire(&valeur).expect("lisible");
    assert_eq!(signature.identity, Some(&b"jean@sous.example.com"[..]));
    assert_eq!(signature.body_length, Some(42));
    assert_eq!(signature.timestamp, Some(1000));
    assert_eq!(signature.expiration, Some(2000));
}

#[test]
fn une_etiquette_inconnue_s_ignore() {
    // §3.2 : c'est ce qui permet à la RFC d'en ajouter sans casser les
    // vérificateurs. `z=` en est une, qui ne sert qu'au diagnostic.
    let mut valeur = std::vec::Vec::from(ENTIERE);
    valeur.extend_from_slice(b"; z=From:jean@example.com; futur=demain");
    assert!(lire(&valeur).is_ok());
}

#[test]
fn les_noms_d_etiquette_sont_sensibles_a_la_casse() {
    // §3.2. Traiter `D=` comme `d=` accepterait une signature dont le domaine
    // n'est écrit nulle part — et l'on irait chercher la clé de personne.
    let mechante = ENTIERE.to_vec();
    let mechante = std::string::String::from_utf8(mechante)
        .expect("ASCII")
        .replace("d=example.com", "D=example.com");
    assert_eq!(lire(mechante.as_bytes()), Err(Error::MissingTag("d")));
}

// ── CE QUI FAIT ÉCHOUER, ET CE QUE CHACUN PROTÈGE ───────────────────────────

#[test]
fn rsa_sha1_est_refuse() {
    // RFC 8301 §3.1 l'interdit aux signataires COMME AUX VÉRIFICATEURS. SHA-1 se
    // collisionne pour un coût qu'un particulier peut payer : accepter ces
    // signatures reviendrait à valider ce qu'on sait falsifiable.
    assert_eq!(
        Algorithm::parse(b"rsa-sha1"),
        Err(Error::UnsupportedAlgorithm)
    );
    let avec = std::string::String::from_utf8(ENTIERE.to_vec())
        .expect("ASCII")
        .replace("a=rsa-sha256", "a=rsa-sha1");
    assert_eq!(lire(avec.as_bytes()), Err(Error::UnsupportedAlgorithm));
}

#[test]
fn les_deux_algorithmes_admis_se_lisent_sans_casse() {
    assert_eq!(
        Algorithm::parse(b"RSA-SHA256").expect("lisible"),
        Algorithm::RsaSha256
    );
    assert_eq!(
        Algorithm::parse(b"ed25519-sha256").expect("lisible"),
        Algorithm::Ed25519Sha256
    );
    assert_eq!(Algorithm::RsaSha256.hash_name(), b"sha256");
    assert_eq!(Algorithm::Ed25519Sha256.hash_name(), b"sha256");
    assert_eq!(Algorithm::parse(b"md5"), Err(Error::UnsupportedAlgorithm));
}

#[test]
fn une_signature_qui_ne_couvre_pas_from_est_refusee() {
    // C'EST LE CŒUR DU SUJET : une signature qui ne couvre pas l'auteur ne dit
    // rien de l'auteur, et c'est pourtant lui que l'humain lira.
    let sans = std::string::String::from_utf8(ENTIERE.to_vec())
        .expect("ASCII")
        .replace("h=from:to:subject:date", "h=to:subject:date");
    assert_eq!(lire(sans.as_bytes()), Err(Error::FromNotSigned));
    // La comparaison est insensible à la casse, comme tout nom de champ.
    let majuscule = std::string::String::from_utf8(ENTIERE.to_vec())
        .expect("ASCII")
        .replace("h=from:", "h=From:");
    assert!(lire(majuscule.as_bytes()).is_ok());
}

#[test]
fn une_identite_hors_du_domaine_est_refusee() {
    // Sans cette règle, un signataire s'attribuerait l'identité d'un domaine
    // qu'il ne détient pas.
    for (agent, admis) in [
        ("jean@example.com", true),
        ("jean@sous.example.com", true),
        ("@example.com", true),
        ("jean@autre.example", false),
        // `badexample.com` finit par `example.com` sans être dessous : le point
        // compte, et l'oublier autoriserait qui enregistre un nom qui finit par
        // celui du signataire.
        ("jean@badexample.com", false),
        // Sans `@`, ce n'est pas une identité.
        ("example.com", false),
    ] {
        let mut valeur = std::vec::Vec::from(ENTIERE);
        valeur.extend_from_slice(b"; i=");
        valeur.extend_from_slice(agent.as_bytes());
        assert_eq!(lire(&valeur).is_ok(), admis, "{agent}");
    }
}

#[test]
fn une_signature_qui_expire_avant_d_etre_posee_est_refusee() {
    for (t, x, admis) in [(1000, 2000, true), (1000, 1000, false), (1000, 999, false)] {
        let mut valeur = std::vec::Vec::from(ENTIERE);
        valeur.extend_from_slice(std::format!("; t={t}; x={x}").as_bytes());
        assert_eq!(lire(&valeur).is_ok(), admis, "t={t} x={x}");
    }
    // Une expiration SEULE reste licite : c'est l'ordre des deux qui compte.
    let mut valeur = std::vec::Vec::from(ENTIERE);
    valeur.extend_from_slice(b"; x=1");
    assert!(lire(&valeur).is_ok());
}

#[test]
fn une_etiquette_en_double_est_refusee() {
    // Deux `d=` désigneraient deux domaines, et rien ne dirait lequel signe.
    for doublon in [
        "; d=autre.example",
        "; v=1",
        "; a=rsa-sha256",
        "; c=simple",
        "; s=x",
        "; h=from",
        "; b=x",
        "; bh=x",
    ] {
        let mut valeur = std::vec::Vec::from(ENTIERE);
        valeur.extend_from_slice(doublon.as_bytes());
        assert_eq!(lire(&valeur), Err(Error::DuplicateTag), "{doublon}");
    }
    // Et les étiquettes facultatives ne font pas exception.
    for doublon in ["i=jean@example.com", "l=1", "t=1", "x=9"] {
        let mut valeur = std::vec::Vec::from(ENTIERE);
        valeur.extend_from_slice(std::format!("; {doublon}; {doublon}").as_bytes());
        assert_eq!(lire(&valeur), Err(Error::DuplicateTag), "{doublon}");
    }
}

#[test]
fn une_etiquette_obligatoire_absente_est_refusee() {
    for (retiree, attendue) in [
        ("a=rsa-sha256; ", Error::MissingTag("a")),
        ("d=example.com; ", Error::MissingTag("d")),
        ("s=brisbane; ", Error::MissingTag("s")),
        ("h=from:to:subject:date; ", Error::MissingTag("h")),
    ] {
        let ampute = std::string::String::from_utf8(ENTIERE.to_vec())
            .expect("ASCII")
            .replace(retiree, "");
        assert_eq!(lire(ampute.as_bytes()), Err(attendue), "{retiree}");
    }
}

#[test]
fn une_version_autre_que_1_est_refusee() {
    for version in ["v=2", "v=", "v=1x"] {
        let autre = std::string::String::from_utf8(ENTIERE.to_vec())
            .expect("ASCII")
            .replace("v=1", version);
        assert_eq!(
            lire(autre.as_bytes()),
            Err(Error::UnsupportedVersion),
            "{version}"
        );
    }
    // Absente aussi : `v=` est obligatoire, et sa place est la première.
    let sans = std::string::String::from_utf8(ENTIERE.to_vec())
        .expect("ASCII")
        .replace("v=1; ", "");
    assert_eq!(lire(sans.as_bytes()), Err(Error::UnsupportedVersion));
}

#[test]
fn un_domaine_ou_un_selecteur_vide_est_refuse() {
    let sans_domaine = std::string::String::from_utf8(ENTIERE.to_vec())
        .expect("ASCII")
        .replace("d=example.com", "d=");
    assert_eq!(lire(sans_domaine.as_bytes()), Err(Error::MalformedDomain));
    let sans_selecteur = std::string::String::from_utf8(ENTIERE.to_vec())
        .expect("ASCII")
        .replace("s=brisbane", "s=");
    assert_eq!(lire(sans_selecteur.as_bytes()), Err(Error::MalformedDomain));
}

#[test]
fn une_methode_de_requete_inconnue_fait_ignorer_la_signature() {
    // §3.5 : un vérificateur DOIT ignorer une signature dont le `q=` ne nomme
    // que des méthodes qu'il n'implémente pas.
    let mut valeur = std::vec::Vec::from(ENTIERE);
    valeur.extend_from_slice(b"; q=ldap/x");
    assert_eq!(lire(&valeur), Err(Error::UnsupportedAlgorithm));
    // Une liste qui en nomme une qu'on connaît suffit.
    let mut valeur = std::vec::Vec::from(ENTIERE);
    valeur.extend_from_slice(b"; q=ldap/x : dns/txt");
    assert!(lire(&valeur).is_ok());
}

#[test]
fn un_nombre_qui_deborde_est_refuse() {
    // Un `x=` qui déborderait en repartant de zéro ferait expirer une signature
    // valide, ou l'inverse.
    assert_eq!(nombre(b"18446744073709551615").expect("lisible"), u64::MAX);
    assert_eq!(nombre(b"18446744073709551616"), Err(Error::MalformedNumber));
    assert_eq!(
        nombre(b"99999999999999999999999"),
        Err(Error::MalformedNumber)
    );
    assert_eq!(nombre(b""), Err(Error::MalformedNumber));
    assert_eq!(nombre(b"12a"), Err(Error::MalformedNumber));
    assert_eq!(nombre(b"-1"), Err(Error::MalformedNumber));
    assert_eq!(nombre(b"0").expect("lisible"), 0);
}

// ── CE QUE L'APPELANT LIT ───────────────────────────────────────────────────

#[test]
fn le_base64_se_rend_sans_ses_blancs() {
    // Le `b=` d'une signature réelle est plié : les blancs n'en font pas partie,
    // et les garder ferait échouer le décodage.
    let mut valeur = std::vec::Vec::from(
        &b"v=1; a=rsa-sha256; d=example.com; s=x; h=from; bh=YWJj\r\n\tZA==; b=Zm9v\r\n IGJhcg=="[..],
    );
    let signature = lire(&valeur).expect("lisible");
    let mut tampon = [0_u8; 64];
    assert_eq!(
        signature.body_hash_base64(&mut tampon).expect("tient"),
        b"YWJjZA=="
    );
    assert_eq!(
        signature.signature_base64(&mut tampon).expect("tient"),
        b"Zm9vIGJhcg=="
    );
    // Et un tampon trop petit refuse plutôt que de tronquer : une valeur
    // tronquée se décoderait en autre chose, et cette autre chose serait
    // comparée à un condensat.
    let mut minuscule = [0_u8; 4];
    assert_eq!(
        signature.signature_base64(&mut minuscule),
        Err(Error::BufferTooSmall)
    );
    valeur.clear();
}

#[test]
fn la_liste_des_champs_signes_se_lit_sans_ses_blancs() {
    let valeur = b"v=1; a=rsa-sha256; d=example.com; s=x; bh=x; b=x; \
                   h=from :\r\n to\t: subject";
    let signature = lire(valeur).expect("lisible");
    let noms: std::vec::Vec<&[u8]> = signature.signed_headers().collect();
    assert_eq!(noms, [&b"from"[..], b"to", b"subject"]);
}

#[test]
fn un_nom_vide_dans_la_liste_est_rendu_tel_quel() {
    // `h=from::to` nomme un champ qui n'existe pas ; c'est à l'appelant de le
    // constater, et non à la grammaire de le taire.
    let valeur = b"v=1; a=rsa-sha256; d=example.com; s=x; bh=x; b=x; h=from::to";
    let signature = lire(valeur).expect("lisible");
    let noms: std::vec::Vec<&[u8]> = signature.signed_headers().collect();
    assert_eq!(noms, [&b"from"[..], b"", b"to"]);
    // Un `h=` qui finit par un deux-points nomme un dernier champ vide.
    let valeur = b"v=1; a=rsa-sha256; d=example.com; s=x; bh=x; b=x; h=from:";
    let noms: std::vec::Vec<&[u8]> = lire(valeur).expect("lisible").signed_headers().collect();
    assert_eq!(noms, [&b"from"[..], b""]);
}

#[test]
fn sous_le_domaine_est_total() {
    assert!(sous_le_domaine(b"@example.com", b"example.com"));
    assert!(sous_le_domaine(b"a@b.example.com", b"example.com"));
    assert!(!sous_le_domaine(b"a@com", b"example.com"));
    assert!(!sous_le_domaine(b"", b"example.com"));
    assert!(!sous_le_domaine(b"a@xexample.com", b"example.com"));
    // Le dernier `@` fait foi : une partie locale entre guillemets peut en
    // porter un.
    assert!(sous_le_domaine(b"\"a@b\"@example.com", b"example.com"));
}

#[test]
fn une_liste_mal_formee_remonte_telle_quelle() {
    assert_eq!(lire(b"v=1;;a=rsa-sha256"), Err(Error::MalformedTagList));
    assert_eq!(lire(b"1=x"), Err(Error::MalformedTagName));
    assert_eq!(lire(b"v=\x01"), Err(Error::MalformedTagValue));
}

#[test]
fn les_types_se_deboguent_et_se_comparent() {
    let signature = lire(ENTIERE).expect("lisible");
    let copie = signature;
    assert_eq!(copie, signature);
    assert!(!std::format!("{signature:?}").is_empty());
    assert!(!std::format!("{:?}", signature.signed_headers()).is_empty());
    assert!(!std::format!("{:?}", Algorithm::RsaSha256).is_empty());
    assert_ne!(Algorithm::RsaSha256, Algorithm::Ed25519Sha256);
}

#[test]
fn une_faute_dans_une_valeur_remonte_de_la_ou_elle_est() {
    // Chaque étiquette valide la sienne, et sa faute est CELLE DE L'ÉTIQUETTE —
    // pas une « liste mal formée » qui ne dirait pas quoi corriger.
    for (mechante, attendue) in [
        ("c=strict", Error::UnsupportedCanonicalization),
        ("l=x", Error::MalformedNumber),
        ("t=x", Error::MalformedNumber),
        ("x=x", Error::MalformedNumber),
    ] {
        let mut valeur = std::vec::Vec::from(ENTIERE);
        valeur.extend_from_slice(b"; ");
        valeur.extend_from_slice(mechante.as_bytes());
        // `c=` figure déjà dans la signature entière : on la retire d'abord.
        let texte = std::string::String::from_utf8(valeur)
            .expect("ASCII")
            .replace("c=relaxed/simple; ", "");
        assert_eq!(lire(texte.as_bytes()), Err(attendue), "{mechante}");
    }
}

#[test]
fn la_signature_et_le_condensat_sont_obligatoires() {
    // Sans `b=`, il n'y a rien à vérifier ; sans `bh=`, rien à comparer au
    // corps. Une signature à laquelle il en manque une n'est pas une signature.
    let sans_b = std::string::String::from_utf8(ENTIERE.to_vec())
        .expect("ASCII")
        .replace(
            "b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB4nujc7YopdG5",
            "",
        );
    assert_eq!(lire(sans_b.as_bytes()), Err(Error::MissingTag("b")));

    let sans_bh = std::string::String::from_utf8(ENTIERE.to_vec())
        .expect("ASCII")
        .replace("bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; ", "");
    assert_eq!(lire(sans_bh.as_bytes()), Err(Error::MissingTag("bh")));
}
