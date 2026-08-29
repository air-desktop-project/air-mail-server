// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : ce qu'une signature DKIM couvre, et ce qu'elle dit.**
//!
//! Trois surfaces, toutes fournies par autrui : le champ `DKIM-Signature` d'un
//! message, l'enregistrement de clé publique lu dans le DNS, et **le corps du
//! message**, qui est ce qu'un pair envoie de plus gros.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets et le découpage.
//! 2. **LE DÉCOUPAGE NE CHANGE RIEN.** La canonicalisation du corps est une
//!    machine en flux : le pair choisit la taille de ses paquets, et le
//!    condensat ne doit pas en dépendre. Une fin de ligne coupée en deux est le
//!    cas qui casse les implémentations naïves.
//! 3. **`relaxed` tient ses promesses** : aucune tabulation ne survit, aucune
//!    suite de deux espaces, aucun blanc avant une fin de ligne.
//! 4. **Le corps canonicalisé finit par une fin de ligne**, sauf le corps vide
//!    en `relaxed` — et cette exception-là est dans la RFC.
//! 5. **La borne `l=` est tenue au sens strict** : jamais un octet de plus.
//! 6. **Une signature acceptée est cohérente** : `v=1`, un algorithme admis,
//!    `from` couvert, `i=` sous `d=`, `x=` après `t=`.
//! 7. **Une clé acceptée n'est pas révoquée.**

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_dkim::{
    Algorithm, BodyCanon, Canon, PublicKeyRecord, Signature, Trailer, canonicalize_header,
};

#[derive(Debug, Arbitrary)]
struct Entree<'a> {
    /// La valeur d'un champ `DKIM-Signature`, telle qu'un message la porte.
    signature: &'a [u8],
    /// Un enregistrement de clé, tel que le DNS le rend.
    cle: &'a [u8],
    /// Le corps du message, et la façon dont il est découpé.
    corps: Vec<&'a [u8]>,
    /// Un champ d'en-tête. Le nom est ramené à ce qu'un nom peut être — voir
    /// `nom_de_champ` ci-dessous.
    nom: &'a [u8],
    valeur: &'a [u8],
    /// Les choix : `relaxed` ou non, et la borne `l=`.
    relaxed: bool,
    limite: Option<u32>,
}

/// Ramène des octets quelconques à ce qu'un nom de champ peut être.
///
/// RFC 5322 §3.6.8 : `%d33-57 / %d59-126`, c'est-à-dire ni blanc, ni deux-points,
/// ni fin de ligne. Le bloc d'en-tête a été validé bien avant d'arriver à la
/// canonicalisation, et c'est lui qui garantit cette forme : lui donner ici des
/// octets qu'aucun message ne peut porter éprouverait un contrat que personne
/// n'a signé.
fn nom_de_champ(brut: &[u8]) -> Vec<u8> {
    brut.iter()
        .copied()
        .filter(|octet| (33..=126).contains(octet) && *octet != b':')
        .collect()
}

/// Canonicalise un corps donné en morceaux, et rend ce qui sort.
fn canoniser(canon: Canon, morceaux: &[&[u8]], limite: Option<u64>) -> Vec<u8> {
    let mut rendu = Vec::new();
    let mut machine = BodyCanon::new(canon, limite);
    for morceau in morceaux {
        machine.update(morceau, &mut |sortie| rendu.extend_from_slice(sortie));
    }
    let ecrits = machine.finish(&mut |sortie| rendu.extend_from_slice(sortie));
    assert_eq!(
        ecrits,
        rendu.len() as u64,
        "le compte des octets écrits ne suit pas ce qui est sorti"
    );
    rendu
}

fuzz_target!(|entree: Entree| {
    let canon = if entree.relaxed {
        Canon::Relaxed
    } else {
        Canon::Simple
    };
    let limite = entree.limite.map(u64::from);

    // ── 1, 2 : le découpage ne change rien ──────────────────────────────────
    let par_morceaux = canoniser(canon, &entree.corps, limite);
    let entier: Vec<u8> = entree.corps.concat();
    let d_un_tenant = canoniser(canon, &[&entier[..]], limite);
    assert_eq!(
        par_morceaux, d_un_tenant,
        "le découpage a changé la canonicalisation"
    );
    // Et octet par octet, ce qui coupe TOUT ce qui peut l'être.
    let un_par_un: Vec<&[u8]> = entier.chunks(1).collect();
    assert_eq!(
        canoniser(canon, &un_par_un, limite),
        d_un_tenant,
        "un découpage octet par octet a changé la canonicalisation"
    );

    // ── 5 : la borne ────────────────────────────────────────────────────────
    let sans_borne = canoniser(canon, &[&entier[..]], None);
    match limite {
        Some(borne) => assert!(
            d_un_tenant.len() as u64 <= borne,
            "la borne `l=` a été dépassée"
        ),
        None => assert_eq!(d_un_tenant, sans_borne),
    }
    // Ce qui sort sous une borne est un PRÉFIXE de ce qui sort sans elle : la
    // borne coupe, elle ne réécrit pas.
    assert!(
        sans_borne.starts_with(&d_un_tenant),
        "la borne a changé les octets au lieu de les couper"
    );

    // ── 3, 4 : ce que chaque algorithme promet ──────────────────────────────
    if limite.is_none() {
        if canon == Canon::Relaxed {
            assert!(
                !sans_borne.windows(2).any(|paire| paire == b"  "),
                "deux espaces ont survécu à `relaxed`"
            );
            assert!(
                !sans_borne.contains(&b'\t'),
                "une tabulation a survécu à `relaxed`"
            );
            assert!(
                !sans_borne
                    .windows(3)
                    .any(|trio| trio[0] == b' ' && &trio[1..] == b"\r\n"),
                "un blanc de queue a survécu à `relaxed`"
            );
        }
        assert!(
            sans_borne.is_empty() || sans_borne.ends_with(b"\r\n"),
            "le corps canonicalisé ne finit pas par une fin de ligne"
        );
        assert!(
            !sans_borne.is_empty() || canon == Canon::Relaxed,
            "`simple` rend toujours au moins une fin de ligne"
        );
    }

    // ── Les en-têtes ────────────────────────────────────────────────────────
    let nom = nom_de_champ(entree.nom);
    for fin in [Trailer::Crlf, Trailer::Aucun] {
        let mut rendu = Vec::new();
        canonicalize_header(canon, &nom, entree.valeur, fin, &mut |sortie| {
            rendu.extend_from_slice(sortie)
        });
        if fin == Trailer::Crlf {
            assert!(
                rendu.ends_with(b"\r\n"),
                "le terminateur demandé n'a pas été écrit"
            );
        }
        if canon == Canon::Relaxed {
            let corps = rendu.strip_suffix(b"\r\n").unwrap_or(&rendu);
            assert!(
                !corps.contains(&b'\r') && !corps.contains(&b'\n'),
                "un pliage a survécu à `relaxed`"
            );
            assert!(!corps.contains(&b'\t'), "une tabulation a survécu");
        }
    }

    // ── 6 : une signature acceptée est cohérente ────────────────────────────
    if let Ok(signature) = Signature::parse(entree.signature) {
        assert!(
            signature
                .signed_headers()
                .any(|nom| nom.eq_ignore_ascii_case(b"from")),
            "une signature qui ne couvre pas `from` a été acceptée"
        );
        assert!(!signature.domain.is_empty());
        assert!(!signature.selector.is_empty());
        assert!(
            matches!(
                signature.algorithm,
                Algorithm::RsaSha256 | Algorithm::Ed25519Sha256
            ),
            "un algorithme retiré a été accepté"
        );
        if let (Some(pose), Some(fin)) = (signature.timestamp, signature.expiration) {
            assert!(fin > pose, "une signature expire avant d'être posée");
        }
        // Deux lectures rendent la même chose.
        assert_eq!(Signature::parse(entree.signature), Ok(signature));
        let mut tampon = [0_u8; 1024];
        if let Ok(sans_blancs) = signature.signature_base64(&mut tampon) {
            assert!(
                !sans_blancs.iter().any(u8::is_ascii_whitespace),
                "un blanc a survécu au dépliage"
            );
        }
    }

    // ── 7 : une clé acceptée n'est pas révoquée ─────────────────────────────
    if let Ok(cle) = PublicKeyRecord::parse(entree.cle) {
        assert!(!cle.key.is_empty(), "une clé révoquée a été acceptée");
        assert_eq!(PublicKeyRecord::parse(entree.cle), Ok(cle));
        let _ = cle.accepts(Algorithm::RsaSha256);
        let _ = cle.matches(Algorithm::Ed25519Sha256);
    }
});
