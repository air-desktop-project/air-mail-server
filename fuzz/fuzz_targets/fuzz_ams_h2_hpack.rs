// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les primitives HPACK** — l'entier à préfixe, le codage de Huffman,
//! la chaîne littérale.
//!
//! # Pourquoi celle-ci
//!
//! C'est le décodeur le plus exposé d'HTTP/2 : il lit des longueurs venues du
//! réseau, il a un état partagé par toute la connexion, et il décomprime. Un
//! entier qui déborde en silence — ce qui est ARRIVÉ ici, à l'écriture — fait
//! lire une longueur pour une autre, donc une chaîne pour une autre, donc un
//! en-tête que personne n'a envoyé.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN ENTIER ACCEPTÉ SE RÉÉCRIT ET SE RELIT À L'IDENTIQUE**, et n'a
//!    consommé que ce qu'on lui a donné. C'est la propriété qui aurait attrapé
//!    le débordement silencieux : la valeur relue n'aurait pas été celle qu'on
//!    croyait avoir lue.
//! 3. **CE QU'ON ÉCRIT SE RELIT** : entier, chaîne comprimée, chaîne en clair.
//! 4. **UNE CHAÎNE DÉCODÉE NE DÉBORDE PAS DE CE QU'ON A DONNÉ** : ni de
//!    l'entrée, ni du tampon de sortie.
//! 5. **LE DÉCODAGE DE HUFFMAN EST DÉTERMINISTE** : deux lectures des mêmes
//!    octets rendent les mêmes octets.
//! 6. **CE QUE HUFFMAN REND SE RECOMPRIME EN LUI-MÊME.** L'encodage est
//!    canonique : il n'y a qu'une façon d'écrire une chaîne, et c'est ce qui
//!    interdit d'en écrire deux qu'un pair lirait différemment.
//! 7. **LE DÉCODEUR AVANCE, OU IL REFUSE.** Un champ rendu consomme au moins un
//!    octet et jamais plus que le bloc. Un décodeur qui rendrait un champ sans
//!    avancer bouclerait sur le premier octet — c'est un déni de service en
//!    trois octets.
//! 8. **LA TABLE DYNAMIQUE RESTE DANS SA BORNE**, quoi qu'un bloc demande, et
//!    ce qu'elle rend se relit d'un seul tenant.
//! 9. **LES DEUX ÉTAGES SE COMPOSENT.** HPACK ne juge PAS les champs — il rend
//!    les octets qu'on lui a donnés à comprimer —, et c'est `HeadBuilder` qui
//!    décide si une liste est recevable. La propriété éprouve donc la JOINTURE :
//!    tout ce que le décompresseur rend passe par le juge, et le juge ne panique
//!    pas.
//!
//!    Cette propriété-là a d'abord été écrite à l'envers — « un nom décodé est un
//!    nom » —, et le fuzz l'a démentie en trois secondes avec un nom d'un seul
//!    octet nul. Il avait raison : ce n'est pas le décompresseur qui refuse.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_h2::hpack::{
    Decoder, STATIQUE_LEN, TABLE_SIZE_MAX, decode_huffman, decode_integer, decode_string,
    encode_huffman, encode_integer, encode_string, encoded_huffman_len,
};
use ams_proto_http::{HeadBuilder, Limits as LimitesHttp};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Des octets à lire comme un entier à préfixe.
    entier: &'a [u8],
    /// La largeur du préfixe, ramenée entre un et huit.
    bits: u8,
    /// Des octets à lire comme une chaîne littérale.
    chaine: &'a [u8],
    /// Des octets à lire comme un corps comprimé.
    comprime: &'a [u8],
    /// Des octets à comprimer.
    clair: &'a [u8],
    /// Deux blocs d'en-têtes, lus l'un après l'autre par le MÊME décodeur.
    ///
    /// Deux, parce que la table dynamique survit d'un bloc à l'autre : c'est
    /// l'état partagé, et c'est là que vivent les désynchronisations.
    blocs: (&'a [u8], &'a [u8]),
}

fuzz_target!(|entree: Entree<'_>| {
    let bits = u32::from(entree.bits % 8 + 1);

    // ── L'entier ────────────────────────────────────────────────────────────
    if let Ok((valeur, lus)) = decode_integer(entree.entier, bits) {
        // PROPRIÉTÉ 2 : on n'a pas consommé plus qu'on n'a reçu.
        assert!(
            lus <= entree.entier.len(),
            "un entier a mangé trop d'octets"
        );
        assert!(lus >= 1, "un entier accepté sans octet");

        // Et il se réécrit à l'identique. C'est ici que le débordement
        // silencieux se serait vu : la valeur relue n'aurait pas été celle-ci.
        let mut ecrit = [0_u8; 8];
        if let Ok(ecrits) = encode_integer(valeur, bits, 0, &mut ecrit) {
            assert_eq!(
                decode_integer(ecrit.get(..ecrits).unwrap_or_default(), bits),
                Ok((valeur, ecrits)),
                "un entier réécrit ne se relit pas pareil"
            );
        }
    }

    // ── La chaîne littérale ─────────────────────────────────────────────────
    let mut sortie = vec![0_u8; 64 * 1024];
    if let Ok((texte, lus)) = decode_string(entree.chaine, &mut sortie) {
        // PROPRIÉTÉ 4.
        assert!(
            lus <= entree.chaine.len(),
            "une chaîne a mangé trop d'octets"
        );
        let taille = texte.len();
        assert!(taille <= 64 * 1024, "une chaîne déborde du tampon");

        // PROPRIÉTÉ 3 : ce qu'on a lu se réécrit et se relit.
        let mut ecrit = vec![0_u8; taille.saturating_mul(2).saturating_add(16)];
        let clair = texte.to_vec();
        if let Ok(ecrits) = encode_string(&clair, &mut ecrit) {
            let mut relu = vec![0_u8; taille.saturating_add(16)];
            let (retour, consommes) =
                decode_string(ecrit.get(..ecrits).unwrap_or_default(), &mut relu)
                    .expect("ce qu'on écrit se relit");
            assert_eq!(retour, clair.as_slice(), "une chaîne réécrite a changé");
            assert_eq!(consommes, ecrits, "on relit exactement ce qu'on a écrit");
        }
    }

    // ── Huffman seul ────────────────────────────────────────────────────────
    let mut premier = vec![0_u8; 64 * 1024];
    if let Ok(ecrits) = decode_huffman(entree.comprime, &mut premier) {
        // PROPRIÉTÉ 5 : deux lectures, le même résultat.
        let mut second = vec![0_u8; 64 * 1024];
        assert_eq!(
            decode_huffman(entree.comprime, &mut second),
            Ok(ecrits),
            "deux lectures ne s'accordent pas"
        );
        assert_eq!(
            premier.get(..ecrits),
            second.get(..ecrits),
            "deux lectures ne rendent pas les mêmes octets"
        );

        // PROPRIÉTÉ 6 : ce qui sort se recomprime en ce qui est entré.
        // L'encodage est CANONIQUE : il n'y a qu'une façon de l'écrire.
        let decode = premier.get(..ecrits).unwrap_or_default().to_vec();
        let attendu = encoded_huffman_len(&decode);
        let mut recomprime = vec![0_u8; attendu.saturating_add(8)];
        let refait = encode_huffman(&decode, &mut recomprime).expect("recomprimable");
        assert_eq!(
            refait, attendu,
            "la longueur annoncée n'est pas celle écrite"
        );
        assert_eq!(
            recomprime.get(..refait),
            Some(entree.comprime),
            "une chaîne acceptée n'est pas celle qu'on aurait écrite"
        );
    }

    // ── Le décodeur, sur deux blocs et une seule table ──────────────────────
    let mut decodeur = Decoder::new();
    let mut place = vec![0_u8; 16 * 1024];
    let bornes = LimitesHttp::DEFAULT;
    for bloc in [entree.blocs.0, entree.blocs.1] {
        decodeur.begin_block();
        // LES PAIRES SE RECOPIENT AVANT D'ÊTRE JUGÉES : le décompresseur prête
        // son tampon, et le tour suivant le réécrit. C'est la même contrainte
        // que l'appelant réel aura — et la raison pour laquelle le décodeur
        // écrit dans un tampon fourni plutôt que de prêter sa table.
        let mut recoltees: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut reste = bloc;
        let mut tours = 0_u32;
        loop {
            // PROPRIÉTÉ 7 : la boucle avance, ou elle s'arrête.
            tours = tours.saturating_add(1);
            assert!(tours < 100_000, "le décodeur n'avance pas");

            let Ok(issue) = decodeur.next(reste, &mut place) else {
                break;
            };
            let Some((champ, lus)) = issue else {
                break;
            };
            assert!(lus >= 1, "un champ rendu sans consommer d'octet");
            assert!(lus <= reste.len(), "un champ a mangé plus que le bloc");

            recoltees.push((champ.name.to_vec(), champ.value.to_vec()));

            // PROPRIÉTÉ 8, à chaque tour : la table ne déborde jamais.
            let table = decodeur.table();
            assert!(table.size() <= table.max_size(), "la table déborde");
            assert!(
                table.max_size() <= TABLE_SIZE_MAX,
                "la borne a été franchie"
            );
            for index in 1..=table.len() {
                let (n, v) = table.get(index).expect("dans la table");
                let poids = u32::try_from(n.len().saturating_add(v.len()))
                    .unwrap_or(u32::MAX)
                    .saturating_add(32);
                assert!(
                    poids <= table.max_size(),
                    "une entrée pèse plus que la table"
                );
            }
            // Et l'index qui suit la dernière ne désigne rien.
            assert!(table.get(table.len().saturating_add(1)).is_none());
            let _ = STATIQUE_LEN;

            reste = reste.get(lus..).unwrap_or_default();
        }
        // PROPRIÉTÉ 9 : la jointure des deux étages. Le juge accepte ou refuse ;
        // ce qu'on éprouve, c'est qu'il TRANCHE — et qu'aucune paire venue du
        // décompresseur ne le fait paniquer.
        let mut juge = HeadBuilder::new(&bornes);
        for (nom, valeur) in &recoltees {
            if juge.field(nom, valeur).is_err() {
                break;
            }
        }
        let _ = juge.finish();
    }

    // ── La compression, dans l'autre sens ───────────────────────────────────
    let attendu = encoded_huffman_len(entree.clair);
    let mut serre = vec![0_u8; attendu.saturating_add(8)];
    let ecrits = encode_huffman(entree.clair, &mut serre).expect("comprimable");
    assert_eq!(
        ecrits, attendu,
        "la longueur annoncée n'est pas celle écrite"
    );
    let mut retour = vec![0_u8; entree.clair.len().saturating_add(8)];
    let relus = decode_huffman(serre.get(..ecrits).unwrap_or_default(), &mut retour)
        .expect("ce qu'on comprime se décomprime");
    assert_eq!(
        retour.get(..relus),
        Some(entree.clair),
        "un aller-retour de compression a changé les octets"
    );
});
