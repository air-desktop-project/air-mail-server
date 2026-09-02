// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les paramètres de RFC 3461** — ce qu'un déposant demande du sort de
//! son message, et qui ressort dans un rapport que NOUS composons.
//!
//! # CE QUI EST HOSTILE ICI
//!
//! `ENVID` et `ORCPT` traversent le serveur pour ressortir sous notre nom, dans
//! un document que le client du déposant lira comme un rapport officiel. Un
//! `CRLF` glissé dedans y écrirait des champs de statut à notre place — la même
//! faille que le `Diagnostic-Code` d'un serveur inconnu, par une autre porte.
//!
//! C'est pourquoi §4 les encode en **xtext**. Le décodage a lieu une fois, et ce
//! qui n'est pas un xtext valable est refusé, jamais corrigé.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN XTEXT DÉCODÉ NE GRANDIT JAMAIS** : `+41` fait un octet là où il en
//!    occupait trois. C'est ce qui permet à l'appelant de dimensionner son
//!    tampon sans rien calculer.
//! 3. **CE QUI SORT EST DE L'ASCII VISIBLE**, sans `CR`, sans `LF`, sans espace
//!    ni tabulation : ce qui s'écrira dans le rapport ne peut donc pas y ouvrir
//!    une seconde ligne.
//! 4. **RIEN N'EST ÉCRIT AU-DELÀ DU TAMPON** : ce qui borde ne bouge pas.
//! 5. **`NEVER` NE SE COMBINE AVEC RIEN** (§4.1), et un `NOTIFY` accepté demande
//!    toujours au moins une chose.
//! 6. **CE QUI EST ÉCRIT SE RELIT À L'IDENTIQUE** : ré-encoder puis décoder rend
//!    la valeur de départ, et ce qui sort de l'encodeur est un xtext valable.
//!
//! # LA SIXIÈME PROPRIÉTÉ TIENT UN MESSAGE ENTIER
//!
//! La file garde ces valeurs DÉCODÉES — c'est sous cette forme qu'elles
//! s'écrivent dans un rapport — et le fil, lui, veut du xtext. Un aller-retour
//! qui ne se referme pas ferait partir vers le saut suivant une adresse
//! d'origine qui n'est plus celle du déposant, ou pire un `RCPT` refusé :
//! `marie+liste@x.test` écrite en clair se relit comme l'échappée `+li`, qui
//! n'est pas de l'hexadécimal. L'adressage par étiquette est partout, et le
//! message serait perdu pour un caractère.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use ams_proto_smtp::{
    Notify, ORCPT_MAX, Ret, XTEXT_GROWTH, decode_xtext, encode_xtext, parse_orcpt,
};
use libfuzzer_sys::fuzz_target;

/// Ce qui borde le tampon, pour voir si l'on écrit au-delà.
const GARDE: u8 = 0xa5;

fuzz_target!(|entree: &[u8]| {
    // ── `NOTIFY` (§4.1) ─────────────────────────────────────────────────────
    if let Ok(notify) = Notify::parse(entree) {
        // 5. `NEVER` NE SE COMBINE AVEC RIEN.
        if notify.never() {
            assert!(
                !notify.on_success() && !notify.on_failure() && !notify.on_delay(),
                "`NEVER` mêlé à autre chose : {:?}",
                String::from_utf8_lossy(entree)
            );
        }
        assert!(
            notify.never() || notify.on_success() || notify.on_failure() || notify.on_delay(),
            "un `NOTIFY` accepté qui ne demande rien : {:?}",
            String::from_utf8_lossy(entree)
        );
    }

    // `RET` ne connaît que deux valeurs, et ne rend rien d'autre.
    let _ = Ret::parse(entree);

    // ── `xtext` (§4) ────────────────────────────────────────────────────────
    let mut tampon = vec![GARDE; entree.len().saturating_add(64)];
    let issue = {
        let place = tampon
            .get_mut(..entree.len())
            .expect("le tampon fait au moins la longueur de l'entrée");
        decode_xtext(entree, place).map(<[u8]>::len)
    };
    // 4. RIEN N'EST ÉCRIT AU-DELÀ.
    assert!(
        tampon
            .get(entree.len()..)
            .is_some_and(|bord| bord.iter().all(|octet| *octet == GARDE)),
        "écrit au-delà de la place donnée"
    );
    if let Ok(combien) = issue {
        // 2. LE DÉCODAGE NE GRANDIT JAMAIS.
        assert!(combien <= entree.len(), "le décodage a grandi");
        let decode = tampon.get(..combien).unwrap_or_default();
        // 3. CE QUI SORT EST DE L'ASCII VISIBLE.
        assert!(
            decode.iter().all(u8::is_ascii_graphic),
            "un octet qui ouvrirait une seconde ligne dans le rapport"
        );

        // ── 6. L'ALLER ET LE RETOUR SE RÉPONDENT (§4) ───────────────────────
        //
        // Ce qui sort du décodeur est exactement ce que la file garde ; c'est
        // donc exactement ce que l'encodeur devra remettre sur le fil.
        let mut encode = vec![GARDE; combien.saturating_mul(XTEXT_GROWTH).saturating_add(64)];
        let large = combien.saturating_mul(XTEXT_GROWTH);
        let ecrit = {
            let place = encode
                .get_mut(..large)
                .expect("le tampon fait au moins le pire gonflement");
            encode_xtext(decode, place)
                .expect("ce qui sort du décodeur est de l'ASCII visible")
                .len()
        };
        // 4. RIEN N'EST ÉCRIT AU-DELÀ, ici non plus.
        assert!(
            encode
                .get(large..)
                .is_some_and(|bord| bord.iter().all(|octet| *octet == GARDE)),
            "l'encodeur a écrit au-delà du pire gonflement annoncé"
        );
        let sur_le_fil = encode.get(..ecrit).unwrap_or_default();
        let mut relu = vec![GARDE; ecrit.saturating_add(64)];
        let retour = {
            let place = relu
                .get_mut(..ecrit)
                .expect("le décodage ne grandit jamais");
            decode_xtext(sur_le_fil, place).expect("un xtext qu'on vient d'écrire se relit")
        };
        assert_eq!(
            retour,
            decode,
            "l'aller-retour a changé la valeur : {:?}",
            String::from_utf8_lossy(decode)
        );
    }

    // ── `ORCPT` (§4.2) ──────────────────────────────────────────────────────
    let mut sortie = vec![GARDE; ORCPT_MAX.saturating_add(64)];
    let issue = {
        let place = sortie
            .get_mut(..ORCPT_MAX)
            .expect("le tampon fait au moins `ORCPT_MAX`");
        parse_orcpt(entree, place)
            .map(|(type_adresse, adresse)| (type_adresse.len(), adresse.len()))
    };
    assert!(
        sortie
            .get(ORCPT_MAX..)
            .is_some_and(|bord| bord.iter().all(|octet| *octet == GARDE)),
        "écrit au-delà de la place donnée"
    );
    let Ok((type_len, adresse_len)) = issue else {
        return;
    };
    assert!(type_len > 0 && adresse_len > 0, "un `ORCPT` vide est passé");
    assert!(
        sortie
            .get(..adresse_len)
            .is_some_and(|vue| vue.iter().all(u8::is_ascii_graphic)),
        "une adresse d'origine qui ouvrirait une seconde ligne"
    );
    // Le TYPE ne se décode pas : §4.2 le veut en clair, et il est fait de
    // lettres, de chiffres et de tirets.
    assert!(
        entree.get(..type_len).is_some_and(|vue| vue
            .iter()
            .all(|octet| octet.is_ascii_alphanumeric() || *octet == b'-')),
        "un type d'adresse qui n'en est pas un"
    );
});
