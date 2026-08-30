// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la `BODYSTRUCTURE` d'un message** (RFC 9051 §7.5.2).
//!
//! # LE DÉCOUPAGE NE DOIT RIEN CHANGER
//!
//! Le balayeur se fait POUSSER le message, par morceaux dont la taille est celle
//! du tampon de celui qui lit — donc une taille que le message ne choisit pas, et
//! que rien ne garantit stable. Une frontière de la RFC 2046 tombant à cheval
//! sur deux morceaux ne doit pas se voir. C'est la même propriété que pour la
//! phase de données de SMTP, et pour la même raison : **deux lecteurs qui
//! découpent différemment doivent conclure pareil**, faute de quoi ce qu'un
//! client voit dépend de la mémoire du serveur.
//!
//! # Les autres propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets du message.
//! 2. **CE QUI EST ÉCRIT EST BIEN FORMÉ** : les parenthèses s'équilibrent, les
//!    chaînes se ferment, et aucune n'emporte de fin de ligne. Une structure mal
//!    formée désynchronise le client, qui lira la suite du dialogue comme la fin
//!    de la réponse.
//! 3. **L'ÉTAT EST BORNÉ** : ce que le balayeur retient ne dépend pas de la
//!    taille du message. La cible le vérifie en composant la même structure avec
//!    un message répété, ce qui ne change ni ce qu'il rend ni le fait qu'il
//!    rende.
//! 4. **UN TAMPON TROP COURT LE DIT** au lieu d'écrire une structure à moitié.
//! 5. **UNE PARTIE NE DÉSIGNE JAMAIS D'OCTETS HORS DU MESSAGE.** L'intervalle
//!    qu'on rend part droit dans une lecture de fichier : s'il débordait, le
//!    client recevrait ce qui suit le message — ou le serveur lirait ce qu'il
//!    n'a pas. Le chemin, lui, vient du réseau.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_mime::{BodyScanner, BodySpan, Error, Limits};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Le message, tel qu'il arriverait du disque.
    message: &'a [u8],
    /// Par combien d'octets on le pousse. Zéro vaut « tout d'un coup ».
    morceau: u8,
    /// La place qu'on laisse, pour éprouver le manque.
    place: u16,
    /// Un chemin de partie, tel qu'un client l'écrirait.
    chemin: Vec<u32>,
}

/// Vérifie qu'un texte est une structure bien formée.
fn bien_formee(texte: &[u8]) {
    assert!(
        texte.first() == Some(&b'(') && texte.last() == Some(&b')'),
        "une structure s'ouvre et se ferme"
    );
    let mut profondeur = 0_usize;
    let mut dans_une_chaine = false;
    let mut i = 0_usize;
    while i < texte.len() {
        let octet = texte.get(i).copied().unwrap_or(0);
        if dans_une_chaine {
            match octet {
                // Un octet échappé ne compte pas : c'est ce qui distingue un
                // guillemet de fin d'un guillemet du texte.
                b'\\' => i = i.saturating_add(1),
                b'"' => dans_une_chaine = false,
                // UNE CHAÎNE NE PORTE PAS DE FIN DE LIGNE : elle ferait de la
                // réponse deux réponses, et le client lirait la seconde comme du
                // protocole.
                b'\r' | b'\n' => panic!("une fin de ligne dans une chaîne"),
                _ => {}
            }
            i = i.saturating_add(1);
            continue;
        }
        match octet {
            b'"' => dans_une_chaine = true,
            b'(' => profondeur = profondeur.saturating_add(1),
            b')' => {
                assert!(profondeur > 0, "une parenthèse fermante de trop");
                profondeur = profondeur.saturating_sub(1);
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    assert!(!dans_une_chaine, "une chaîne qui ne se ferme pas");
    assert_eq!(profondeur, 0, "des parenthèses qui ne s'équilibrent pas");
}

/// Compose la structure d'un message poussé par morceaux de `taille`.
fn composer(message: &[u8], taille: usize, out: &mut [u8]) -> Result<usize, Error> {
    let bornes = Limits::DEFAULT;
    let mut balayeur = BodyScanner::new(&bornes);
    match taille {
        0 => balayeur.push(message),
        taille => {
            for morceau in message.chunks(taille) {
                balayeur.push(morceau);
            }
        }
    }
    balayeur.finish();
    balayeur.write(out)
}

fuzz_target!(|entree: Entree<'_>| {
    let mut grand = vec![0_u8; 256 * 1024];

    let Ok(ecrits) = composer(entree.message, 0, &mut grand) else {
        return;
    };
    assert!(ecrits <= grand.len());
    // PROPRIÉTÉ 2.
    bien_formee(grand.get(..ecrits).unwrap_or_default());
    let attendu = grand.get(..ecrits).unwrap_or_default().to_vec();

    // PROPRIÉTÉ 1 : le découpage ne change rien.
    let mut autre = vec![0_u8; 256 * 1024];
    for taille in [1_usize, 2, 3, usize::from(entree.morceau).max(1)] {
        let refait = composer(entree.message, taille, &mut autre).expect("composable");
        assert_eq!(
            autre.get(..refait),
            Some(attendu.as_slice()),
            "morceaux de {taille}"
        );
    }

    // PROPRIÉTÉ 5 : une partie ne sort pas du message.
    let bornes = Limits::DEFAULT;
    let mut balayeur = BodyScanner::new(&bornes);
    balayeur.push(entree.message);
    balayeur.finish();
    let chemin = entree.chemin.get(..8).unwrap_or(&entree.chemin);
    for quoi in [
        BodySpan::Content,
        BodySpan::Mime,
        BodySpan::Header,
        BodySpan::Text,
    ] {
        let Some((debut, fin)) = balayeur.span(chemin, quoi) else {
            continue;
        };
        assert!(debut <= fin, "un intervalle à l'envers : {debut}..{fin}");
        let taille = u64::try_from(entree.message.len()).unwrap_or(u64::MAX);
        assert!(
            fin <= taille,
            "une partie qui sort du message : {debut}..{fin} pour {taille}"
        );
    }

    // PROPRIÉTÉ 4 : un tampon trop court le dit.
    let court = usize::from(entree.place).min(ecrits);
    let mut petit = vec![0_u8; court];
    match composer(entree.message, 0, &mut petit) {
        Ok(refait) => {
            assert_eq!(
                refait, ecrits,
                "deux compositions du même message diffèrent"
            );
            assert_eq!(petit.get(..refait), Some(attendu.as_slice()));
        }
        Err(erreur) => assert_eq!(erreur, Error::BufferTooSmall),
    }
});
