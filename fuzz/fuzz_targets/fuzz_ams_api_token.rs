// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les jetons porteurs de l'API REST.**
//!
//! # Pourquoi celle-ci
//!
//! Un jeton est ce qu'un attaquant contrôle entièrement, et ce qui décide de
//! tout : il porte le compte pour qui il vaut et les pouvoirs qu'il ouvre. Une
//! seule suite d'octets qui se ferait accepter sans avoir été scellée
//! donnerait tous les pouvoirs qu'elle s'attribue.
//!
//! Et le danger n'est pas seulement la contrefaçon. Deux écritures d'un même
//! jeton, un champ lu avant d'être authentifié, une longueur qui ment : chacune
//! ouvre une porte différente, et aucune ne se voit à l'exécution.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets présentés.
//! 2. **RIEN NE SE VÉRIFIE SANS AVOIR ÉTÉ SCELLÉ AVEC LA BONNE CLÉ.** C'est la
//!    propriété entière : des octets arbitraires ne doivent jamais passer, et
//!    ceux scellés avec une autre clé non plus.
//! 3. **CE QU'ON SCELLE SE RELIT EXACTEMENT** — compte, portées, expiration,
//!    identifiant. Un aller-retour qui perdrait un bit de portée donnerait un
//!    pouvoir qu'on n'a pas accordé.
//! 4. **UN SEUL OCTET CHANGÉ SUFFIT À LE REFUSER**, où qu'il soit dans
//!    l'écriture.
//! 5. **UN JETON N'OUVRE JAMAIS PLUS QUE SA PORTÉE** : `authorize` n'accorde que
//!    ce que `contains` accorde, et un jeton vide n'ouvre rien.
//! 6. **UNE ÉCRITURE NON CANONIQUE SE REFUSE** (§3.5 de RFC 4648) : sans cela,
//!    plusieurs écritures désignent le même jeton, et une révocation cesse de
//!    reconnaître ce qu'elle a révoqué.
//! 7. **UN JETON EXPIRÉ NE SE VÉRIFIE JAMAIS**, quelle que soit l'heure qu'on
//!    présente.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_api::{
    Area, ENCODED_OCTETS_MAX, Key, LIFETIME_MAX_US, LOGIN_OCTETS_MAX, Reason, Rights, Scope,
    TOKEN_OCTETS_MAX, Token, authorize, bearer, issue, verify,
};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Des octets bruts, tels qu'un client les présenterait.
    presente: &'a [u8],
    /// La clé du serveur.
    clef: [u8; 32],
    /// Une autre clé, qui ne doit rien ouvrir de la première.
    autre: [u8; 32],
    /// Un compte, ses pouvoirs, son heure et son identifiant.
    login: &'a str,
    bits: u8,
    vie: u32,
    nonce: u64,
    /// L'instant qu'on présente.
    maintenant: u64,
    /// Ce que la route demande.
    voulue: u8,
    /// Le rang d'un octet à changer.
    abime: u16,
    /// Une valeur de champ `Authorization`.
    entete: &'a [u8],
}

fuzz_target!(|entree: Entree| {
    let Ok(clef) = Key::new(&entree.clef) else {
        return;
    };
    let Ok(autre) = Key::new(&entree.autre) else {
        return;
    };

    // PROPRIÉTÉ 2 : des octets arbitraires ne passent pas — sauf s'ils sont
    // exactement un jeton que cette clé a scellé, ce que le hasard ne trouve
    // pas.
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    if let Err(faute) = verify(&clef, entree.presente, entree.maintenant, &mut place) {
        assert!(
            matches!(
                faute.reason(),
                Reason::BadToken | Reason::TokenExpired | Reason::BufferTooSmall
            ),
            "une faute inattendue : {faute:?}"
        );
    }

    // On émet un jeton, si les champs le permettent.
    let expiry = entree.maintenant.saturating_add(u64::from(entree.vie));
    let attendu = Token {
        login: entree.login,
        scope: Scope::from_bits(entree.bits),
        expiry,
        nonce: entree.nonce,
    };
    let mut ecrit = [0_u8; ENCODED_OCTETS_MAX];
    let Ok(jeton) = issue(&clef, &attendu, entree.maintenant, &mut ecrit) else {
        // L'émission ne refuse que ce qu'elle a annoncé refuser.
        assert!(
            entree.login.is_empty()
                || entree.login.len() > LOGIN_OCTETS_MAX
                || expiry > entree.maintenant.saturating_add(LIFETIME_MAX_US),
            "l'émission a refusé un jeton licite : {attendu:?}"
        );
        return;
    };
    let jeton = jeton.to_vec();

    // L'écriture ne porte que l'alphabet de §5 de RFC 4648.
    assert!(
        jeton
            .iter()
            .all(|octet| octet.is_ascii_alphanumeric() || *octet == b'-' || *octet == b'_'),
        "un caractère hors alphabet est écrit"
    );

    // PROPRIÉTÉS 3 et 7 : l'aller-retour, et l'expiration.
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    match verify(&clef, &jeton, entree.maintenant, &mut place) {
        Ok(lu) => {
            assert_eq!(lu, attendu, "un aller-retour a changé le jeton");
            assert!(entree.maintenant < expiry, "un jeton expiré s'est vérifié");
            // PROPRIÉTÉ 5 : il n'ouvre jamais plus que sa portée.
            let voulue = Scope::from_bits(entree.voulue);
            assert_eq!(
                authorize(&lu, Some(voulue)).is_ok(),
                lu.scope.contains(voulue),
                "l'autorisation ne suit pas la portée"
            );
            assert!(authorize(&lu, None).is_ok(), "ce qui n'exige rien passe");
            // Un jeton vide n'ouvre aucun domaine.
            if lu.scope == Scope::none() {
                for area in Area::TOUS {
                    assert!(authorize(&lu, Some(Scope::one(area, Rights::Read))).is_err());
                }
            }
        }
        Err(faute) => assert_eq!(
            faute.reason(),
            Reason::TokenExpired,
            "un jeton qu'on vient d'émettre ne se vérifie pas"
        ),
    }

    // PROPRIÉTÉ 7 : passé l'expiration, jamais.
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    if let Ok(lu) = verify(&clef, &jeton, expiry, &mut place) {
        panic!("un jeton s'est vérifié à son heure d'expiration : {lu:?}");
    }
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    assert!(
        verify(&clef, &jeton, u64::MAX, &mut place).is_err(),
        "un jeton s'est vérifié à la fin des temps"
    );

    // PROPRIÉTÉ 2 : une autre clé n'ouvre rien.
    if entree.clef != entree.autre {
        let mut place = [0_u8; TOKEN_OCTETS_MAX];
        let faute = verify(&autre, &jeton, entree.maintenant, &mut place)
            .expect_err("une autre clé a ouvert le jeton");
        assert_eq!(faute.reason(), Reason::BadToken);
    }

    // PROPRIÉTÉ 4 : un seul octet changé suffit.
    if !jeton.is_empty() {
        let rang = usize::from(entree.abime) % jeton.len();
        let mut abime = jeton.clone();
        abime[rang] = match abime[rang] {
            b'A' => b'B',
            _ => b'A',
        };
        if abime != jeton {
            let mut place = [0_u8; TOKEN_OCTETS_MAX];
            assert!(
                verify(&clef, &abime, entree.maintenant, &mut place).is_err(),
                "l'octet {rang} a été changé et le jeton passe encore"
            );
        }
    }

    // PROPRIÉTÉ 6 : le remplissage ajouté ne fait pas une seconde écriture.
    for suffixe in [&b"="[..], b"==", b"A", b" "] {
        let mut avec = jeton.clone();
        avec.extend_from_slice(suffixe);
        let mut place = [0_u8; TOKEN_OCTETS_MAX];
        assert!(
            verify(&clef, &avec, entree.maintenant, &mut place).is_err(),
            "une seconde écriture du même jeton est passée : {suffixe:?}"
        );
    }

    // Le champ `Authorization` : ce qu'il rend est toujours une part de ce
    // qu'on lui a donné, et ne porte jamais d'espace.
    if let Ok(porte) = bearer(entree.entete) {
        assert!(!porte.is_empty(), "un jeton vide est passé");
        assert!(!porte.contains(&b' '), "un jeton avec une espace est passé");
        assert!(
            porte.len() < entree.entete.len(),
            "le schéma n'a pas été ôté"
        );
    }
    // Et notre propre écriture s'y relit.
    let mut entete = std::vec::Vec::from(&b"Bearer "[..]);
    entete.extend_from_slice(&jeton);
    assert_eq!(
        bearer(&entete),
        Ok(jeton.as_slice()),
        "notre propre en-tête ne se relit pas"
    );
});
