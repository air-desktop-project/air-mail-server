// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les entiers de §16 et les numéros de paquet de §17.1.**
//!
//! # Pourquoi celle-ci
//!
//! Tout QUIC repose sur ces deux calculs. Un entier mal lu décale le reste du
//! paquet, et un numéro de paquet mal reconstruit fait déchiffrer avec le
//! mauvais nonce — le paquet est alors jeté sans un mot, et la connexion
//! s'éteint sans que rien ne dise pourquoi. Ce sont les deux endroits où une
//! erreur ne se voit pas.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN ENTIER LU TIENT DANS CE QU'ON A DONNÉ**, et sa longueur est celle que
//!    ses deux bits de tête annoncent. Rendre davantage ferait consommer à
//!    l'appelant des octets qu'il n'a pas.
//! 3. **CE QU'ON ÉCRIT SE RELIT**, et se réécrit identique. L'écriture n'est pas
//!    canonique — §16 le dit — mais la NÔTRE l'est : on écrit toujours au plus
//!    court, et deux écritures d'un même nombre ne peuvent donc pas différer.
//! 4. **UNE ÉCRITURE LONGUE SE LIT COMME LA COURTE.** C'est le contraire de
//!    HPACK, et le refuser refuserait des paquets conformes.
//! 5. **UN NUMÉRO DE PAQUET ÉCRIT ASSEZ LONG SE RECONSTRUIT EXACTEMENT.** C'est
//!    la propriété qui compte, et la seule qui protège la connexion.
//! 6. **UN NUMÉRO RECONSTRUIT RESTE DANS L'ESPACE** : jamais sous zéro, jamais
//!    au-delà de 2^62 - 1, quels que soient les bits reçus.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_quic::{
    PACKET_NUMBER_MAX, PACKET_NUMBER_OCTETS_MAX, VARINT_MAX, packet_numbers, varints,
};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Des octets bruts, tels qu'ils arriveraient du réseau.
    brut: &'a [u8],
    /// Une valeur à écrire puis relire.
    valeur: u64,
    /// Un numéro de paquet, et ce que le pair a acquitté.
    numero: u64,
    acquitte: Option<u64>,
    /// Ce qu'un paquet portait, et sur combien d'octets.
    tronque: u32,
    octets: u8,
}

fuzz_target!(|entree: Entree| {
    // PROPRIÉTÉ 2 : un entier lu tient dans ce qu'on a donné.
    if let Ok((valeur, lus)) = varints::decode(entree.brut) {
        assert!(lus >= 1 && lus <= 8, "une longueur impossible : {lus}");
        assert!(
            lus <= entree.brut.len(),
            "on a lu {lus} octets pour {}",
            entree.brut.len()
        );
        assert!(
            valeur <= VARINT_MAX,
            "un entier hors de l'espace : {valeur}"
        );
        // La longueur est celle que les deux bits de tête annoncent, et rien
        // d'autre ne la dit : c'est ce qui interdit la contrebande.
        let annonce = entree.brut.first().copied().unwrap_or(0) >> 6;
        assert_eq!(lus, 1_usize << annonce, "la longueur ne suit pas l'annonce");

        // PROPRIÉTÉ 4 : réécrite au plus court, la valeur se relit pareil.
        let mut court = [0_u8; 8];
        let ecrits = varints::encode(valeur, &mut court).expect("une valeur lue se réécrit");
        let (relue, _) = varints::decode(&court).expect("ce qu'on écrit se relit");
        assert_eq!(relue, valeur, "un aller-retour a changé la valeur");
        assert!(
            ecrits <= lus,
            "notre écriture est plus longue que la sienne"
        );
    }

    // PROPRIÉTÉ 3 : ce qu'on écrit se relit, et se réécrit identique.
    let valeur = entree.valeur & VARINT_MAX;
    let mut ecrit = [0_u8; 8];
    let ecrits = varints::encode(valeur, &mut ecrit).expect("sous la borne");
    assert_eq!(
        ecrits,
        varints::encoded_len(valeur).expect("mesurable"),
        "la mesure et l'écriture ne s'accordent pas"
    );
    let (relue, lus) = varints::decode(&ecrit).expect("relisible");
    assert_eq!(relue, valeur);
    assert_eq!(lus, ecrits);
    let mut deux = [0_u8; 8];
    let encore = varints::encode(relue, &mut deux).expect("réécrivable");
    assert_eq!(encore, ecrits, "notre écriture n'est pas déterministe");
    assert_eq!(
        deux.get(..encore),
        ecrit.get(..ecrits),
        "notre écriture n'est pas déterministe"
    );

    // PROPRIÉTÉ 5 : un numéro écrit assez long se reconstruit exactement.
    let numero = entree.numero & PACKET_NUMBER_MAX;
    let acquitte = entree.acquitte.map(|vu| vu.min(numero));
    if let Ok(taille) = packet_numbers::encoded_len(numero, acquitte) {
        assert!(taille >= 1 && taille <= PACKET_NUMBER_OCTETS_MAX);
        let mut place = [0_u8; PACKET_NUMBER_OCTETS_MAX];
        let poses = packet_numbers::encode(numero, taille, &mut place).expect("écrivable");
        let mut vu = 0_u64;
        for lu in place.get(..poses).unwrap_or_default() {
            vu = vu.saturating_mul(256).saturating_add(u64::from(*lu));
        }
        // Le receveur a traité tout ce qui précède : c'est le cas que la RFC
        // décrit, et celui où la reconstruction doit être exacte.
        let largest = numero.checked_sub(1);
        let relu = packet_numbers::decode(largest, vu, taille).expect("reconstruit");
        assert_eq!(relu, numero, "un numéro écrit assez long s'est perdu");
    }

    // PROPRIÉTÉ 6 : quels que soient les bits reçus, on reste dans l'espace.
    let octets = usize::from(entree.octets % 6);
    if let Ok(relu) = packet_numbers::decode(entree.acquitte, u64::from(entree.tronque), octets) {
        assert!(
            relu <= PACKET_NUMBER_MAX,
            "un numéro reconstruit est sorti de l'espace : {relu}"
        );
    }
});
