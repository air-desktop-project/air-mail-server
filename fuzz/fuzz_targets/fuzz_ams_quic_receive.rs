// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : l'ouverture d'un paquet QUIC**, de l'en-tête aux trames.
//!
//! # Pourquoi celle-ci
//!
//! C'est le premier code du serveur qu'un inconnu atteint. Le port est ouvert au
//! monde entier, et ces octets-là n'ont traversé aucune authentification — ils
//! sont lus, démasqués et déchiffrés AVANT qu'on sache à qui l'on parle.
//!
//! Les vecteurs de l'annexe A prouvent que la chaîne est juste sur deux vrais
//! paquets. Cette cible prouve qu'elle refuse proprement tout le reste.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **CE QU'ON REND EST DANS CE QU'ON A REÇU** : la charge et le paquet
//!    tiennent dans le datagramme, et la charge est dans le paquet.
//! 3. **UN PAQUET QUI S'OUVRE A CONSOMMÉ AU MOINS SON EN-TÊTE**, et jamais plus
//!    que le datagramme. Rendre zéro ferait boucler l'appelant sans fin ; rendre
//!    trop lui ferait lire le datagramme suivant comme le sien.
//! 4. **CE QUI NE S'AUTHENTIFIE PAS SE JETTE, ET NE FERME RIEN.** C'est la
//!    propriété qui empêche un tiers de fermer une connexion qui ne lui
//!    appartient pas — et la seule faute qui condamne est celle qu'on découvre
//!    APRÈS avoir déchiffré.
//! 5. **CE QU'ON A CHIFFRÉ SOI-MÊME SE ROUVRE**, et rend le clair qu'on avait.
//!    Sans cela, les quatre premières ne diraient rien : un code qui refuse tout
//!    les satisfait toutes.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_quic::{Frame, PACKET_NUMBER_MAX};
use ams_quic::{Reason, open_packet};
use ams_quic_crypto::{Keys, Role, Secret, protect};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Un datagramme, tel qu'il arriverait du réseau.
    datagramme: &'a [u8],
    /// L'identifiant que le client aurait choisi.
    destination: &'a [u8],
    /// Le plus grand numéro déjà traité.
    plus_grand: Option<u64>,
    /// La longueur d'identifiant qu'on croit avoir émise.
    identifiant: u8,
    /// Un clair à chiffrer puis à rouvrir.
    clair: &'a [u8],
    /// Le numéro de ce paquet-là.
    numero: u32,
}

fuzz_target!(|entree: Entree| {
    let destination = entree
        .destination
        .get(..20.min(entree.destination.len()))
        .unwrap_or(&[]);
    let Ok(clefs) = Secret::initial(destination, Role::Client).and_then(|s| s.keys()) else {
        return;
    };
    let plus_grand = entree.plus_grand.map(|vu| vu % PACKET_NUMBER_MAX);
    let identifiant = usize::from(entree.identifiant % 21);

    // PROPRIÉTÉS 2, 3 et 4 : ce qu'un datagramme quelconque donne.
    let mut datagramme = std::vec::Vec::from(entree.datagramme);
    let taille = datagramme.len();
    match open_packet(&mut datagramme, &clefs, plus_grand, identifiant) {
        Ok(ouvert) => {
            assert!(
                ouvert.total <= taille,
                "un paquet de {} octets pour un datagramme de {taille}",
                ouvert.total
            );
            assert!(ouvert.total >= 1, "un paquet qui n'a rien consommé");
            let fin = ouvert.payload_at.saturating_add(ouvert.payload_len);
            assert!(
                fin <= ouvert.total,
                "la charge dépasse le paquet : {fin} pour {}",
                ouvert.total
            );
            assert!(ouvert.number <= PACKET_NUMBER_MAX);
            // La charge se lit comme des trames, ou ne se lit pas — mais elle
            // ne fait rien paniquer.
            let charge = datagramme.get(ouvert.payload_at..fin).unwrap_or_default();
            let mut reste = charge;
            let mut tours = 0_u32;
            while let Ok((_, lus)) = Frame::parse(reste) {
                tours = tours.saturating_add(1);
                assert!(tours < 100_000, "le décodeur de trames n'avance pas");
                assert!(lus >= 1 && lus <= reste.len());
                reste = reste.get(lus..).unwrap_or_default();
                if reste.is_empty() {
                    break;
                }
            }
        }
        Err(faute) => {
            // PROPRIÉTÉ 4 : seule une faute découverte APRÈS le déchiffrement
            // condamne. Tout le reste se jette.
            assert_eq!(
                faute.se_jette(),
                faute.code().is_none(),
                "jeter et n'avoir pas de code doivent coïncider"
            );
            assert!(
                matches!(
                    faute.reason(),
                    Reason::NotForUs
                        | Reason::NotAuthentic
                        | Reason::ReservedBitsSet
                        | Reason::BadPacketNumber
                ),
                "une faute inattendue : {faute:?}"
            );
        }
    }

    // PROPRIÉTÉ 5 : ce qu'on a chiffré soi-même se rouvre.
    fabriquer_et_rouvrir(&clefs, u64::from(entree.numero), entree.clair, identifiant);
});

/// Fabrique un paquet à en-tête court, puis le rouvre.
fn fabriquer_et_rouvrir(clefs: &Keys, numero: u64, clair: &[u8], identifiant: usize) {
    // La charge doit porter de quoi échantillonner : quatre octets après le
    // numéro, puis seize.
    let clair = clair.get(..1_024.min(clair.len())).unwrap_or(&[]);
    let mut paquet = std::vec::Vec::new();
    // Forme courte, bit fixe, numéro sur quatre octets.
    paquet.push(0x43);
    paquet.extend_from_slice(&std::vec![0xcd_u8; identifiant]);
    let numero_a = paquet.len();
    let tronque = u32::try_from(numero & 0xffff_ffff).unwrap_or(0);
    paquet.extend_from_slice(&tronque.to_be_bytes());
    let fin_du_numero = paquet.len();
    paquet.extend_from_slice(clair);
    paquet.extend_from_slice(&[0_u8; 16]);

    let (aad, corps) = paquet.split_at_mut(fin_du_numero);
    let Ok(ecrits) = clefs.seal(numero, aad, corps, clair.len()) else {
        return;
    };
    paquet.truncate(fin_du_numero.saturating_add(ecrits));
    if protect(clefs, &mut paquet, numero_a, 4).is_err() {
        // Trop court pour un échantillon : §5.4.2 le dit, et l'on n'en fabrique
        // pas un.
        return;
    }

    // Le receveur a traité tout ce qui précède : c'est le cas où la
    // reconstruction doit être exacte.
    let precedent = numero.checked_sub(1);
    let total = paquet.len();
    let ouvert = open_packet(&mut paquet, clefs, precedent, identifiant)
        .expect("ce qu'on chiffre se rouvre");
    assert_eq!(ouvert.number, numero, "le numéro s'est perdu");
    assert_eq!(ouvert.total, total, "un en-tête court va jusqu'au bout");
    assert_eq!(ouvert.payload_len, clair.len());
    assert_eq!(
        paquet.get(ouvert.payload_at..ouvert.payload_at.saturating_add(ouvert.payload_len)),
        Some(clair),
        "le clair a changé"
    );
}
