// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le cadrage HTTP/3**, les types de flux et les réglages.
//!
//! # Pourquoi celle-ci
//!
//! Le cadrage d'HTTP/3 est ce qui décide où un message s'arrête, comme celui
//! d'HTTP/2. Mais il repose sur des entiers de longueur variable, et une trame
//! peut annoncer 2^62 octets là où un `usize` en tient 2^32 : les endroits où
//! l'on convertit sont exactement ceux où l'on peut se tromper de taille.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN EN-TÊTE LU TIENT DANS CE QU'ON A DONNÉ** : sa propre longueur ne
//!    dépasse jamais le tampon, et la mesure totale n'est jamais inférieure à
//!    l'en-tête seul.
//! 3. **LES TYPES QU'HTTP/2 EMPLOYAIT NE PASSENT JAMAIS** (§11.2.1) : les
//!    recevoir veut dire qu'un pair parle le mauvais protocole, et ce qui suit
//!    ne sera pas ce qu'on croit.
//! 4. **UNE TRAME N'A SA PLACE QUE LÀ OÙ §7.2 LA MET**, et un type inconnu a sa
//!    place partout — c'est ce qui le rend ignorable.
//! 5. **DES RÉGLAGES ACCEPTÉS SE RÉÉCRIVENT ET SE RELISENT IDENTIQUES.** Sans
//!    cela, ce qu'on croit avoir négocié ne serait pas ce que le pair a dit.
//! 6. **UN TYPE DE FLUX SE LIT OU SE RAPPELLE**, jamais autre chose : un flux
//!    QUIC livre par morceaux, et refuser un type incomplet refuserait un pair
//!    qui n'a rien fait de mal.
//! 7. **UNE LIGNE DE CHAMP QPACK CONSOMME AU MOINS UN OCTET**, jamais plus
//!    qu'on ne lui en a donné, et ce qu'elle rend tient dans le tampon. Un
//!    décodeur qui n'avance pas boucle sans fin ; un décodeur qui avance trop
//!    lit la ligne suivante comme la sienne.
//! 8. **UN COMPTE D'INSERTIONS RECONSTRUIT RESTE DANS SA FENÊTRE**, et le rang
//!    de la section ne descend jamais sous zéro. Se tromper de tour décalerait
//!    toute la table, sans qu'aucune faute ne se voie.
//! 9. **AUCUNE INSERTION NE PASSE QUAND ON ANNONCE UNE TABLE NULLE** (§3.2.3) :
//!    c'est ce qui ferme d'un coup le blocage de compression et CRIME à la
//!    réception, et une seule qui passerait rouvrirait les deux.
//! 10. **CE QU'ON ÉCRIT SUR LE FLUX DE DÉCODEUR SE RELIT IDENTIQUE.**
//! 11. **UNE SECTION ACCEPTÉE FAIT UNE REQUÊTE COMPLÈTE**, et une réponse
//!     écrite se relit comme la réponse qu'on a voulue. Sans cela, ce qu'on
//!     croit servir ne serait pas ce que le client reçoit.

#![no_main]

use libfuzzer_sys::fuzz_target;

use ams_proto_h3::qpack::{
    EncoderInstruction, FieldLine, check_encoder_instruction, max_entries,
    read_decoder_instruction, read_encoder_instruction, read_field_line, read_prefix, read_section,
    write_decoder_instruction,
};
use ams_proto_h3::{
    FrameHeader, FrameKind, Placement, Reason, Settings, StreamHead, StreamKind, accept_stream,
    read_stream_head,
};
use ams_proto_http::Limits;

fuzz_target!(|donnees: &[u8]| {
    // PROPRIÉTÉS 2, 3 et 4 : l'en-tête de trame.
    match FrameHeader::parse(donnees) {
        Ok(entete) => {
            assert!(
                entete.header_len() <= donnees.len(),
                "un en-tête plus long que le tampon"
            );
            assert!(entete.header_len() >= 2, "deux entiers font deux octets");
            assert!(
                entete.total() >= entete.length(),
                "la mesure oublie l'en-tête"
            );
            // Le type ne fait jamais partie de ceux qu'HTTP/2 employait.
            assert!(
                !FrameKind::RESERVES_PAR_HTTP2.contains(&entete.kind().value()),
                "un type réservé est passé"
            );
            // Un inconnu a sa place partout ; les autres, seulement là où §7.2
            // les met.
            let requete = entete.check_stream(Placement::Request).is_ok();
            let controle = entete.check_stream(Placement::Control).is_ok();
            if matches!(entete.kind(), FrameKind::Unknown(_)) {
                assert!(
                    requete && controle,
                    "un inconnu n'est pas ignorable partout"
                );
            } else {
                assert!(
                    !(requete && controle),
                    "un type connu ne va pas sur les deux flux"
                );
            }
        }
        Err(faute) => {
            // Les seules fautes possibles ici sont celles-là : une troisième
            // voudrait dire qu'on a inventé une règle.
            assert!(
                matches!(faute.reason(), Reason::Truncated | Reason::ReservedH2Frame),
                "une faute inattendue : {faute:?}"
            );
        }
    }

    // PROPRIÉTÉ 5 : les réglages font un aller-retour.
    if let Ok(lus) = Settings::read(donnees) {
        let mut place = [0_u8; 64];
        let ecrits = lus.write(&mut place).expect("ce qu'on a lu se réécrit");
        let relus = Settings::read(place.get(..ecrits).unwrap_or_default())
            .expect("ce qu'on écrit se relit");
        assert_eq!(relus, lus, "un aller-retour a changé les réglages");
    }

    // PROPRIÉTÉS 7 et 8 : QPACK.
    {
        let mut place = [0_u8; 4096];
        let capacite = place.len();
        let mut libre = place.as_mut_slice();
        let mut reste = donnees;
        let mut tours = 0_u32;
        while let Ok(decode) = read_field_line(reste, libre) {
            tours = tours.saturating_add(1);
            assert!(tours < 100_000, "le décodeur de lignes n'avance pas");
            assert!(decode.read >= 1, "une ligne rendue sans consommer d'octet");
            assert!(
                decode.read <= reste.len(),
                "une ligne a consommé {} octets pour {}",
                decode.read,
                reste.len()
            );
            // Ce qu'elle rend tient dans ce qu'on a donné.
            match decode.line {
                FieldLine::Literal { name, value, .. } => {
                    assert!(name.len().saturating_add(value.len()) <= capacite);
                }
                FieldLine::LiteralWithName { value, .. }
                | FieldLine::LiteralWithPostBaseName { value, .. } => {
                    assert!(value.len() <= capacite);
                }
                FieldLine::Indexed { .. } | FieldLine::IndexedPostBase { .. } => {}
            }
            reste = reste.get(decode.read..).unwrap_or_default();
            libre = decode.rest;
            if reste.is_empty() {
                break;
            }
        }
    }

    // PROPRIÉTÉ 9 : aucune insertion ne passe avec une table nulle.
    {
        let mut place = [0_u8; 4096];
        let mut libre = place.as_mut_slice();
        let mut reste = donnees;
        let mut tours = 0_u32;
        while let Ok(decode) = read_encoder_instruction(reste, libre) {
            tours = tours.saturating_add(1);
            assert!(tours < 100_000, "le décodeur d'instructions n'avance pas");
            assert!(decode.read >= 1, "une instruction sans octet consommé");
            assert!(decode.read <= reste.len());
            let admise = check_encoder_instruction(decode.instruction, 0).is_ok();
            match decode.instruction {
                EncoderInstruction::SetCapacity { capacity } => {
                    assert_eq!(admise, capacity == 0, "seule la capacité nulle passe");
                }
                _ => assert!(!admise, "une insertion est passée sans table"),
            }
            reste = reste.get(decode.read..).unwrap_or_default();
            libre = decode.rest;
            if reste.is_empty() {
                break;
            }
        }
    }

    // PROPRIÉTÉ 10 : le flux de décodeur fait un aller-retour.
    if let Ok((instruction, lus)) = read_decoder_instruction(donnees) {
        assert!(lus >= 1 && lus <= donnees.len());
        let mut place = [0_u8; 16];
        if let Ok(ecrits) = write_decoder_instruction(instruction, &mut place) {
            let (relue, encore) = read_decoder_instruction(place.get(..ecrits).unwrap_or_default())
                .expect("ce qu'on écrit se relit");
            assert_eq!(relue, instruction, "un aller-retour a changé l'instruction");
            assert_eq!(encore, ecrits);
        }
    }

    // Le préfixe d'une section : le compte reconstruit reste dans sa fenêtre.
    for capacite in [0_u64, 32, 4_096] {
        for inserees in [0_u64, 40, 1_000_000] {
            let Ok(prefixe) = read_prefix(donnees, inserees, capacite) else {
                continue;
            };
            let plafond = inserees.saturating_add(max_entries(capacite));
            assert!(
                prefixe.required_insert_count <= plafond,
                "un compte au-delà de ce qu'on a reçu : {} pour {plafond}",
                prefixe.required_insert_count
            );
            assert!(prefixe.read >= 2, "deux entiers font deux octets");
            assert!(prefixe.read <= donnees.len());
        }
    }

    // PROPRIÉTÉ 11 : une section acceptée fait une requête complète.
    {
        let mut place = [0_u8; 4096];
        if let Ok(requete) = read_section(donnees, &mut place, &Limits::DEFAULT) {
            assert!(
                !requete.path().is_empty(),
                "une requête acceptée sans chemin"
            );
            assert!(
                !requete.scheme().is_empty(),
                "une requête acceptée sans schéma"
            );
        }
    }

    // PROPRIÉTÉ 6 : le type d'un flux se lit, ou se rappelle.
    match read_stream_head(donnees) {
        StreamHead::More => assert!(
            donnees.len() < 8,
            "un tampon de huit octets porte tout entier de §16"
        ),
        StreamHead::Ready { kind, read } => {
            assert!(read >= 1 && read <= 8, "une longueur impossible : {read}");
            assert!(read <= donnees.len());
            assert_eq!(StreamKind::from_wire(kind.value()), kind);
            // Ce qu'on conduit s'accepte ; le reste s'abandonne, et la
            // connexion, elle, survit.
            assert_eq!(accept_stream(kind).is_ok(), kind.servi());
            // Les flux critiques sont exactement ceux qu'on conduit.
            assert_eq!(kind.est_critique(), kind.servi());
        }
    }
});
