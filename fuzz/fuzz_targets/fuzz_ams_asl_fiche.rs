// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la fiche d'identité d'une machine** — l'écriture et la lecture.
//!
//! # Pourquoi celle-ci
//!
//! Ce fichier porte **la moitié privée de la clé d'une machine**, et c'est le
//! seul secret durable que ce serveur tienne pour `air-service-locator`. Une
//! lecture fautive n'y produit pas un refus : elle produit **une autre clé**,
//! avec laquelle le serveur signerait sans que rien ne cloche — et l'annuaire
//! refuserait son annonce sans pouvoir dire pourquoi.
//!
//! Et ce format n'est pas le nôtre : il est celui qu'écrit `asl enroll`. Le
//! fichier vient donc du disque d'un tiers, et peut être tronqué par un disque
//! plein, modifié à la main, ou recopié à moitié.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets — y compris de l'UTF-8
//!    mal formé, qui arrive dès qu'un éditeur se trompe d'encodage.
//! 2. **CE QU'ON ÉCRIT SE RELIT À L'IDENTIQUE** : la même machine, le même
//!    compte, et surtout **la même clé publique** — c'est-à-dire la même graine.
//! 3. **AUCUNE TRONCATURE NE REND UNE AUTRE IDENTITÉ.** C'est la propriété qui
//!    compte : un fichier abîmé doit se refuser, jamais dériver une seconde clé.
//!    Un refus est sans danger ; une clé différente est une panne muette.
//! 4. **CE QUI NE DIT RIEN NE CHANGE RIEN** : des lignes vides, des
//!    commentaires et des lignes sans `=`, insérés n'importe où, ne changent pas
//!    ce qui est lu.
//! 5. **LA DERNIÈRE OCCURRENCE GAGNE**, comme chez `asl` — une divergence ici
//!    ferait que le même fichier voudrait dire deux choses selon le programme
//!    qui le lit.
//! 6. **UN TAMPON TROP COURT LAISSE UN PRÉFIXE, ET RIEN D'AUTRE** : l'écriture
//!    refuse, et ce qui reste dans le tampon se lit comme la MÊME identité ou
//!    ne se lit pas.
//!
//! # CE QUE CETTE CIBLE A TROUVÉ LE 2026-10-08, À SA PREMIÈRE CAMPAGNE
//!
//! Sa propriété 6 disait d'abord « un refus ne laisse RIEN de lisible ». Elle
//! est tombée en cinquante secondes, et sur deux choses à la fois.
//!
//! **La propriété était trop forte.** À une taille précise, tout tient sauf le
//! saut de ligne final — et une fiche sans son dernier saut de ligne se lit
//! parfaitement : `lines()` n'en exige pas. Le refus est juste (on n'écrira pas
//! ce qu'on a promis d'écrire), et le reste est lisible et exact.
//!
//! **Mais le code avait un vrai défaut.** L'écrivain continuait après avoir
//! débordé : une écriture plus COURTE qui suivait une refusée tenait dans la
//! place restante et se posait **là où la refusée aurait dû commencer**. Le
//! tampon ne portait alors pas un préfixe, mais un mélange — les paires
//! hexadécimales de la graine derrière le compte, sans leur clé `graine = `.
//! Rien de lisible n'en sortait, par chance et non par construction.
//!
//! L'écrivain s'arrête désormais au premier débordement, et c'est ce qui rend
//! la propriété 6 vraie et éprouvable.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_asl::fiche::{GRAINE_OCTETS, ecrire_une_fiche, lire_une_fiche};
use ams_asl::{FICHE_OCTETS_MAX, Faute};
use asl_id::{Genre, Identifiant};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Une fiche telle qu'elle pourrait arriver du disque.
    brute: &'a [u8],
    /// De quoi composer une fiche licite, puis la relire.
    entropie_machine: [u8; 16],
    entropie_compte: [u8; 16],
    graine: [u8; GRAINE_OCTETS],
    /// Le compte y est-il ?
    avec_compte: bool,
    /// Des lignes à glisser dans la fiche, qui ne doivent rien changer.
    bruit: [&'a str; 3],
    /// La taille du tampon d'écriture, pour éprouver le refus.
    tampon: u16,
}

fuzz_target!(|entree: Entree| {
    // PROPRIÉTÉ 1 : rien ne panique sur des octets quelconques. Une fiche du
    // disque n'est pas forcément de l'UTF-8 ; ce qui ne l'est pas ne se lit
    // pas, et ce n'est pas une panne.
    if let Ok(texte) = core::str::from_utf8(entree.brute) {
        let _ = lire_une_fiche(texte);
    }

    let machine = Identifiant::depuis_entropie(Genre::Machine, entree.entropie_machine);
    let compte = entree
        .avec_compte
        .then(|| Identifiant::depuis_entropie(Genre::Utilisateur, entree.entropie_compte));

    // PROPRIÉTÉ 6 : un tampon trop court refuse, et n'écrit pas à moitié.
    let taille = usize::from(entree.tampon) % (FICHE_OCTETS_MAX.saturating_add(1));
    let mut court = vec![0_u8; taille];
    let refus = ecrire_une_fiche(machine, compte, &entree.graine, &mut court);
    match refus {
        Err(Faute::TamponTropCourt) => {}
        Err(autre) => panic!("une écriture ne refuse que par le tampon : {autre:?}"),
        Ok(combien) => assert!(combien <= taille, "l'écrivain a dépassé son tampon"),
    }

    // PROPRIÉTÉ 2 : l'aller-retour, sur un tampon qui suffit toujours.
    let mut place = [0_u8; FICHE_OCTETS_MAX];
    let combien = ecrire_une_fiche(machine, compte, &entree.graine, &mut place)
        .expect("FICHE_OCTETS_MAX suffit à toute fiche");
    let ecrite = core::str::from_utf8(place.get(..combien).unwrap_or_default())
        .expect("ce que nous écrivons est de l'UTF-8");

    let relue = lire_une_fiche(ecrite).expect("ce que nous écrivons se relit");
    assert_eq!(relue.identite.machine(), machine, "la machine a changé");
    assert_eq!(relue.compte, compte, "le compte a changé");
    let publique = relue.identite.publique();

    // PROPRIÉTÉ 6 : ce que le tampon trop court a laissé est un PRÉFIXE, donc
    // la même identité ou rien. On le vérifie ici, et non plus haut, parce
    // qu'il faut la fiche entière pour savoir quelle identité comparer.
    if refus.is_err() {
        if let Ok(texte) = core::str::from_utf8(&court) {
            if let Ok(lue) = lire_une_fiche(texte) {
                assert_eq!(
                    lue.identite.machine(),
                    machine,
                    "une écriture refusée a laissé une AUTRE machine"
                );
                assert_eq!(
                    lue.identite.publique().octets(),
                    relue.identite.publique().octets(),
                    "une écriture refusée a laissé une AUTRE clé"
                );
            }
        }
    }

    // PROPRIÉTÉ 3 : aucune troncature ne rend une AUTRE identité.
    for coupe in 0..ecrite.len() {
        let Some(tronquee) = ecrite.get(..coupe) else {
            // Une coupe au milieu d'un caractère multioctet : il y en a, les
            // commentaires portent un tiret cadratin. Rien à éprouver.
            continue;
        };
        if let Ok(lue) = lire_une_fiche(tronquee) {
            assert_eq!(
                lue.identite.machine(),
                machine,
                "une troncature à {coupe} octets a rendu une AUTRE machine"
            );
            assert_eq!(
                lue.identite.publique().octets(),
                publique.octets(),
                "une troncature à {coupe} octets a rendu une AUTRE clé"
            );
        }
    }

    // PROPRIÉTÉ 4 : ce qui ne dit rien ne change rien.
    let mut bruitee = String::new();
    for ligne in entree.bruit {
        // Une ligne de bruit qui porterait un `=` et l'une des trois clés
        // DIRAIT quelque chose — et la propriété 5 veut qu'elle gagne. On ne
        // garde donc ici que ce qui ne dit rien, par construction.
        if ligne.contains('=') || ligne.contains('\n') || ligne.contains('\r') {
            continue;
        }
        bruitee.push('#');
        bruitee.push_str(ligne);
        bruitee.push('\n');
        bruitee.push('\n');
        bruitee.push_str(ligne);
        bruitee.push('\n');
    }
    bruitee.push_str(ecrite);
    let lue = lire_une_fiche(&bruitee).expect("du bruit qui ne dit rien ne change rien");
    assert_eq!(lue.identite.machine(), machine);
    assert_eq!(lue.identite.publique().octets(), publique.octets());

    // PROPRIÉTÉ 5 : la dernière occurrence gagne. On met devant une fiche
    // ENTIÈRE et licite, portant une autre machine : c'est la nôtre, derrière,
    // qui doit être lue.
    let autre = Identifiant::depuis_entropie(Genre::Machine, [0x00; 16]);
    let mut doublee = [0_u8; FICHE_OCTETS_MAX];
    let devant = ecrire_une_fiche(autre, None, &[0xff; GRAINE_OCTETS], &mut doublee)
        .expect("FICHE_OCTETS_MAX suffit");
    let mut deux = String::from(
        core::str::from_utf8(doublee.get(..devant).unwrap_or_default()).expect("de l'UTF-8"),
    );
    deux.push_str(ecrite);
    let lue = lire_une_fiche(&deux).expect("deux fiches à la suite se lisent");
    assert_eq!(
        lue.identite.machine(),
        machine,
        "LA PREMIÈRE OCCURRENCE A GAGNÉ : `asl` lit l'autre, et le même fichier \
         voudrait dire deux choses"
    );
    assert_eq!(
        lue.identite.publique().octets(),
        publique.octets(),
        "la graine de devant a gagné"
    );
});
