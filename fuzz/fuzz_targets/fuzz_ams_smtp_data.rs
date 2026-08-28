//! Fuzz : la phase de données SMTP — **le découpage des lectures ne change rien**.
//!
//! # La propriété qui vise la contrebande SMTP
//!
//! La faille de 2023 ne tient pas à un débordement : elle tient à ce que deux
//! lecteurs ne coupent pas le même flux au même endroit. C'est donc l'INDÉPENDANCE
//! AU DÉCOUPAGE qu'il faut éprouver, et pas seulement l'absence de panique.
//!
//! Cette cible lit chaque flux **deux fois** : une fois d'un seul tenant, une fois
//! par tranches arbitraires — dont des tranches d'un octet, qui coupent au milieu
//! d'un `CRLF` ou d'un terminateur. Les deux lectures doivent rendre exactement le
//! même verdict et exactement les mêmes octets.
//!
//! Un décodeur qui, sur `\r\n.\r` suivi de `\n` dans une autre lecture, conclurait
//! autrement que sur `\r\n.\r\n` d'un coup, échouerait ici. C'est précisément la
//! divergence dont vit l'attaque.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use ams_proto_smtp::{DataEvent, DataFault, DataReceiver, Limits};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Ce qu'une lecture complète a produit.
#[derive(Debug, PartialEq, Eq)]
enum Lecture {
    /// Le message, dé-échappé.
    Message(Vec<u8>),
    /// Le flux s'est arrêté sans `<CRLF>.<CRLF>`.
    Tronque(Vec<u8>),
    /// La grammaire a refusé.
    Refus(DataFault),
}

#[derive(Debug, Arbitrary)]
struct Entree {
    flux: Vec<u8>,
    /// Le calendrier des lectures : chaque valeur donne la taille d'une tranche.
    tranches: Vec<u8>,
    max_text_line_octets: u16,
    max_message_octets: u32,
}

/// Lit `flux` en le livrant selon `calendrier`, comme le ferait une socket.
fn lire(flux: &[u8], calendrier: &[usize], limits: &Limits, max_message: u64) -> Lecture {
    let mut receveur = DataReceiver::new(limits, max_message);
    let mut sortie = Vec::new();
    let mut debut = 0_usize;
    let mut fin = 0_usize;
    let mut prochaine = 0_usize;
    loop {
        if debut == fin {
            if fin == flux.len() {
                return Lecture::Tronque(sortie);
            }
            // Une tranche nulle ne ferait pas avancer la lecture : on prend au
            // moins un octet, comme une socket qui rend au moins ce qu'elle a.
            let taille = calendrier
                .get(prochaine % calendrier.len().max(1))
                .copied()
                .unwrap_or(1)
                .max(1);
            prochaine = prochaine.wrapping_add(1);
            fin = flux.len().min(fin.saturating_add(taille));
        }
        let (evenement, consomme) = match receveur.next(&flux[debut..fin]) {
            Ok(progres) => progres,
            Err(faute) => return Lecture::Refus(faute),
        };
        match evenement {
            DataEvent::Complete => return Lecture::Message(sortie),
            DataEvent::Content(morceau) => sortie.extend_from_slice(morceau),
            DataEvent::NeedMore => {}
        }
        // L'INVARIANTE DE PROGRÈS : sans elle, une boucle réelle tournerait à
        // vide, et un pair pourrait l'y enfermer avec trois octets.
        assert!(
            consomme > 0,
            "ni consommé ni conclu sur {:?}",
            &flux[debut..fin]
        );
        assert!(consomme <= fin - debut, "consommé plus que fourni");
        debut = debut.saturating_add(consomme);
    }
}

fuzz_target!(|entree: Entree| {
    let limits = Limits {
        max_text_line_octets: usize::from(entree.max_text_line_octets),
        ..Limits::DEFAULT
    };
    let max_message = u64::from(entree.max_message_octets);

    let calendrier: Vec<usize> = entree
        .tranches
        .iter()
        .map(|&taille| usize::from(taille))
        .collect();

    // Une lecture d'un seul tenant, et une lecture hachée.
    let entiere = lire(&entree.flux, &[usize::MAX], &limits, max_message);
    let hachee = lire(&entree.flux, &calendrier, &limits, max_message);

    // LA PROPRIÉTÉ CENTRALE. Deux lecteurs qui coupent le flux différemment
    // doivent en tirer la même chose — c'est exactement ce que la contrebande
    // SMTP exploite quand ce n'est pas le cas.
    assert_eq!(
        entiere, hachee,
        "le découpage des lectures change le résultat : {:?}",
        entree.flux
    );

    let (Lecture::Message(message) | Lecture::Tronque(message)) = &entiere else {
        return;
    };

    // AUCUN CR NI LF ISOLÉ N'A SURVÉCU dans ce qui a été accepté.
    let mut precedent = None;
    for (rang, &octet) in message.iter().enumerate() {
        if octet == b'\n' {
            assert_eq!(precedent, Some(b'\r'), "LF isolé à l'offset {rang}");
        }
        if precedent == Some(b'\r') {
            assert_eq!(octet, b'\n', "CR isolé à l'offset {rang}");
        }
        precedent = Some(octet);
    }
    assert_ne!(
        precedent,
        Some(b'\r'),
        "le message se termine par un CR isolé"
    );

    // LE MESSAGE NE PEUT PAS ÊTRE PLUS LONG QUE CE QUI A ÉTÉ LU.
    assert!(message.len() <= entree.flux.len(), "octets inventés");

    // LES BORNES ANNONCÉES SONT TENUES.
    assert!(
        u64::try_from(message.len()).unwrap_or(u64::MAX) <= max_message,
        "message au-delà de la borne"
    );
    // LES LIGNES ACHEVÉES respectent la borne, CRLF compris. La DERNIÈRE tranche
    // du découpage est exclue : sur un flux tronqué, c'est une ligne que le pair
    // n'a pas fini d'envoyer, et elle n'a pas encore son CRLF. L'y soumettre
    // faisait échouer cette cible sur un octet parfaitement licite.
    let tranches: Vec<&[u8]> = message.split(|&octet| octet == b'\n').collect();
    for ligne in tranches.iter().rev().skip(1) {
        // La tranche porte encore son `CR` ; le `\n` retiré par le découpage
        // compte pour un octet de plus.
        assert!(
            ligne.len().saturating_add(1) <= limits.max_text_line_octets,
            "ligne au-delà de la borne : {ligne:?}"
        );
    }
});
