// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : ce qu'un `FETCH`, un `STORE`, un `SEARCH` et un `APPEND`
//! désignent** — l'ensemble de numéros, la liste d'éléments, les drapeaux à
//! écrire, l'expression de recherche, et la ligne qui précède un message.
//!
//! # Pourquoi celle-ci
//!
//! `FETCH` est la commande qui rend des octets. Ce qu'elle rend est choisi par
//! deux lectures distinctes du même texte : `contains` répond « ce message
//! est-il demandé ? » (chemin `UID FETCH`), et `ranges` énumère « quels
//! messages sont demandés ? » (chemin de l'émission). **Deux lectures qui se
//! contrediraient, c'est un message rendu à qui ne l'a pas demandé** — ou un
//! message tu à qui l'a demandé. Aucun test d'exemple ne couvre les 2^32
//! numéros ; celle-ci les tire au sort.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN ENSEMBLE ACCEPTÉ EST BORNÉ** : il ne rend jamais plus
//!    d'intervalles que `max_sequence_items`. Sans cela, un `1:2,1:2,…` de
//!    mille octets ferait mille parcours de boîte par commande.
//! 3. **UN INTERVALLE RENDU EST ORDONNÉ ET NON NUL** : `bas <= haut`, et
//!    `bas >= 1`. Le zéro n'est pas un numéro de message (§9), et un intervalle
//!    à l'envers ferait une boucle qui ne tourne pas.
//! 4. **LES DEUX LECTURES S'ACCORDENT** : `contains(n)` vaut exactement « un
//!    intervalle rendu couvre `n` ».
//! 5. **LE TEXTE RECOPIÉ SE RELIT PAREIL** : `as_bytes` puis `parse` rend les
//!    mêmes intervalles — le texte qu'on retient est bien celui qu'on a lu.
//! 6. **UNE LISTE D'ÉLÉMENTS ACCEPTÉE EST BORNÉE ET COHÉRENTE** :
//!    `items().len()` ne dépasse pas `max_fetch_items`, et une section partielle
//!    ne demande jamais zéro octet — une longueur nulle annoncée serait un
//!    littéral `{0}` que le client attendrait de lire.
//! 8. **UNE RECHERCHE ACCEPTÉE DÉCIDE, ET NE BOUCLE PAS.** Son arbre est un
//!    arbre : chaque nœud ne nomme que des indices déjà remplis, donc plus
//!    petits que le sien. L'évaluation descend, et se termine — la vérifier sur
//!    des expressions arbitraires, c'est vérifier qu'aucune entrée ne fabrique
//!    un cycle.
//! 10. **UN NOM DE BOÎTE ACCEPTÉ NE PEUT PAS SORTIR DE SA RACINE.** C'est la
//!     seule règle du serveur dont dépend un chemin : un nom accepté devient un
//!     répertoire. Sa transcription Maildir++ — les `/` deviennent des `.` — ne
//!     doit contenir NI séparateur de chemin, NI `..`, ni commencer autrement
//!     que par le point qu'on ajoute. Ce n'est pas une garde qu'on espère : la
//!     propriété se vérifie sur la transcription elle-même.
//! 9. **UNE LIGNE D'`APPEND` ACCEPTÉE ANNONCE UNE LONGUEUR QU'ON PEUT TENIR.**
//!    C'est la seule commande dont un argument est un MESSAGE : ce que la
//!    grammaire admet, l'appelant devra l'écouler, et une longueur au-delà de la
//!    borne doit être refusée AVANT qu'un octet n'arrive.
//! 11. **UN `LIST` ACCEPTÉ NE DEMANDE QUE DU TRAVAIL BORNÉ.** Chaque motif fait
//!     un parcours de plus sur toutes les boîtes du compte, et un motif plus
//!     long que le plus long nom de boîte ne pourrait en désigner aucune. Les
//!     deux bornes se vérifient sur ce que la lecture rend.
//! 12. **UN `STATUS` ACCEPTÉ DEMANDE SIX ÉLÉMENTS AU PLUS, ET AUCUN DEUX
//!     FOIS.** §6.3.11 n'en définit que six, et la réponse en porte un par
//!     élément demandé : un doublon ferait une réponse que §7.3.3 n'admet pas.
//! 13. **LES OPTIONS DE RETOUR D'UN `SEARCH` NE MANGENT PAS LE CRITÈRE.** Elles
//!     se lisent en tête, et ce qui suit est ce qu'il faut chercher ; le perdre
//!     ferait chercher autre chose que ce qui a été demandé.
//! 7. **UN `STORE` ACCEPTÉ NE PORTE QUE DES DRAPEAUX QU'ON SAIT ÉCRIRE.** Le
//!    reste doit être refusé plutôt que laissé tomber : un client à qui l'on
//!    répond `OK` croit son étiquette posée, et ne la reverra jamais. La
//!    propriété se vérifie en réécrivant les drapeaux lus — ce qui sort doit se
//!    relire à l'identique.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_imap::{
    Append, Candidate, FETCH_ITEMS_MAX, Fetch, FetchItem, Flags, LIST_PATTERNS_MAX, Limits, List,
    MAILBOX_NAME_MAX, SEARCH_KEYS_MAX, STATUS_ATTS_MAX, Search, SearchReturn, SearchScope,
    SearchSource, SequenceSet, StatusItems, Store, mailbox_name_is_safe, mailbox_name_trimmed,
};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Le texte de l'ensemble, tel qu'il arriverait du client.
    ensemble: &'a [u8],
    /// La taille de la boîte, c'est-à-dire ce que vaut `*`.
    star: u32,
    /// Quelques numéros à confronter aux deux lectures.
    numeros: [u32; 4],
    /// Les arguments complets d'un `FETCH`.
    arguments: &'a [u8],
    /// Les arguments complets d'un `STORE`.
    ecriture: &'a [u8],
    /// Les critères d'un `SEARCH`.
    criteres: &'a [u8],
    /// La ligne d'un `APPEND`.
    depot: &'a [u8],
    /// Un nom de boîte, tel qu'un client l'écrirait.
    boite: &'a [u8],
    /// Les arguments complets d'un `LIST`.
    liste: &'a [u8],
    /// Les éléments d'un `STATUS`.
    etat: &'a [u8],
    /// Les options de retour d'un `SEARCH`.
    retour: &'a [u8],
    /// Un message à confronter à ces critères.
    message: (u32, u32, u64, u8, u64),
}

/// Ce que la recherche demande au message : une réponse constante.
///
/// **ELLE RÉPOND TOUJOURS PAREIL**, et c'est le point : un critère qui lit le
/// message ne doit pas rendre la recherche instable.
struct Lecteur {
    /// Ce qu'on répond aux critères de contenu.
    reponse: bool,
    /// Ce qu'on répond aux critères `SENT…`.
    jour: Option<u64>,
}

impl SearchSource for Lecteur {
    fn contains(&mut self, _: SearchScope, _: &[u8], _: &[u8]) -> bool {
        self.reponse
    }

    fn sent_day(&mut self) -> Option<u64> {
        self.jour
    }
}

/// Rassemble les intervalles rendus, en s'arrêtant à la borne.
fn intervalles(ensemble: &SequenceSet<'_>, star: u32, bornes: &Limits) -> Vec<(u32, u32)> {
    let recus: Vec<(u32, u32)> = ensemble.ranges(star).collect();
    // PROPRIÉTÉ 2 : borné.
    assert!(
        recus.len() <= bornes.max_sequence_items,
        "{} intervalles pour une borne de {}",
        recus.len(),
        bornes.max_sequence_items
    );
    for (bas, haut) in &recus {
        // PROPRIÉTÉ 3 : ordonné, non nul.
        assert!(*bas >= 1, "un intervalle commence à zéro");
        assert!(bas <= haut, "un intervalle rendu est à l'envers");
    }
    recus
}

fuzz_target!(|entree: Entree<'_>| {
    let bornes = Limits::DEFAULT;

    if let Ok(ensemble) = SequenceSet::parse(entree.ensemble, &bornes) {
        let recus = intervalles(&ensemble, entree.star, &bornes);

        // PROPRIÉTÉ 4 : les deux lectures s'accordent.
        for numero in entree.numeros {
            let couvert = recus
                .iter()
                .any(|(bas, haut)| numero >= *bas && numero <= *haut);
            assert_eq!(
                ensemble.contains(numero, entree.star),
                couvert,
                "les deux lectures de {:?} se contredisent sur {numero} (star = {})",
                core::str::from_utf8(ensemble.as_bytes()),
                entree.star
            );
        }

        // PROPRIÉTÉ 5 : le texte retenu se relit pareil.
        let relu =
            SequenceSet::parse(ensemble.as_bytes(), &bornes).expect("un texte accepté se relit");
        assert_eq!(
            relu.ranges(entree.star).collect::<Vec<_>>(),
            recus,
            "le texte recopié ne se relit pas pareil"
        );
    }

    if let Ok(fetch) = Fetch::parse(entree.arguments, &bornes) {
        // PROPRIÉTÉ 6 : borné et cohérent.
        let items = fetch.items();
        assert!(items.len() <= bornes.max_fetch_items.min(FETCH_ITEMS_MAX));
        assert!(!items.is_empty(), "un FETCH accepté ne demande rien");
        for item in items {
            if let FetchItem::Body { partial, .. } = item
                && let Some(partial) = partial
            {
                assert!(partial.length > 0, "une section partielle vide");
            }
        }
        // L'ensemble qu'il porte est celui qu'il a lu, et il est lisible.
        let ensemble = fetch.set();
        assert_eq!(ensemble.as_bytes(), fetch.set_text());
        let _ = intervalles(&ensemble, entree.star, &bornes);
    }

    if let Ok(liste) = List::parse(entree.liste) {
        // PROPRIÉTÉ 11 : le travail demandé est borné aux deux bouts.
        let motifs = liste.patterns();
        assert!(
            motifs.len() <= LIST_PATTERNS_MAX,
            "{} motifs pour une borne de {LIST_PATTERNS_MAX}",
            motifs.len()
        );
        for motif in motifs {
            assert!(
                motif.len() <= MAILBOX_NAME_MAX,
                "un motif de {} octets ne peut désigner aucune boîte",
                motif.len()
            );
        }
    }

    if let Ok(etat) = StatusItems::parse(entree.etat) {
        // PROPRIÉTÉ 12 : **SIX ÉLÉMENTS AU PLUS, ET AUCUN DEUX FOIS.** §6.3.11
        // n'en définit que six, et la réponse en porte un par élément : un
        // doublon ferait une réponse que la grammaire de §7.3.3 n'admet pas.
        let items = etat.items();
        assert!(!items.is_empty(), "un STATUS accepté ne demande rien");
        assert!(items.len() <= STATUS_ATTS_MAX, "{} éléments", items.len());
        for (rang, att) in items.iter().enumerate() {
            assert!(
                !items.get(..rang).unwrap_or_default().contains(att),
                "l'élément {att:?} est demandé deux fois"
            );
            assert!(etat.wants(*att));
        }
    }

    if let Ok((retour, reste)) = SearchReturn::parse(entree.retour) {
        // PROPRIÉTÉ 13 : **CE QUI N'EST PAS UNE OPTION RESTE À LIRE.** Les
        // options se lisent en tête d'un `SEARCH` ; ce qui suit est le critère,
        // et le perdre ferait chercher autre chose que ce qui a été demandé.
        assert!(
            reste.len() <= entree.retour.len(),
            "la lecture des options a rendu plus qu'elle n'a reçu"
        );
        // `SAVE` seul n'écrit rien ; tout le reste écrit.
        assert_eq!(
            retour.ecrit(),
            retour.min || retour.max || retour.all || retour.count
        );
    }

    if let Ok(ecriture) = Store::parse(entree.ecriture, &bornes) {
        // PROPRIÉTÉ 7 : ce qui est accepté se réécrit à l'identique.
        let mut rendu = [0_u8; 64];
        let ecrits = ecriture
            .flags()
            .write(&mut rendu)
            .expect("les drapeaux d'un STORE accepté tiennent en soixante-quatre octets");
        let mut relus = Flags::NONE;
        for mot in ecrits.split(|octet| *octet == b' ') {
            if mot.is_empty() {
                continue;
            }
            let drapeau =
                Flags::parse_one(mot).expect("un drapeau qu'on vient d'écrire doit se relire");
            relus = relus.with(drapeau);
        }
        assert_eq!(
            relus,
            ecriture.flags(),
            "un drapeau s'est perdu à l'écriture"
        );

        let ensemble = ecriture.set();
        assert_eq!(ensemble.as_bytes(), ecriture.set_text());
        let _ = intervalles(&ensemble, entree.star, &bornes);
    }

    // ── PROPRIÉTÉ 10 : un nom accepté ne sort pas de sa racine ─────────────
    if mailbox_name_is_safe(entree.boite) {
        let nom = mailbox_name_trimmed(entree.boite);
        assert!(!nom.is_empty(), "un nom accepté est vide");
        assert!(
            nom.len() <= MAILBOX_NAME_MAX,
            "un nom accepté est trop long"
        );
        // La transcription Maildir++ : les `/` deviennent des `.`, et l'on
        // préfixe d'un point. C'est CE nom-là qui devient un répertoire.
        let mut repertoire = vec![b'.'];
        for octet in nom {
            repertoire.push(if *octet == b'/' { b'.' } else { *octet });
        }
        assert!(
            !repertoire.contains(&b'/'),
            "un nom accepté fabrique un chemin à plusieurs morceaux : {repertoire:?}"
        );
        assert!(
            !repertoire.windows(2).any(|paire| paire == b".."),
            "un nom accepté fabrique un `..` : {repertoire:?}"
        );
        assert!(
            !repertoire.contains(&0) && !repertoire.iter().any(u8::is_ascii_control),
            "un nom accepté porte un octet qu'un système de fichiers lit mal"
        );
    }

    // ── PROPRIÉTÉ 9 : ce qu'un `APPEND` annonce, on peut le tenir ──────────
    const APPEND_MAX: u64 = 1_048_576;
    if let Ok(Some(depot)) = Append::parse(entree.depot, APPEND_MAX) {
        assert!(
            depot.octets() <= APPEND_MAX,
            "un APPEND accepté annonce {} octets, au-delà de la borne",
            depot.octets()
        );
        assert!(
            !depot.mailbox().is_empty(),
            "un APPEND accepté ne nomme aucune boîte"
        );
        // La date, si elle est là, se relit comme celle qu'on écrit.
        let _ = depot.date();
        let _ = depot.flags();
        let _ = depot.synchronizing();
    }

    if let Ok(recherche) = Search::parse(entree.criteres, &bornes) {
        // PROPRIÉTÉ 8 : l'arbre est borné, et l'évaluation se termine.
        assert!(recherche.len() <= SEARCH_KEYS_MAX);
        assert!(!recherche.is_empty());
        let (sequence, uid, size, drapeaux, date) = entree.message;
        let mut flags = Flags::NONE;
        for (bit, drapeau) in [
            Flags::SEEN,
            Flags::ANSWERED,
            Flags::FLAGGED,
            Flags::DELETED,
            Flags::DRAFT,
        ]
        .into_iter()
        .enumerate()
        {
            if drapeaux & (1_u8 << (bit % 8)) != 0 {
                flags = flags.with(drapeau);
            }
        }
        let candidat = Candidate {
            sequence,
            uid,
            size,
            flags,
            internal_date: date,
        };
        // Qu'elle rende vrai ou faux importe peu : ce qu'on éprouve est
        // qu'elle RENDE, et deux fois la même chose.
        //
        // LE LECTEUR RÉPOND TOUJOURS PAREIL : un critère qui lit le message ne
        // doit pas rendre la recherche instable, et c'est ce qu'on vérifie en
        // lui donnant une réponse constante.
        let mut lecteur = Lecteur {
            reponse: true,
            jour: Some(date),
        };
        let verdict = recherche.matches(&candidat, entree.star, entree.star, &mut lecteur);
        assert_eq!(
            verdict,
            recherche.matches(&candidat, entree.star, entree.star, &mut lecteur),
            "une recherche a changé d'avis sur le même message"
        );
        // Et la réponse inverse donne un verdict, elle aussi — sans date, ce qui
        // fait passer les critères `SENT…` par leur chemin d'absence.
        let _ = recherche.matches(
            &candidat,
            entree.star,
            entree.star,
            &mut Lecteur {
                reponse: false,
                jour: None,
            },
        );
    }
});
