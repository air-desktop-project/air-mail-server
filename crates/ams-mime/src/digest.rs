// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le sujet et l'expéditeur d'un message, pour une liste.
//!
//! # POURQUOI CE N'EST PAS UNE `ENVELOPE`, ET NE DOIT PAS L'ÊTRE
//!
//! L'`ENVELOPE` de §7.5.2 de RFC 9051 rend DIX champs, dont six listes
//! d'adresses, et elle les rend **tels quels** — un sujet en mots encodés reste
//! encodé, parce qu'un client IMAP doit recevoir ce que le message porte.
//!
//! Une liste de messages dans une API REST ne demande pas cela. Elle demande deux
//! textes courts, lisibles, qu'un client affiche sans rien savoir de MIME. Les
//! deux besoins sont contraires sur les trois points qui comptent :
//!
//! - **le décodage.** L'un rend les octets, l'autre rend le sens.
//! - **la longueur.** Une enveloppe est aussi longue que son auteur l'a voulu —
//!   d'où l'écoulement par morceaux d'`ams-session::imap`. Celle-ci tient dans
//!   deux tampons dont on connaît la taille avant de lire.
//! - **le coût.** Une enveloppe se compose une fois par message affiché ; un
//!   résumé se compose pour toute une page.
//!
//! Vouloir une seule fonction pour les deux donnerait à chacun les contraintes de
//! l'autre. C'est pourquoi il y a deux chemins.
//!
//! # CE QUI EST DÉLIBÉRÉMENT ABSENT DE L'EXPÉDITEUR
//!
//! **Le nom d'affichage.** `"Votre banque" <pirate@example.test>` est un message
//! dont le nom ment, et rien dans la RFC 5322 ne l'interdit — c'est même la forme
//! ordinaire de l'hameçonnage. L'adresse, elle, est la seule partie que le client
//! peut recouper avec ce qu'il connaît.
//!
//! Un client qui veut le nom a l'`ENVELOPE` d'IMAP, ou le message lui-même.
//!
//! # ET UN SUJET QU'ON NE PEUT PAS RENDRE ENTIER N'EST PAS RENDU
//!
//! Le tronquer ferait afficher un texte qui n'est pas celui du message — et,
//! pire, un texte qu'on aurait choisi de couper là. Mieux vaut dire qu'on n'a pas
//! de sujet que d'en donner la moitié.

use crate::decode::decode_encoded_words;
use crate::limits::Limits;
use crate::message::Message;

/// Ce qu'un sujet décodé peut occuper, en octets.
///
/// Mille vingt-quatre. §2.1.1 de RFC 5322 recommande de ne pas dépasser
/// neuf cent quatre-vingt-dix-huit caractères par ligne ; un sujet plus long que
/// cela est déjà hors des usages, et un client ne l'afficherait pas entier.
pub const DIGEST_SUBJECT_MAX: usize = 1024;

/// Ce qu'une adresse d'expéditeur peut occuper, en octets.
///
/// §4.5.3.1.3 de RFC 5321 borne un chemin à deux cent cinquante-six octets. Ce
/// n'est pas notre borne, c'est la sienne.
pub const DIGEST_FROM_MAX: usize = 256;

/// Ce qu'un résumé a trouvé.
///
/// **L'ABSENCE ET LE VIDE NE SONT PAS LA MÊME CHOSE** : un message sans champ
/// `Subject:` rend `None` ; un `Subject:` présent et vide rend `Some(0)`. Les
/// confondre ferait croire à un client qu'un message a un sujet vide alors qu'il
/// n'en a pas — ou l'inverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Digest {
    /// Ce que le sujet occupe dans son tampon, s'il y en a un de rendu.
    pub subject: Option<usize>,
    /// Ce que l'adresse de l'expéditeur occupe dans le sien, s'il y en a une.
    pub from: Option<usize>,
}

/// Écrit le sujet décodé et l'adresse de l'expéditeur d'un bloc d'en-tête.
///
/// # IL NE REND PAS D'ERREUR, ET C'EST VOULU
///
/// Un en-tête illisible, un sujet trop long, une adresse qu'on ne sait pas
/// isoler : dans tous les cas la réponse est la même — **ce champ-là n'est pas
/// rendu**, et les autres le sont quand même. Un résumé est une commodité
/// d'affichage ; refuser toute la liste parce qu'un message sur mille a un
/// `From:` biscornu servirait moins bien le client que de lui rendre `null`.
///
/// Ce qui doit échouer bruyamment échoue ailleurs : la lecture du message, elle,
/// rend ses fautes.
#[must_use]
pub fn write_digest(
    entete: &[u8],
    sujet: &mut [u8],
    expediteur: &mut [u8],
    limits: &Limits,
) -> Digest {
    let Ok(message) = Message::parse(entete, limits) else {
        return Digest::default();
    };
    Digest {
        subject: le_sujet(&message, sujet),
        from: l_expediteur(&message, expediteur),
    }
}

/// Le sujet, décodé et déplié.
fn le_sujet(message: &Message<'_>, out: &mut [u8]) -> Option<usize> {
    // §3.6 de RFC 5322 n'admet qu'un `Subject:`. Un second est un en-tête mal
    // formé, et prendre le premier est ce que fait tout le reste de cette crate.
    let champ = message.fields().find(|champ| champ.name_is(b"subject"))?;
    // **LA VALEUR ENCORE PLIÉE**, et c'est licite : `decode_encoded_words` traite
    // déjà `CR` et `LF` comme du blanc, donc un mot encodé coupé par un pli se
    // lit, et le blanc entre deux mots encodés disparaît comme §6.2 le demande.
    let ecrits = decode_encoded_words(champ.raw_value(), out).ok()?;
    // **`decode_encoded_words` N'ÉCRIT PAS AU-DELÀ DE `out`** : il rend
    // `BufferTooSmall` plutôt que de déborder, et l'on vient de l'écarter.
    let ecrit = out
        .get_mut(..ecrits)
        .expect("ce qui vient d'être écrit tient dans le tampon où on l'a écrit");
    Some(nettoyer(ecrit))
}

/// Efface les plis, puis le blanc de bordure. Rend ce qu'il reste.
///
/// # L'ESPACE QUI SUIT LE DEUX-POINTS APPARTIENT À LA SYNTAXE
///
/// §2.2 de RFC 5322 met un blanc facultatif entre le deux-points et la valeur, et
/// `raw_value` le rend parce que c'est ce que le champ PORTE. Un sujet n'est pas
/// un champ : `Subject: facture` a pour sujet « facture », et le rendre comme
/// « facture » avec une espace en tête ferait trier et afficher de travers chez
/// tous les clients à la fois.
///
/// **ET LE VIDE RESTE DU VIDE** : `Subject:` et `Subject:   ` rendent tous deux
/// un sujet vide, ce qui n'est pas la même chose qu'un message sans sujet.
fn nettoyer(texte: &mut [u8]) -> usize {
    let apres_les_plis = effacer_les_plis(texte);
    let vu = texte.get(..apres_les_plis).unwrap_or_default();
    let blanc = |octet: &u8| matches!(*octet, b' ' | b'\t');
    let debut = vu.iter().position(|octet| !blanc(octet));
    let Some(debut) = debut else {
        // Rien que du blanc : le champ existe, et sa valeur est vide.
        return 0;
    };
    let fin = vu
        .iter()
        .rposition(|octet| !blanc(octet))
        .map_or(debut, |rang| rang.saturating_add(1));
    texte.copy_within(debut..fin, 0);
    fin.saturating_sub(debut)
}

/// Efface les fins de ligne d'un texte, sur place. Rend ce qu'il reste.
///
/// # LE PLI S'EFFACE, IL NE DEVIENT PAS UN BLANC
///
/// Le blanc qui suit un `CRLF` appartient déjà à la valeur (§2.2.3 de RFC 5322) :
/// `Jean<CRLF> Dupont` vaut `Jean Dupont`, et remplacer le pli par une espace en
/// mettrait deux. C'est la règle que suit déjà l'`ENVELOPE`, et deux règles pour
/// un même pli donneraient deux textes pour un même message.
///
/// **ET UN TEXTE RENDU NE PORTE PAS DE FIN DE LIGNE.** Ici, le rendu est du JSON,
/// qui saurait l'échapper ; ce n'est donc pas une faille comme en IMAP, mais
/// c'est un artefact de transport que rien ne justifie de montrer.
fn effacer_les_plis(texte: &mut [u8]) -> usize {
    let mut garde = 0_usize;
    for rang in 0..texte.len() {
        let octet = texte.get(rang).copied().unwrap_or(0);
        if matches!(octet, b'\r' | b'\n') {
            continue;
        }
        // **`garde` NE DÉPASSE JAMAIS `rang`** : il n'avance que d'un par tour, et
        // seulement pour les octets qu'on garde. Un `if let` ici ouvrirait une
        // branche qu'aucune entrée ne peut emprunter.
        *texte
            .get_mut(garde)
            .expect("on n'écrit jamais plus loin qu'on ne lit") = octet;
        garde = garde.saturating_add(1);
    }
    garde
}

/// L'adresse de l'expéditeur, sans son nom d'affichage.
fn l_expediteur(message: &Message<'_>, out: &mut [u8]) -> Option<usize> {
    let champ = message.fields().find(|champ| champ.name_is(b"from"))?;
    // **UN `From:` À PLUSIEURS ADRESSES NE REND RIEN.** §3.6.2 de RFC 5322
    // l'admet — un message écrit à plusieurs mains —, et il demande alors un
    // `Sender:`. En choisir une serait désigner un auteur que le message ne
    // désigne pas.
    let adresse = crate::address::sole_address(champ.raw_value()).ok()?;
    let adresse = une_adresse_et_rien_d_autre(adresse)?;
    let place = out.get_mut(..adresse.len())?;
    place.copy_from_slice(adresse);
    Some(adresse.len())
}

/// Ce qui reste après le blanc de bordure, si c'est bien une adresse.
///
/// # POURQUOI UN CONTRÔLE ICI, ALORS QUE `sole_address` A DÉJÀ DÉCIDÉ
///
/// `sole_address` sert d'abord à trouver un DOMAINE : sans chevrons, elle rend la
/// valeur entière — blanc de bordure, plis et commentaires compris —, et le
/// découpage du domaine écarte ensuite ce qui traîne. C'est juste pour ce qu'elle
/// sert, et insuffisant pour ce qu'on rend.
///
/// **CE QU'ON REND EST AFFICHÉ TEL QUEL.** Un commentaire ou un pli qui
/// subsisterait ferait lire au client autre chose qu'une adresse, et une valeur
/// sans arobase ne désigne personne. On préfère ne rien rendre.
fn une_adresse_et_rien_d_autre(adresse: &[u8]) -> Option<&[u8]> {
    let blanc = |octet: &u8| matches!(*octet, b' ' | b'\t' | b'\r' | b'\n');
    let debut = adresse.iter().position(|octet| !blanc(octet))?;
    let fin = adresse
        .iter()
        .rposition(|octet| !blanc(octet))
        .map_or(debut, |rang| rang.saturating_add(1));
    let nu = adresse
        .get(debut..fin)
        .expect("deux rangs de cette tranche, dans l'ordre");
    // Un blanc au MILIEU, un commentaire, un chevron ou une virgule : ce n'est
    // plus une adresse, c'est ce qui l'entourait.
    let propre = !nu
        .iter()
        .any(|octet| blanc(octet) || matches!(*octet, b'(' | b')' | b'<' | b'>' | b','));
    match propre && nu.contains(&b'@') {
        true => Some(nu),
        false => None,
    }
}

#[cfg(test)]
mod tests;
