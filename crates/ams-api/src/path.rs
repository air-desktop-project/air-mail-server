// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le découpage d'un chemin, et son décodage.
//!
//! # ON NE NORMALISE PAS : ON REFUSE
//!
//! Presque toute faute d'autorisation d'une API vit dans l'écart entre deux
//! écritures d'un même chemin. `/v1/accounts/marc`, `/v1/accounts/./marc`,
//! `/v1//accounts/marc`, `/v1/accounts/%6darc` : quatre chaînes, une ressource.
//! Si le contrôle d'accès regarde la chaîne et le service regarde la ressource,
//! il existe une écriture qui passe l'un et atteint l'autre.
//!
//! Normaliser ne résout pas cela, **cela le déplace** : il faut alors que tout
//! le monde normalise pareil, y compris les intermédiaires, y compris demain.
//! Refuser, en revanche, ne demande d'accord à personne : une seule écriture est
//! acceptée, et c'est la plus simple.
//!
//! # LE `%2F` EST LE CŒUR DU SUJET
//!
//! §3.3 de RFC 3986 : la barre oblique sépare les segments, et un `%2F` **n'est
//! pas** une barre oblique — c'est un octet à l'intérieur d'un segment. Un
//! décodeur qui découpe après avoir décodé transforme donc `a%2F..%2Fb` en trois
//! segments, dont un `..`.
//!
//! **On découpe AVANT de décoder**, et un `%2F` décodé reste dans son segment.
//! Il n'y a alors plus rien à remonter.
//!
//! # ET CE QUI RESTE SE REFUSE
//!
//! Un `.` ou un `..`, un segment vide, un octet de contrôle : chacun a une
//! écriture licite qui dit la même chose, et aucun n'apporte rien qu'on veuille
//! servir.
//!
//! # ON DÉCOUPE AVANT DE DÉCODER, ET L'ON JUGE APRÈS
//!
//! Les deux moitiés de cette phrase se contredisent en apparence, et ne se
//! contredisent pas : le découpage regarde une SYNTAXE — où sont les
//! séparateurs — et le jugement regarde un SENS — que dit ce segment.
//!
//! Découper après décoder ferait d'un `%2F` un séparateur. Juger avant décoder
//! laisserait passer `%2e%2e`, qui s'écrit avec six octets dont aucun n'est un
//! point et se décode en `..`. Le premier jet de ce module faisait la seconde
//! faute, et un test l'a trouvée.

use crate::error::{Error, Reason};

/// Combien de segments un chemin peut porter.
///
/// Huit. La route la plus longue de cette API en compte six — `/v1/mailboxes/
/// {boite}/messages/{uid}/parts/{partie}` — et deux de marge suffisent à
/// distinguer « trop long » de « inconnu » sans retenir ce qu'un pair choisit.
pub const SEGMENTS_MAX: usize = 8;

/// Ce qu'un segment peut faire de long, **une fois décodé**.
///
/// Deux cent cinquante-cinq octets. C'est ce qu'un nom de boîte ou de compte
/// peut raisonnablement faire, et c'est aussi la borne d'un nom de fichier sur
/// tout système de fichiers qu'on vise — ce qui n'est pas un hasard, puisque
/// c'est là que ces noms finissent.
pub const SEGMENT_OCTETS_MAX: usize = 255;

/// Les segments d'un chemin, décodés.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segments<'o> {
    /// Les segments, dans l'ordre, complétés par des chaînes vides.
    segments: [&'o str; SEGMENTS_MAX],
    /// Combien il y en a.
    combien: usize,
}

impl<'o> Segments<'o> {
    /// Combien de segments.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.combien
    }

    /// N'y en a-t-il aucun ?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.combien == 0
    }

    /// Le segment de ce rang, ou la chaîne vide au-delà.
    ///
    /// # LA CHAÎNE VIDE NE PEUT DÉSIGNER QU'UNE ABSENCE
    ///
    /// Un segment vide est refusé au décodage : `//` et `/` désigneraient la même
    /// ressource, et deux écritures sont une de trop. Il n'existe donc AUCUN
    /// segment valide égal à `""`, et rendre `""` hors des bornes ne peut pas se
    /// confondre avec un segment réel.
    ///
    /// C'est ce qui permet à la table de routage de n'avoir aucune garde sur
    /// l'absence — une garde qu'aucun chemin ne peut emprunter, et qui serait
    /// donc une affirmation non vérifiée.
    #[must_use]
    pub fn get(&self, rang: usize) -> &'o str {
        self.segments.get(rang).copied().unwrap_or("")
    }
}

/// Sépare le chemin de la chaîne de requête.
///
/// **LE POINT D'INTERROGATION NE FAIT PAS PARTIE DU CHEMIN** (§3.4 de RFC 3986),
/// et le routage n'a rien à faire de ce qui suit. Les séparer ici évite qu'un
/// `?` se retrouve dans un nom de boîte — ou, pire, qu'un chemin se termine
/// différemment selon qu'on ait regardé la requête ou non.
///
/// Rend le chemin et ce qui suit le premier `?`, **non décodé** : chaque
/// paramètre a ses propres règles, et les décoder tous d'avance en ferait un
/// seul.
#[must_use]
pub fn split_query(cible: &[u8]) -> (&[u8], &[u8]) {
    match cible.iter().position(|octet| *octet == b'?') {
        Some(rang) => (
            cible.get(..rang).unwrap_or_default(),
            cible.get(rang.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (cible, &[]),
    }
}

/// Découpe et décode un chemin dans `sortie`.
///
/// # Errors
///
/// [`Reason::BadPath`] pour un chemin qui ne commence pas par une barre oblique,
/// un segment vide, un `.` ou un `..`, un octet de contrôle, un pourcentage mal
/// écrit, ou de l'UTF-8 invalide ; [`Reason::PathTooLong`] au-delà de ce qu'on
/// retient ; [`Reason::BufferTooSmall`] si `sortie` ne suffit pas — **celle-là
/// est la nôtre**.
pub fn decode<'o>(chemin: &[u8], sortie: &'o mut [u8]) -> Result<Segments<'o>, Error> {
    // §3.3 : un chemin d'origine commence par une barre oblique. Le reste — un
    // chemin absolu, une autorité — n'a pas sa place sur une requête d'API.
    let Some(b'/') = chemin.first() else {
        return Err(Error::new(Reason::BadPath));
    };
    let corps = chemin.get(1..).unwrap_or_default();
    let mut segments = [""; SEGMENTS_MAX];
    // La racine seule : zéro segment, et non un segment vide.
    if corps.is_empty() {
        return Ok(Segments {
            segments,
            combien: 0,
        });
    }

    let mut combien = 0_usize;
    let mut reste = sortie;
    let mut places = segments.iter_mut();
    // **ON DÉCOUPE AVANT DE DÉCODER** : un `%2F` décodé reste alors dans son
    // segment, et il n'y a plus rien à remonter.
    for brut in corps.split(|octet| *octet == b'/') {
        // La place qui manque EST la borne : la chercher et la vérifier sont la
        // même opération, et il n'y a donc pas de garde séparée qui pourrait
        // diverger du tableau.
        let Some(place) = places.next() else {
            return Err(Error::new(Reason::PathTooLong));
        };
        let (ecrit, libre) = decoder_un_segment(brut, reste)?;
        reste = libre;
        *place = ecrit;
        combien = combien.saturating_add(1);
    }
    Ok(Segments { segments, combien })
}

/// Décode un segment, et rend ce qu'il a écrit puis ce qui reste libre.
fn decoder_un_segment<'o>(
    brut: &[u8],
    sortie: &'o mut [u8],
) -> Result<(&'o str, &'o mut [u8]), Error> {
    // **UN SEGMENT VIDE EST UNE SECONDE ÉCRITURE DE LA MÊME CHOSE** : `//` et
    // `/` désignent la même ressource, et deux écritures sont une de trop.
    if brut.is_empty() {
        return Err(Error::new(Reason::BadPath));
    }
    let mut ecrits = 0_usize;
    let mut octets = brut.iter().copied();
    while let Some(octet) = octets.next() {
        let valeur = match octet {
            b'%' => {
                let haut = octets.next().ok_or(Error::new(Reason::BadPath))?;
                let bas = octets.next().ok_or(Error::new(Reason::BadPath))?;
                let haut = chiffre(haut).ok_or(Error::new(Reason::BadPath))?;
                let bas = chiffre(bas).ok_or(Error::new(Reason::BadPath))?;
                haut.saturating_mul(16).saturating_add(bas)
            }
            autre => autre,
        };
        // **AUCUN OCTET DE CONTRÔLE**, encodé ou non. Un NUL coupe un nom de
        // fichier au milieu chez qui le lit en C ; un saut de ligne coupe un
        // journal en deux et y écrit ce qu'on veut.
        if valeur < 0x20 || valeur == 0x7f {
            return Err(Error::new(Reason::BadPath));
        }
        let place = sortie
            .get_mut(ecrits)
            .ok_or(Error::new(Reason::BufferTooSmall))?;
        *place = valeur;
        ecrits = ecrits.saturating_add(1);
    }

    // **LA LONGUEUR SE MESURE APRÈS DÉCODAGE, ET C'EST LA MÊME RAISON.**
    //
    // Un nom de 255 octets s'écrit sur 255 octets, ou sur 765 s'il est
    // entièrement encodé. Mesurer la forme reçue ferait donc accepter ce nom
    // dans une écriture et le refuser dans l'autre — deux réponses pour une
    // ressource, ce que tout ce module existe pour empêcher.
    //
    // Défaut écrit puis trouvé par le fuzz, sur un aller-retour qui réencodait
    // ce qu'on venait de décoder.
    if ecrits > SEGMENT_OCTETS_MAX {
        return Err(Error::new(Reason::BadPath));
    }
    let (ecrit, libre) = sortie.split_at_mut(ecrits);
    // **NI `.` NI `..`, ET LA VÉRIFICATION EST APRÈS LE DÉCODAGE.**
    //
    // Le premier ne dit rien, le second remonte. Les résoudre serait une
    // normalisation ; les refuser n'exige d'accord avec personne.
    //
    // Mais l'ordre est tout : `%2e%2e` s'écrit avec six octets dont aucun n'est
    // un point, et se décode en `..`. Une vérification faite sur le segment BRUT
    // le laisse passer — c'est ce que faisait le premier jet, et c'est
    // exactement la faute que ce module existe pour empêcher.
    //
    // La règle générale : **on découpe avant de décoder, et on juge après**. Le
    // découpage regarde une syntaxe, le jugement regarde un sens.
    if ecrit == b"." || ecrit == b".." {
        return Err(Error::new(Reason::BadPath));
    }
    // **DE L'UTF-8, ET RIEN D'AUTRE** : ces noms finissent dans des chemins de
    // fichiers et dans des réponses JSON. Un octet qui n'est pas de l'UTF-8 y
    // serait rendu différemment par chaque lecteur — et deux lecteurs qui ne
    // voient pas le même nom, c'est le même écart que deux écritures d'un chemin.
    let texte = core::str::from_utf8(ecrit).map_err(|_| Error::new(Reason::BadPath))?;
    Ok((texte, libre))
}

/// La valeur d'un chiffre hexadécimal.
///
/// **LES DEUX CASSES, ET C'EST §6.2.2.1 DE RFC 3986 QUI LE DIT** : `%2F` et
/// `%2f` sont le même octet. Les distinguer ferait deux écritures là où la
/// norme n'en voit qu'une.
const fn chiffre(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(octet.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(octet.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
