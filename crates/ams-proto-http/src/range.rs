// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les requêtes de portée (§14 de RFC 9110).
//!
//! # POURQUOI CE SERVEUR EN A BESOIN, ET NON PAR COMMODITÉ
//!
//! Une réponse de cette API rend une tranche d'un tampon que la boucle a alloué.
//! Un message de courrier, lui, fait la taille que son expéditeur a voulue — des
//! mébioctets, parfois. **Sans portée, un message entier ne se lit pas du tout**
//! par HTTP, et ce n'est pas un confort qui manquerait : c'est la ressource.
//!
//! # UNE SEULE PORTÉE, ET C'EST LA PREMIÈRE
//!
//! §14.2 laisse un serveur « ignore or reject » un champ qui en demande
//! plusieurs. Les servir toutes demanderait une réponse `multipart/byteranges`,
//! c'est-à-dire un cadrage MIME que cette API ne produit nulle part ailleurs.
//!
//! Rendre la première est sans ambiguïté : `Content-Range` dit EXACTEMENT quels
//! octets partent, et un client qui en attendait deux le voit du premier coup.
//!
//! # CE QUI EST MAL FORMÉ S'IGNORE, CE QUI EST HORS BORNES SE REFUSE
//!
//! §14.2 : « An origin server MUST ignore a Range header field that contains a
//! range unit it does not understand. » Un champ illisible n'est donc pas une
//! faute du client — c'est un champ qu'on n'a pas compris, et la réponse est
//! celle qu'on aurait donnée sans lui.
//!
//! Une portée qui commence au-delà de la représentation, en revanche, ne peut pas
//! être satisfaite, et §15.5.17 lui donne son propre code. La distinction compte :
//! l'une dit « je n'ai pas compris », l'autre « ce que tu demandes n'existe pas ».

/// Ce qu'une portée couvre, **bornes comprises**.
///
/// §14.1.1 compte le dernier octet DEDANS : `bytes=0-0` demande un octet. C'est
/// le piège de cette section, et il vaut d'être nommé — un décalage d'un octet ne
/// se voit pas sur un message, il se voit sur le dernier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// Le premier octet demandé.
    pub first: u64,
    /// Le dernier, INCLUS.
    pub last: u64,
}

impl ByteRange {
    /// Combien d'octets cette portée couvre.
    ///
    /// **`octets` ET NON `len`** : `len` appelle `is_empty`, et une portée n'est
    /// jamais vide — `last` est inclus. Écrire un `is_empty` qui rend toujours
    /// `false` serait une fonction que personne n'appelle et que rien n'éprouve.
    #[must_use]
    pub const fn octets(&self) -> u64 {
        self.last.saturating_sub(self.first).saturating_add(1)
    }
}

/// Pourquoi une portée n'a pas été retenue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeFault {
    /// On n'a pas compris le champ. **§14.2 demande de l'IGNORER**, et non de
    /// refuser la requête : la réponse est celle qu'on aurait donnée sans lui.
    Ignored,
    /// La portée commence au-delà de la représentation (§15.5.17).
    Unsatisfiable,
}

/// La première portée que ce champ demande, bornée par `complete`.
///
/// `complete` est la taille de la représentation entière, en octets.
///
/// # Errors
///
/// [`RangeFault`] dit lequel des deux cas.
pub fn parse_range(valeur: &[u8], complete: u64) -> Result<ByteRange, RangeFault> {
    // §14.1 : `bytes=` et rien d'autre. `Range: items=1-3` est une unité qu'on ne
    // comprend pas, donc un champ qu'on ignore.
    let reste = valeur.strip_prefix(b"bytes=").ok_or(RangeFault::Ignored)?;
    // **LA PREMIÈRE, ET RIEN QUE LA PREMIÈRE.**
    // `split` rend TOUJOURS au moins une tranche, même sur une entrée vide : le
    // repli porte cette impossibilité dans la bibliothèque standard plutôt que
    // dans une garde qu'aucune entrée ne peut emprunter.
    let premiere = reste.split(|octet| *octet == b',').next().unwrap_or(reste);
    let premiere = rogner(premiere);

    let (avant, apres) = couper(premiere)?;

    // **UNE REPRÉSENTATION VIDE NE SE DÉCOUPE PAS.** Aucune portée ne peut la
    // satisfaire, et §15.5.17 est exactement ce cas.
    let dernier_possible = complete.checked_sub(1).ok_or(RangeFault::Unsatisfiable)?;

    if avant.is_empty() {
        // §14.1.1 : `bytes=-500`, les cinq cents DERNIERS octets. Un suffixe nul
        // ne désigne rien, et §14.1.1 le nomme comme non satisfiable.
        let combien = entier(apres)?;
        if combien == 0 {
            return Err(RangeFault::Unsatisfiable);
        }
        let first = complete.saturating_sub(combien);
        return Ok(ByteRange {
            first,
            last: dernier_possible,
        });
    }

    let first = entier(avant)?;
    if first > dernier_possible {
        return Err(RangeFault::Unsatisfiable);
    }
    // `bytes=500-` : jusqu'au bout.
    let last = match apres.is_empty() {
        true => dernier_possible,
        // **ON BORNE PLUTÔT QUE DE REFUSER** : §14.1.1 dit qu'un dernier octet
        // au-delà de la représentation vaut le dernier qui existe. Refuser
        // obligerait un client à connaître la taille avant de demander.
        false => entier(apres)?.min(dernier_possible),
    };
    match last < first {
        true => Err(RangeFault::Ignored),
        false => Ok(ByteRange { first, last }),
    }
}

/// Coupe `premier-dernier` sur son tiret, sans en admettre deux.
fn couper(portee: &[u8]) -> Result<(&[u8], &[u8]), RangeFault> {
    let tiret = portee
        .iter()
        .position(|octet| *octet == b'-')
        .ok_or(RangeFault::Ignored)?;
    let avant = rogner(portee.get(..tiret).unwrap_or_default());
    let apres = rogner(portee.get(tiret.saturating_add(1)..).unwrap_or_default());
    // Un second tiret : ce n'est pas une portée, et deviner ce qu'on en ferait
    // reviendrait à inventer une syntaxe.
    //
    // **`bytes=-` N'EST PAS REFUSÉ ICI**, et c'est délibéré : `entier` refuse
    // déjà une tranche vide. Le vérifier aux deux endroits ferait une garde que
    // rien ne peut atteindre — et c'est celle d'`entier` qui protège vraiment,
    // puisqu'elle vaut pour tous ses appelants.
    if apres.contains(&b'-') {
        return Err(RangeFault::Ignored);
    }
    Ok((avant, apres))
}

/// Lit un entier décimal, sans signe ni espace.
///
/// **CE QUI DÉBORDE S'IGNORE**, et ne se sature pas : saturer ferait servir des
/// octets que le client n'a pas demandés.
fn entier(octets: &[u8]) -> Result<u64, RangeFault> {
    if octets.is_empty() {
        return Err(RangeFault::Ignored);
    }
    let mut valeur = 0_u64;
    for octet in octets {
        let chiffre = octet.checked_sub(b'0').filter(|c| *c < 10);
        let chiffre = u64::from(chiffre.ok_or(RangeFault::Ignored)?);
        valeur = valeur
            .checked_mul(10)
            .and_then(|dix| dix.checked_add(chiffre))
            .ok_or(RangeFault::Ignored)?;
    }
    Ok(valeur)
}

/// Ôte les blancs de tête et de queue.
fn rogner(octets: &[u8]) -> &[u8] {
    let debut = octets
        .iter()
        .position(|octet| !matches!(*octet, b' ' | b'\t'))
        .unwrap_or(octets.len());
    let fin = octets
        .iter()
        .rposition(|octet| !matches!(*octet, b' ' | b'\t'))
        .map_or(debut, |rang| rang.saturating_add(1));
    octets.get(debut..fin).unwrap_or_default()
}

#[cfg(test)]
mod tests;
