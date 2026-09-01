//! Retrouver le `SubjectPublicKeyInfo` dans un certificat.
//!
//! # POURQUOI CETTE CRATE LIT UN PEU DE DER
//!
//! §2.1.2 de RFC 6698 : le sélecteur `1` porte sur le `SubjectPublicKeyInfo`, et
//! non sur le certificat entier. **C'est le sélecteur qui survit à un
//! renouvellement** — un certificat réémis avec la même clé garde la même
//! empreinte —, et c'est pour cela qu'il est de loin le plus publié.
//!
//! Le retrouver demande de traverser le certificat. Ce n'est PAS une
//! bibliothèque X.509 : on ne décode rien, on ne valide rien, on ne lit aucun
//! nom, aucune date, aucune extension. **On saute des éléments et on rend une
//! tranche.** Écrire davantage serait écrire un second décodeur X.509 dans ce
//! dépôt, qui finirait par diverger de celui que rustls emploie — et c'est
//! rustls qui décide de la validité, pas nous.
//!
//! # LA TRANCHE RENDUE PORTE SON PROPRE EN-TÊTE
//!
//! Ce qui se hache est le `SubjectPublicKeyInfo` **encodé en DER**, étiquette et
//! longueur comprises. Rendre seulement son contenu donnerait une empreinte qui
//! ne correspondrait à aucun `TLSA` du monde.
//!
//! # CE QUE CE MODULE REFUSE
//!
//! Tout ce qui n'a pas la forme attendue, en rendant `None` : le certificat ne
//! satisfait alors aucun enregistrement à sélecteur `1`. Refuser est le seul
//! comportement sûr — inventer une tranche ferait comparer une empreinte à autre
//! chose que ce qu'elle désigne.

/// Combien d'éléments séparent la version de la clé, dans le `tbsCertificate`
/// (RFC 5280 §4.1) :
///
/// ```text
/// TBSCertificate ::= SEQUENCE {
///   [0] version              -- FACULTATIF
///   serialNumber             -- 1
///   signature                -- 2
///   issuer                   -- 3
///   validity                 -- 4
///   subject                  -- 5
///   subjectPublicKeyInfo     -- celui qu'on cherche
///   ...
/// }
/// ```
const AVANT_LA_CLEF: usize = 5;

/// L'étiquette d'une `SEQUENCE` construite.
const SEQUENCE: u8 = 0x30;

/// L'étiquette du champ `[0] version`, contextuel et explicite.
const VERSION: u8 = 0xa0;

/// Le `SubjectPublicKeyInfo` de ce certificat, en DER, en-tête compris.
///
/// Rend `None` pour tout ce qui n'a pas la forme d'un certificat.
#[must_use]
pub fn subject_public_key_info(certificat: &[u8]) -> Option<&[u8]> {
    // Certificate ::= SEQUENCE { tbsCertificate, ... }
    let (etiquette, corps, _) = element(certificat, 0)?;
    if etiquette != SEQUENCE {
        return None;
    }
    // tbsCertificate ::= SEQUENCE { ... }
    let (etiquette, tbs, _) = element(corps, 0)?;
    if etiquette != SEQUENCE {
        return None;
    }

    // **LA VERSION EST FACULTATIVE**, et son absence décale tout d'un cran : un
    // certificat v1 n'en porte pas. La reconnaître à son étiquette contextuelle
    // vaut mieux que de supposer une version.
    let (premiere, _, apres_version) = element(tbs, 0)?;
    let mut position = if premiere == VERSION {
        apres_version
    } else {
        0
    };

    for _ in 0..AVANT_LA_CLEF {
        let (_, _, suivant) = element(tbs, position)?;
        position = suivant;
    }
    let (etiquette, _, fin) = element(tbs, position)?;
    if etiquette != SEQUENCE {
        return None;
    }
    tbs.get(position..fin)
}

/// L'élément DER qui commence à `debut` : son étiquette, son contenu, et où il
/// finit.
///
/// **Le DER n'admet qu'UNE écriture par longueur** (§10.1 de X.690) : une
/// longueur courte ne s'écrit pas sur plusieurs octets, et un octet de tête nul
/// n'est pas permis. On refuse les deux plutôt que de les accepter en silence —
/// deux écritures d'une même valeur donneraient deux tranches différentes pour
/// un même certificat, donc deux empreintes.
fn element(octets: &[u8], debut: usize) -> Option<(u8, &[u8], usize)> {
    // **LES ADDITIONS SATURENT PLUTÔT QUE DE SE GARDER.** `debut` vient de notre
    // propre parcours d'une tranche, dont la longueur tient dans un `usize` :
    // aucun de ces reports ne peut déborder. Une garde le dirait quand même, et
    // ce serait une garde que rien n'atteindrait — c'est le `get` qui suit qui
    // refuse ce qui dépasse, et lui, on l'éprouve.
    let etiquette = *octets.get(debut)?;
    let premiere = *octets.get(debut.saturating_add(1))?;
    let (longueur, apres_longueur) = if premiere & 0x80 == 0 {
        // Forme courte : la longueur EST cet octet.
        (usize::from(premiere), debut.saturating_add(2))
    } else {
        let combien = usize::from(premiere & 0x7f);
        // **UNE LONGUEUR SANS FIN N'EST PAS DU DER** (forme indéfinie, `0x80`).
        //
        // Et **quatre octets suffisent** : au-delà, la longueur annoncerait plus
        // de quatre gibioctets. Aucun certificat n'est cela, aucun tampon de ce
        // dépôt ne le tiendrait, et s'arrêter à quatre fait tenir la valeur dans
        // un `usize` de trente-deux bits comme de soixante-quatre. C'est ce qui
        // permet aux deux opérations qui suivent de SATURER plutôt que de porter
        // une garde qu'aucune entrée ne pourrait faire céder.
        if combien == 0 || combien > 4 {
            return None;
        }
        let debut_longueur = debut.saturating_add(2);
        let fin_longueur = debut_longueur.saturating_add(combien);
        let chiffres = octets.get(debut_longueur..fin_longueur)?;
        // Un octet de tête nul est une seconde écriture de la même valeur.
        // `unwrap_or(0)` porte l'impossible — `combien` vaut au moins un — dans
        // la même branche que le refus.
        if chiffres.first().copied().unwrap_or(0) == 0 {
            return None;
        }
        let mut longueur = 0_usize;
        for chiffre in chiffres {
            longueur = longueur
                .saturating_mul(256)
                .saturating_add(usize::from(*chiffre));
        }
        // Et une valeur qui tiendrait dans la forme courte n'a pas le droit
        // d'être écrite dans la forme longue.
        if longueur < 0x80 {
            return None;
        }
        (longueur, fin_longueur)
    };
    let fin = apres_longueur.saturating_add(longueur);
    let contenu = octets.get(apres_longueur..fin)?;
    Some((etiquette, contenu, fin))
}

#[cfg(test)]
mod tests;
