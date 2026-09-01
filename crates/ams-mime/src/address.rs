//! Le domaine d'un champ d'adresse (RFC 5322 §3.4).
//!
//! # Ce que cette tranche couvre, et pourquoi elle s'arrête là
//!
//! **Le domaine, et rien d'autre.** DMARC (C9) a besoin d'une seule chose du
//! champ `From:` : le domaine de son adresse. La partie locale, le nom
//! d'affichage, les groupes, les mots encodés — rien de tout cela ne change le
//! verdict, et écrire une grammaire d'adresse entière pour en tirer un domaine
//! serait écrire, pour l'occasion, la moitié la plus délicate de la RFC 5322.
//!
//! # Un `From:` qui porte plusieurs adresses est REFUSÉ
//!
//! RFC 5322 en autorise plusieurs ; RFC 7489 §6.6.1 dit qu'un receveur peut
//! alors refuser le message. C'est ce qu'on fait, et c'est le seul choix sûr :
//! avec deux auteurs, il y a deux domaines, deux politiques, et rien pour dire
//! laquelle s'applique. Choisir la première reviendrait à laisser l'expéditeur
//! choisir laquelle on vérifie.
//!
//! # Les commentaires se traversent, ils ne se recopient pas
//!
//! `jean(le vrai)@example.com` est licite (RFC 5322 §3.2.2). Le commentaire se
//! saute — parenthèses imbriquées comprises — mais s'il COUPE le domaine, on
//! refuse : recoller les morceaux demanderait un tampon, et cette crate n'alloue
//! pas.

use crate::Error;

/// Le domaine de l'adresse d'un champ, `From:` en particulier.
///
/// `value` est la valeur brute du champ, **encore pliée** — c'est-à-dire ce que
/// rend [`crate::Field::raw_value`].
///
/// # Errors
///
/// [`Error::NoAddress`] s'il n'y a pas d'adresse lisible,
/// [`Error::MultipleAddresses`] s'il y en a plusieurs.
pub fn author_domain(value: &[u8]) -> Result<&[u8], Error> {
    let adresse = sole_address(value)?;
    let arobase = dernier_arobase(adresse).ok_or(Error::NoAddress)?;

    // UNE ADRESSE A UNE PARTIE LOCALE. `@example.com` n'en est pas une, et
    // rendre son domaine ferait vérifier la politique d'un domaine que personne
    // n'a écrit comme auteur.
    let locale = adresse.get(..arobase).unwrap_or_default();
    if sans_commentaires_est_vide(locale) {
        return Err(Error::NoAddress);
    }

    let apres = adresse.get(arobase.saturating_add(1)..).unwrap_or_default();
    let fin = apres
        .iter()
        .position(|octet| !est_octet_de_domaine(*octet))
        .unwrap_or(apres.len());
    let domaine = apres.get(..fin).unwrap_or_default();
    if domaine.is_empty() {
        return Err(Error::NoAddress);
    }
    // Ce qui suit le domaine ne peut être QUE du blanc et des commentaires. Un
    // commentaire au milieu d'un domaine le couperait en deux, et recoller les
    // morceaux demanderait un tampon que cette crate n'a pas.
    if !sans_commentaires_est_vide(apres.get(fin..).unwrap_or_default()) {
        return Err(Error::NoAddress);
    }
    Ok(domaine)
}

/// Un octet qu'un `dot-atom` ou un `domain-literal` peut porter.
fn est_octet_de_domaine(octet: u8) -> bool {
    (0x21..=0x7E).contains(&octet) && !matches!(octet, b'(' | b')' | b'<' | b'>' | b',' | b'@')
}

/// Ce qui reste ne porte-t-il que du blanc et des commentaires ?
fn sans_commentaires_est_vide(morceau: &[u8]) -> bool {
    let mut profondeur = 0_u32;
    let mut echappe = false;
    for octet in morceau {
        if echappe {
            echappe = false;
            continue;
        }
        match octet {
            b'\\' if profondeur > 0 => echappe = true,
            b'(' => profondeur = profondeur.saturating_add(1),
            b')' => profondeur = profondeur.saturating_sub(1),
            _ if profondeur > 0 => {}
            b' ' | b'\t' | b'\r' | b'\n' => {}
            _ => return false,
        }
    }
    profondeur == 0
}

/// L'adresse d'un champ qui n'en porte qu'une.
///
/// Rend ce qui est entre chevrons s'il y en a, la valeur nettoyée sinon.
///
/// `value` est la valeur brute du champ, **encore pliée** — c'est-à-dire ce que
/// rend [`crate::Field::raw_value`].
///
/// # LE NOM D'AFFICHAGE NE FAIT PAS PARTIE DE L'ADRESSE
///
/// `"Votre banque" <pirate@example.test>` rend `pirate@example.test`. Le nom est
/// choisi par celui qui écrit et ne prouve rien ; l'adresse est la seule partie
/// qu'un lecteur peut recouper avec ce qu'il connaît.
///
/// # Errors
///
/// [`Error::NoAddress`] s'il n'y a pas d'adresse lisible,
/// [`Error::MultipleAddresses`] s'il y en a plusieurs — §3.6.2 de RFC 5322
/// l'admet pour un `From:`, et en choisir une désignerait alors un auteur que le
/// message ne désigne pas.
pub fn sole_address(value: &[u8]) -> Result<&[u8], Error> {
    let mut profondeur = 0_u32;
    let mut entre_guillemets = false;
    let mut echappe = false;
    let mut debut_chevron: Option<usize> = None;
    let mut fin_chevron: Option<usize> = None;
    let mut virgules = 0_u32;
    let mut chevrons = 0_u32;

    for (rang, octet) in value.iter().enumerate() {
        if echappe {
            echappe = false;
            continue;
        }
        match octet {
            b'\\' if entre_guillemets || profondeur > 0 => echappe = true,
            b'"' if profondeur == 0 => entre_guillemets = !entre_guillemets,
            _ if entre_guillemets => {}
            b'(' => profondeur = profondeur.saturating_add(1),
            b')' => profondeur = profondeur.saturating_sub(1),
            _ if profondeur > 0 => {}
            b'<' => {
                chevrons = chevrons.saturating_add(1);
                debut_chevron.get_or_insert(rang);
            }
            b'>' => fin_chevron = Some(rang),
            // UNE VIRGULE HORS GUILLEMETS ET HORS COMMENTAIRE SÉPARE DEUX
            // ADRESSES. Avec deux auteurs, il y a deux domaines, deux
            // politiques, et rien pour dire laquelle s'applique.
            b',' => virgules = virgules.saturating_add(1),
            _ => {}
        }
    }

    if entre_guillemets || profondeur > 0 {
        return Err(Error::NoAddress);
    }
    if virgules > 0 || chevrons > 1 {
        return Err(Error::MultipleAddresses);
    }

    match (debut_chevron, fin_chevron) {
        (Some(debut), Some(fin)) if fin > debut => value
            .get(debut.saturating_add(1)..fin)
            .ok_or(Error::NoAddress),
        // Un chevron ouvert et jamais fermé n'est pas une adresse.
        (Some(_), _) => Err(Error::NoAddress),
        // Sans chevrons, c'est la valeur entière — commentaires compris, que le
        // découpage du domaine écartera.
        (None, _) => Ok(value),
    }
}

/// Le rang du dernier `@` hors guillemets et hors commentaire.
///
/// **Le DERNIER** : une partie locale entre guillemets peut en porter un, et
/// `"a@b"@example.com` a pour domaine `example.com`.
fn dernier_arobase(adresse: &[u8]) -> Option<usize> {
    let mut profondeur = 0_u32;
    let mut entre_guillemets = false;
    let mut echappe = false;
    let mut trouve = None;

    for (rang, octet) in adresse.iter().enumerate() {
        if echappe {
            echappe = false;
            continue;
        }
        match octet {
            b'\\' if entre_guillemets || profondeur > 0 => echappe = true,
            b'"' if profondeur == 0 => entre_guillemets = !entre_guillemets,
            _ if entre_guillemets => {}
            b'(' => profondeur = profondeur.saturating_add(1),
            b')' => profondeur = profondeur.saturating_sub(1),
            _ if profondeur > 0 => {}
            b'@' => trouve = Some(rang),
            _ => {}
        }
    }
    trouve
}

#[cfg(test)]
mod tests;
