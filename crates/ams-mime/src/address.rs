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

/// L'adresse d'un champ, **nue** — sans le blanc, ni ce qui l'entoure.
///
/// # POURQUOI `sole_address` NE SUFFIT PAS À CE QU'ON AFFICHE OU À QUI L'ON REMET
///
/// `sole_address` sert d'abord à trouver un DOMAINE : sans chevrons, elle rend la
/// valeur entière — blanc de bordure, plis et commentaires compris —, parce que
/// le découpage du domaine écarte ensuite ce qui traîne. C'est juste pour ce
/// qu'elle sert, et faux dès que la valeur est rendue à un client ou employée
/// pour désigner une boîte.
///
/// `From: jean @ example.test` en sortirait tel quel, et il ne désigne personne.
///
/// **CE QU'ON REND ICI PORTE UNE AROBASE ET RIEN QUI NE FASSE QUE L'ENTOURER** :
/// pas de blanc, pas de commentaire, pas de chevron, pas de virgule.
#[must_use]
pub fn bare_address(value: &[u8]) -> Option<&[u8]> {
    let adresse = sole_address(value).ok()?;
    let blanc = |octet: &u8| matches!(*octet, b' ' | b'\t' | b'\r' | b'\n');
    let debut = adresse.iter().position(|octet| !blanc(octet))?;
    let fin = adresse
        .iter()
        .rposition(|octet| !blanc(octet))
        .map_or(debut, |rang| rang.saturating_add(1));
    let nu = adresse
        .get(debut..fin)
        .expect("deux rangs de cette tranche, dans l'ordre");
    let propre = !nu
        .iter()
        .any(|octet| blanc(octet) || matches!(*octet, b'(' | b')' | b'<' | b'>' | b','));
    (propre && nu.contains(&b'@')).then_some(nu)
}

/// Les éléments d'un champ de LISTE d'adresses (`To:`, `Cc:`, `Bcc:`).
///
/// Rend chaque élément tel qu'il est écrit — nom d'affichage compris. C'est à
/// l'appelant d'en tirer une adresse, et de décider ce qu'il fait d'un élément
/// dont il n'y arrive pas.
///
/// # POURQUOI L'ITÉRATEUR NE JETTE PAS CE QU'IL NE SAIT PAS LIRE
///
/// Un destinataire qu'on écarterait en silence ferait remettre le message à moins
/// de monde que l'expéditeur ne l'a demandé, **sans que rien ne le dise**. Rendre
/// l'élément tel quel laisse l'appelant refuser tout le dépôt, ce qui est la seule
/// réponse honnête pour une soumission.
///
/// # LES GROUPES SE TRAVERSENT
///
/// §3.4 de RFC 5322 admet `amis: jean@example.test, marie@example.test;`. Le nom
/// du groupe n'est pas une adresse et ne se rend pas ; ses membres, oui.
#[must_use]
pub fn address_elements(value: &[u8]) -> AddressElements<'_> {
    AddressElements { reste: value }
}

/// Les éléments d'une liste d'adresses, un par un.
#[derive(Debug, Clone, Copy)]
pub struct AddressElements<'a> {
    /// Ce qu'il reste à parcourir.
    reste: &'a [u8],
}

impl<'a> Iterator for AddressElements<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            if self.reste.is_empty() {
                return None;
            }
            let (element, apres) = decouper(self.reste);
            self.reste = apres;
            let nu = element.trim_ascii();
            if !nu.is_empty() {
                return Some(nu);
            }
        }
    }
}

/// Coupe le premier élément d'une liste, et rend ce qui suit.
///
/// **ON PARCOURT UNE FOIS, ET L'ON DÉLIMITE EN CHEMIN.** Découper d'abord sur les
/// virgules couperait un groupe en deux, et une virgule entre guillemets, dans un
/// commentaire ou entre chevrons n'en est pas une.
fn decouper(valeur: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0_usize;
    while i < valeur.len() {
        match valeur.get(i).copied().unwrap_or(0) {
            b'"' => i = fin_de_chaine(valeur, i),
            b'(' => i = fin_de_commentaire(valeur, i),
            b'<' => i = fin_d_angle(valeur, i),
            // §3.4 : `:` ouvre un groupe, `;` le ferme. Ni l'un ni l'autre ne
            // porte d'adresse, et ce qui les entoure en porte.
            b',' | b';' | b':' => {
                let element = valeur.get(..i).unwrap_or_default();
                let apres = valeur.get(i.saturating_add(1)..).unwrap_or_default();
                return (element, apres);
            }
            _ => i = i.saturating_add(1),
        }
    }
    (valeur, &[])
}

/// Les trois lecteurs qui disent OÙ S'ARRÊTE ce qui n'est pas une adresse.
///
/// # ILS VIVENT ICI PARCE QUE DEUX DÉCOUPAGES EN DÉPENDENT
///
/// Une liste d'adresses se coupe sur les virgules — mais une virgule entre
/// guillemets, dans un commentaire ou entre chevrons n'en est pas une. C'est la
/// seule règle difficile du découpage, et elle tient dans ces trois lecteurs.
///
/// L'`ENVELOPE` d'IMAP et la liste des destinataires d'une soumission coupent la
/// même chose. **Deux copies de cette règle finiraient par différer**, et deux
/// vues d'un même message désigneraient alors des destinataires différents.
/// Le squelette de boucle, lui, se réécrit sans danger : c'est ce qu'il parcourt
/// qui est délicat, pas la façon de le parcourir.
/// Le rang qui suit la chaîne citée commençant en `debut`.
pub(crate) fn fin_de_chaine(texte: &[u8], debut: usize) -> usize {
    let mut i = debut.saturating_add(1);
    while i < texte.len() {
        match texte.get(i).copied().unwrap_or(0) {
            b'\\' => i = i.saturating_add(2),
            b'"' => return i.saturating_add(1),
            _ => i = i.saturating_add(1),
        }
    }
    texte.len()
}

/// Le rang qui suit le commentaire commençant en `debut`, imbrications
/// comprises.
pub(crate) fn fin_de_commentaire(texte: &[u8], debut: usize) -> usize {
    let mut profondeur = 0_usize;
    let mut i = debut;
    while i < texte.len() {
        match texte.get(i).copied().unwrap_or(0) {
            b'\\' => i = i.saturating_add(2),
            b'(' => {
                profondeur = profondeur.saturating_add(1);
                i = i.saturating_add(1);
            }
            b')' => {
                profondeur = profondeur.saturating_sub(1);
                i = i.saturating_add(1);
                if profondeur == 0 {
                    return i;
                }
            }
            _ => i = i.saturating_add(1),
        }
    }
    texte.len()
}

/// Le rang qui suit l'adresse entre chevrons commençant en `debut`.
pub(crate) fn fin_d_angle(texte: &[u8], debut: usize) -> usize {
    let mut i = debut.saturating_add(1);
    while i < texte.len() {
        match texte.get(i).copied().unwrap_or(0) {
            b'"' => i = fin_de_chaine(texte, i),
            b'>' => return i.saturating_add(1),
            _ => i = i.saturating_add(1),
        }
    }
    texte.len()
}
