// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Défaire ce que MIME a encodé : mots encodés (RFC 2047) et encodages de
//! transfert (RFC 2045 §6).
//!
//! # POURQUOI DÉCODER, ALORS QU'ON NE DÉCODE NULLE PART AILLEURS
//!
//! Une `ENVELOPE` rend le texte de l'en-tête TEL QUEL, et c'est la règle : le
//! client doit recevoir ce que le message porte. **Chercher est l'exception**, et
//! c'est le contraire d'une contradiction : un `SEARCH SUBJECT "facture"` qui
//! répondrait « aucun résultat » sur un message intitulé `=?utf-8?B?ZmFjdHVyZQ==?=`
//! serait un mensonge exact — précisément ce que le refus de ce critère évitait
//! jusqu'ici.
//!
//! Rendre et chercher ne demandent donc pas la même chose : l'un rend les octets,
//! l'autre cherche le sens.
//!
//! # CE QU'ON NE SAIT PAS LIRE RESTE TEL QUEL
//!
//! Un mot encodé dans un jeu de caractères qu'on ne sait pas convertir — autre
//! que `us-ascii`, `utf-8` et `iso-8859-1` — est recopié SANS ÊTRE DÉCODÉ. Il ne
//! se trouvera donc pas par son texte, et c'est la vérité : mieux vaut ne pas
//! trouver que de trouver autre chose.
//!
//! Un mot encodé mal formé est du texte ordinaire (RFC 2047 §6.3), et non une
//! erreur : c'est ce que la RFC demande, et cela évite qu'un `=?` isolé dans un
//! sujet fasse échouer une recherche.

use crate::error::Error;

/// Ce que le décodage d'une valeur peut occuper au plus.
///
/// **Le décodage peut GRANDIR** : quatre caractères de base64 rendent trois
/// octets `iso-8859-1`, qui font jusqu'à six octets d'UTF-8. Le double majore
/// tout, et se calcule sans lire l'entrée.
#[must_use]
pub fn decoded_max(octets: usize) -> usize {
    octets.saturating_mul(2)
}

/// Décode les mots encodés d'une valeur d'en-tête (RFC 2047).
///
/// # LE BLANC ENTRE DEUX MOTS ENCODÉS DISPARAÎT
///
/// §6.2 : il ne sert qu'à les séparer, et le garder couperait en deux un texte
/// que l'expéditeur a dû découper pour tenir dans une ligne. Le blanc entre un
/// mot encodé et du texte ordinaire, lui, reste.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `out` ne suffit pas — voir [`decoded_max`].
pub fn decode_encoded_words(valeur: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut plume = Sortie::neuve(out);
    let mut i = 0_usize;
    // Le blanc qu'on a mis de côté, en attendant de savoir ce qui le suit.
    let mut blanc = (0_usize, 0_usize);
    let mut precedent_encode = false;
    while i < valeur.len() {
        let octet = valeur.get(i).copied().unwrap_or(0);
        if matches!(octet, b' ' | b'\t' | b'\r' | b'\n') {
            if blanc.0 == blanc.1 {
                blanc = (i, i);
            }
            blanc.1 = i.saturating_add(1);
            i = i.saturating_add(1);
            continue;
        }
        let mot = mot_encode(valeur, i);
        // Le blanc se rend, SAUF entre deux mots encodés.
        if blanc.0 != blanc.1 && !(precedent_encode && mot.is_some()) {
            plume.pousser(valeur.get(blanc.0..blanc.1).unwrap_or_default())?;
        }
        blanc = (0, 0);
        match mot {
            Some((fin, charset, encodage, texte)) => {
                ecrire_le_mot(&mut plume, charset, encodage, texte)?;
                precedent_encode = true;
                i = fin;
            }
            None => {
                plume.pousser(&[octet])?;
                precedent_encode = false;
                i = i.saturating_add(1);
            }
        }
    }
    if blanc.0 != blanc.1 {
        plume.pousser(valeur.get(blanc.0..blanc.1).unwrap_or_default())?;
    }
    Ok(plume.ecrits)
}

/// Un mot encodé commençant en `debut` : sa fin, son jeu, son encodage, son
/// texte.
fn mot_encode(valeur: &[u8], debut: usize) -> Option<(usize, &[u8], u8, &[u8])> {
    // QUATRE REFUS, ET QUATRE SEULEMENT : pas d'ouverture, pas de fin de jeu,
    // pas d'encodage, pas de fermeture. Tout le reste se découpe à des rangs que
    // la recherche vient de rendre — un `?` de plus y serait une garde
    // qu'aucune valeur ne pourrait faire céder.
    let apres = valeur
        .get(debut..)
        .unwrap_or_default()
        .strip_prefix(b"=?")?;
    let fin_jeu = apres.iter().position(|octet| *octet == b'?')?;
    let charset = apres.get(..fin_jeu).unwrap_or_default();
    // `*langue` est admis après le jeu (RFC 2231 §5) : il ne change pas le
    // décodage, et l'ignorer vaut mieux que de refuser le mot entier.
    let charset = match charset.iter().position(|octet| *octet == b'*') {
        Some(rang) => charset.get(..rang).unwrap_or_default(),
        None => charset,
    };
    let reste = apres.get(fin_jeu.saturating_add(1)..).unwrap_or_default();
    let encodage = reste.first().copied()?.to_ascii_uppercase();
    if !matches!(encodage, b'B' | b'Q') || reste.get(1).copied() != Some(b'?') {
        return None;
    }
    let corps = reste.get(2..).unwrap_or_default();
    let fin_texte = corps.windows(2).position(|fenetre| fenetre == b"?=")?;
    let texte = corps.get(..fin_texte).unwrap_or_default();
    // UN MOT ENCODÉ NE PORTE NI BLANC NI FIN DE LIGNE (§2) : ce qui en porte
    // n'en est pas un, et se recopie comme du texte ordinaire.
    if texte
        .iter()
        .any(|octet| matches!(*octet, b' ' | b'\t' | b'\r' | b'\n'))
    {
        return None;
    }
    // `=?` + jeu + `?` + encodage + `?` + texte + `?=`
    let longueur = 2_usize
        .saturating_add(fin_jeu)
        .saturating_add(3)
        .saturating_add(fin_texte)
        .saturating_add(2);
    Some((debut.saturating_add(longueur), charset, encodage, texte))
}

/// Écrit le texte d'un mot encodé, converti en UTF-8 quand on sait le faire.
fn ecrire_le_mot(
    plume: &mut Sortie<'_>,
    charset: &[u8],
    encodage: u8,
    texte: &[u8],
) -> Result<(), Error> {
    let latin1 =
        charset.eq_ignore_ascii_case(b"iso-8859-1") || charset.eq_ignore_ascii_case(b"latin1");
    let connu = latin1
        || charset.eq_ignore_ascii_case(b"utf-8")
        || charset.eq_ignore_ascii_case(b"us-ascii")
        || charset.eq_ignore_ascii_case(b"ascii");
    if !connu {
        // On recopie le mot ENTIER, bornes comprises : le décoder à demi
        // donnerait un texte qui n'est celui d'aucun jeu de caractères.
        plume.pousser(b"=?")?;
        plume.pousser(charset)?;
        plume.pousser(b"?")?;
        plume.pousser(&[encodage])?;
        plume.pousser(b"?")?;
        plume.pousser(texte)?;
        return plume.pousser(b"?=");
    }
    let mut ecrire = |octet: u8| -> Result<(), Error> {
        match latin1 && octet >= 0x80 {
            // `iso-8859-1` vers UTF-8 : deux octets, sans table.
            true => plume.pousser(&[0xC0_u8 | (octet >> 6), 0x80_u8 | (octet & 0x3F)]),
            false => plume.pousser(&[octet]),
        }
    };
    match encodage {
        b'B' => pour_chaque_base64(texte, &mut ecrire),
        _ => pour_chaque_q(texte, &mut ecrire),
    }
}

/// Décode un corps selon son `Content-Transfer-Encoding`.
///
/// Un encodage qu'on ne connaît pas — `7bit`, `8bit`, `binary`, ou tout autre —
/// laisse le corps tel quel : c'est ce qu'il est.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `out` ne suffit pas.
pub fn decode_transfer(encoding: &[u8], corps: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut plume = Sortie::neuve(out);
    let mut ecrire = |octet: u8| plume.pousser(&[octet]);
    if encoding.eq_ignore_ascii_case(b"base64") {
        pour_chaque_base64(corps, &mut ecrire)?;
        return Ok(plume.ecrits);
    }
    if encoding.eq_ignore_ascii_case(b"quoted-printable") {
        pour_chaque_qp(corps, &mut ecrire)?;
        return Ok(plume.ecrits);
    }
    plume.pousser(corps)?;
    Ok(plume.ecrits)
}

/// Décode ce qui tient dans `out`, et dit combien d'octets BRUTS ont servi.
///
/// # POURQUOI S'ARRÊTER À UNE FRONTIÈRE, ET NON OÙ LA PLACE MANQUE
///
/// Le décodage d'une pièce jointe ne tient pas en mémoire : il faut le REPRENDRE
/// là où on l'a laissé. Reprendre au milieu d'un groupe de base64 demanderait de
/// retenir les bits en cours — donc un état, que l'appelant devrait porter d'un
/// morceau à l'autre et qu'il finirait par perdre. On s'arrête donc à un rang où
/// **il n'y a rien à retenir** : un groupe complet pour le base64, un octet qui
/// n'ouvre pas d'échappement pour le quoted-printable.
///
/// `dernier` dit que `brut` finit le contenu. **IL LE FAUT** : le remplissage
/// du base64 rend le dernier groupe PARTIEL — deux ou trois caractères pour un
/// ou deux octets —, et un décodeur qui n'attendrait que des groupes entiers
/// perdrait la fin de chaque pièce jointe. Seul l'appelant sait où le contenu
/// s'arrête.
///
/// Rend `(octets bruts consommés, octets écrits)`. Zéro consommé veut dire que
/// `out` est trop petit pour avancer, ce qui n'arrive qu'avec moins de trois
/// octets de place.
///
/// # Errors
///
/// [`Error::UnknownEncoding`] pour un encodage qu'on ne sait pas défaire.
pub fn decode_chunk(
    encoding: &[u8],
    brut: &[u8],
    dernier: bool,
    out: &mut [u8],
) -> Result<(usize, usize), Error> {
    if encoding.eq_ignore_ascii_case(b"base64") {
        return Ok(morceau_base64(brut, dernier, out));
    }
    if encoding.eq_ignore_ascii_case(b"quoted-printable") {
        return Ok(morceau_qp(brut, dernier, out));
    }
    if !encodage_transparent(encoding) {
        return Err(Error::UnknownEncoding);
    }
    // `7bit`, `8bit`, `binary` : les octets SONT le contenu.
    let voulu = brut.len().min(out.len());
    for (place, octet) in out.iter_mut().zip(brut.get(..voulu).unwrap_or_default()) {
        *place = *octet;
    }
    Ok((voulu, voulu))
}

/// Cet encodage laisse-t-il les octets tels quels (RFC 2045 §6.2, §6.8) ?
fn encodage_transparent(encoding: &[u8]) -> bool {
    encoding.is_empty()
        || encoding.eq_ignore_ascii_case(b"7bit")
        || encoding.eq_ignore_ascii_case(b"8bit")
        || encoding.eq_ignore_ascii_case(b"binary")
}

/// Décode des groupes ENTIERS de base64, tant que la place le permet.
fn morceau_base64(brut: &[u8], dernier: bool, out: &mut [u8]) -> (usize, usize) {
    let mut accumulateur = 0_u32;
    let mut dans_le_groupe = 0_usize;
    let mut consommes = 0_usize;
    let mut ecrits = 0_usize;
    for (rang, octet) in brut.iter().enumerate() {
        let Some(valeur) = valeur_base64(*octet) else {
            // Blancs, `=`, et tout ce qui n'est pas du base64 : ignorés, comme
            // partout ailleurs — le pliage en sème.
            //
            // **ILS AVANCENT QUAND MÊME LE CURSEUR**, tant qu'aucun groupe n'est
            // entamé : sans cela, une fenêtre entière de pliage ne consommerait
            // rien, et l'appelant tournerait en rond sur le même rang.
            if dans_le_groupe == 0 {
                consommes = rang.saturating_add(1);
            }
            continue;
        };
        accumulateur = (accumulateur << 6) | u32::from(valeur);
        dans_le_groupe = dans_le_groupe.saturating_add(1);
        if dans_le_groupe < 4 {
            continue;
        }
        // Un groupe complet rend trois octets : il faut la place pour les trois,
        // sans quoi on s'arrêterait au milieu.
        if ecrits.saturating_add(3) > out.len() {
            break;
        }
        ecrits = ecrits.saturating_add(poser(out, ecrits, accumulateur, 3));
        accumulateur = 0;
        dans_le_groupe = 0;
        consommes = rang.saturating_add(1);
    }
    // LE DERNIER GROUPE EST PARTIEL, et c'est le remplissage qui le veut :
    // `YQ==` porte deux caractères pour un octet, `YWI=` trois pour deux. Ne
    // rendre que des groupes entiers perdrait la fin de chaque pièce jointe.
    let reste = dans_le_groupe.saturating_sub(1);
    if dernier && dans_le_groupe >= 2 && ecrits.saturating_add(reste) <= out.len() {
        // Les bits manquants valent zéro : on cale le groupe à gauche.
        let cale = accumulateur
            << (6_u32
                .saturating_mul(4_u32.saturating_sub(u32::try_from(dans_le_groupe).unwrap_or(4))));
        ecrits = ecrits.saturating_add(poser(out, ecrits, cale, reste));
        consommes = brut.len();
    }
    (consommes, ecrits)
}

/// Écrit les `combien` octets de poids fort d'un groupe, et rend combien ont
/// tenu.
///
/// # `zip` PLUTÔT QU'UN INDICE
///
/// La place a été vérifiée juste avant ; un `get_mut` y serait une garde
/// qu'aucune entrée ne pourrait faire céder. Le `zip`, lui, s'arrête de lui-même
/// à la plus courte des deux suites.
fn poser(out: &mut [u8], depuis: usize, groupe: u32, combien: usize) -> usize {
    let trio = [
        u8::try_from((groupe >> 16) & 0xFF).unwrap_or(0),
        u8::try_from((groupe >> 8) & 0xFF).unwrap_or(0),
        u8::try_from(groupe & 0xFF).unwrap_or(0),
    ];
    let mut poses = 0_usize;
    for (place, octet) in out
        .iter_mut()
        .skip(depuis)
        .zip(trio.get(..combien).unwrap_or_default())
    {
        *place = *octet;
        poses = poses.saturating_add(1);
    }
    poses
}

/// Décode du quoted-printable, en s'arrêtant hors d'un échappement.
fn morceau_qp(brut: &[u8], dernier: bool, out: &mut [u8]) -> (usize, usize) {
    let mut i = 0_usize;
    let mut ecrits = 0_usize;
    while i < brut.len() {
        let octet = brut.get(i).copied().unwrap_or(0);
        if octet == b'=' {
            let suite = brut.get(i.saturating_add(1)..).unwrap_or_default();
            // UN ÉCHAPPEMENT À CHEVAL SUR DEUX MORCEAUX NE SE DEVINE PAS : on
            // s'arrête avant lui, et le morceau suivant le lira entier. Sauf
            // s'il n'y a pas de morceau suivant : un `=` qui finit le contenu
            // n'échappe rien, et se rend tel quel (RFC 2045 §6.7).
            if !dernier && suite.len() < 2 && !suite.starts_with(b"\n") {
                break;
            }
            if let Some(saut) = coupure_molle(suite) {
                i = i.saturating_add(saut).saturating_add(1);
                continue;
            }
        }
        let (valeur, saut) = octet_echappe(brut, i, octet);
        // Même raison qu'au-dessus : `zip` s'arrête seul, et la place a été
        // vérifiée.
        let mut pose = false;
        for place in out.iter_mut().skip(ecrits).take(1) {
            *place = valeur;
            pose = true;
        }
        if !pose {
            break;
        }
        ecrits = ecrits.saturating_add(1);
        i = i.saturating_add(saut);
    }
    (i, ecrits)
}

/// Donne à `ecrire` chaque octet d'un base64, blancs ignorés.
fn pour_chaque_base64(
    texte: &[u8],
    ecrire: &mut impl FnMut(u8) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut accumulateur = 0_u32;
    let mut bits = 0_u32;
    for octet in texte {
        let Some(valeur) = valeur_base64(*octet) else {
            // Un octet qui n'est pas du base64 — blanc, `=`, ou n'importe quoi
            // d'autre — ne se devine pas : on l'ignore. C'est ce que fait tout
            // décodeur de courrier, parce que le pliage en sème partout.
            continue;
        };
        accumulateur = (accumulateur << 6) | u32::from(valeur);
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            let sorti = (accumulateur >> bits) & 0xFF;
            ecrire(u8::try_from(sorti).unwrap_or(0))?;
        }
    }
    Ok(())
}

/// La valeur d'un caractère base64, s'il en est un.
fn valeur_base64(octet: u8) -> Option<u8> {
    match octet {
        b'A'..=b'Z' => Some(octet.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(octet.wrapping_sub(b'a').saturating_add(26)),
        b'0'..=b'9' => Some(octet.wrapping_sub(b'0').saturating_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Donne à `ecrire` chaque octet d'un `Q` de mot encodé (RFC 2047 §4.2).
///
/// Le `_` y vaut une espace, ce qui est la SEULE différence avec le
/// quoted-printable ordinaire — et celle qu'on oublie.
fn pour_chaque_q(
    texte: &[u8],
    ecrire: &mut impl FnMut(u8) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut i = 0_usize;
    while i < texte.len() {
        let octet = texte.get(i).copied().unwrap_or(0);
        if octet == b'_' {
            ecrire(b' ')?;
            i = i.saturating_add(1);
            continue;
        }
        let (valeur, saut) = octet_echappe(texte, i, octet);
        ecrire(valeur)?;
        i = i.saturating_add(saut);
    }
    Ok(())
}

/// Donne à `ecrire` chaque octet d'un quoted-printable (RFC 2045 §6.7).
fn pour_chaque_qp(
    texte: &[u8],
    ecrire: &mut impl FnMut(u8) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut i = 0_usize;
    while i < texte.len() {
        let octet = texte.get(i).copied().unwrap_or(0);
        // UN `=` EN FIN DE LIGNE EST UNE COUPURE MOLLE : elle disparaît, et la
        // ligne suivante se recolle à celle-ci. L'oublier ferait apparaître des
        // fins de ligne au milieu des mots.
        if octet == b'=' {
            let suite = texte.get(i.saturating_add(1)..).unwrap_or_default();
            if let Some(saut) = coupure_molle(suite) {
                i = i.saturating_add(saut).saturating_add(1);
                continue;
            }
        }
        let (valeur, saut) = octet_echappe(texte, i, octet);
        ecrire(valeur)?;
        i = i.saturating_add(saut);
    }
    Ok(())
}

/// Combien d'octets une coupure molle occupe après le `=`, si c'en est une.
fn coupure_molle(suite: &[u8]) -> Option<usize> {
    if suite.starts_with(b"\r\n") {
        return Some(2);
    }
    match suite.first().copied() {
        Some(b'\n') => Some(1),
        _ => None,
    }
}

/// L'octet que `=XX` désigne, et ce qu'il occupe. Ailleurs, l'octet lui-même.
fn octet_echappe(texte: &[u8], rang: usize, octet: u8) -> (u8, usize) {
    if octet != b'=' {
        return (octet, 1);
    }
    let haut = texte.get(rang.saturating_add(1)).copied().and_then(quartet);
    let bas = texte.get(rang.saturating_add(2)).copied().and_then(quartet);
    match (haut, bas) {
        // `=` suivi d'autre chose que deux chiffres hexadécimaux n'échappe
        // rien : RFC 2045 §6.7 veut qu'on le laisse tel quel plutôt que de
        // deviner.
        (Some(haut), Some(bas)) => ((haut << 4) | bas, 3),
        _ => (octet, 1),
    }
}

/// La valeur d'un chiffre hexadécimal.
fn quartet(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(octet.wrapping_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(octet.wrapping_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// De quoi écrire dans un tampon fixe.
struct Sortie<'a> {
    out: &'a mut [u8],
    ecrits: usize,
}

impl<'a> Sortie<'a> {
    fn neuve(out: &'a mut [u8]) -> Self {
        Self { out, ecrits: 0 }
    }

    fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(morceau.len());
        let place = self
            .out
            .get_mut(self.ecrits..fin)
            .ok_or(Error::BufferTooSmall)?;
        place.copy_from_slice(morceau);
        self.ecrits = fin;
        Ok(())
    }
}

#[cfg(test)]
#[path = "decode/tests.rs"]
mod tests;
