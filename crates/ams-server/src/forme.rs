// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce message ne porte-t-il que son corps ?
//!
//! # LA RÈGLE, ET D'OÙ ELLE VIENT
//!
//! Décision de l'exploitant (2026-09-27) : un message soumis par l'API se donne
//! **corps d'abord** — du texte, du HTML, ou les deux en `multipart/alternative`
//! — et ses pièces jointes **ensuite**, par un brouillon, en morceaux écrits sur
//! disque. Tout le reste — une pièce jointe, une image en ligne, un message
//! transféré, une partie `Content-Disposition: attachment` — ne se soumet pas
//! d'un seul tenant.
//!
//! # POURQUOI ICI, ET NON DANS `ams-mime`
//!
//! Le corps est borné à un mébioctet et tient en mémoire le temps de la
//! requête : cette lecture peut donc découper le message qu'elle a sous la
//! main. Le balayeur d'`ams-mime`, lui, se fait pousser des octets sans les
//! retenir, et ne dit ni le sous-type d'une feuille, ni la nature d'un
//! conteneur — ce qu'il faudrait ici.

/// Combien de `multipart/alternative` peuvent s'emboîter. Un client en écrit
/// un ; au-delà de deux, ce n'est plus un corps.
const PROFONDEUR_MAX: usize = 2;

/// Ce message ne porte-t-il que son corps — texte, HTML, ou les deux ?
#[must_use]
pub fn corps_seul(message: &[u8]) -> bool {
    corps_seul_a(message, 0)
}

fn corps_seul_a(message: &[u8], profondeur: usize) -> bool {
    let Ok(lu) = ams_mime::Message::parse(message, &ams_mime::Limits::DEFAULT) else {
        return false;
    };
    let valeur = |nom: &[u8]| -> Option<Vec<u8>> {
        lu.fields()
            .find(|champ| champ.name_is(nom))
            .map(|champ| champ.unfolded().flatten().copied().collect())
    };
    // **UNE PARTIE QUI SE DIT PIÈCE JOINTE EN EST UNE**, quel que soit son
    // type : un `text/plain` marqué `attachment` est un fichier joint.
    if valeur(b"content-disposition")
        .is_some_and(|disposition| premier_mot(&disposition).eq_ignore_ascii_case(b"attachment"))
    {
        return false;
    }
    // RFC 2045 §5.2 : sans `Content-Type:`, c'est du `text/plain`.
    let Some(genre) = valeur(b"content-type") else {
        return true;
    };
    let type_ = premier_mot(&genre);
    if type_.eq_ignore_ascii_case(b"text/plain") || type_.eq_ignore_ascii_case(b"text/html") {
        return true;
    }
    if !type_.eq_ignore_ascii_case(b"multipart/alternative") || profondeur >= PROFONDEUR_MAX {
        return false;
    }
    let Some(frontiere) = parametre(&genre, b"boundary") else {
        return false;
    };
    let parties = parties(lu.body(), &frontiere);
    !parties.is_empty()
        && parties
            .iter()
            .all(|partie| corps_seul_a(partie, profondeur.saturating_add(1)))
}

/// Ce qui précède le premier `;`, sans blancs.
fn premier_mot(valeur: &[u8]) -> &[u8] {
    valeur
        .split(|octet| *octet == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii()
}

/// La valeur d'un paramètre (`boundary="abc"` ou `boundary=abc`).
fn parametre(valeur: &[u8], nom: &[u8]) -> Option<Vec<u8>> {
    valeur
        .split(|octet| *octet == b';')
        .skip(1)
        .find_map(|morceau| {
            let (clef, brute) = morceau.split_at(morceau.iter().position(|octet| *octet == b'=')?);
            if !clef.trim_ascii().eq_ignore_ascii_case(nom) {
                return None;
            }
            let brute = brute.get(1..).unwrap_or_default().trim_ascii();
            let nue = brute
                .strip_prefix(b"\"")
                .and_then(|reste| reste.strip_suffix(b"\""))
                .unwrap_or(brute);
            (!nue.is_empty()).then(|| nue.to_vec())
        })
}

/// Les parties d'un corps `multipart`, entre ses frontières (RFC 2046 §5.1.1).
///
/// Une frontière est une ligne `--frontière`, en début de ligne ; la dernière
/// est `--frontière--`. Ce qui précède la première et suit la dernière est le
/// préambule et l'épilogue, qu'on ignore. Une partie qui n'est pas fermée ne
/// compte pas : un `multipart` coupé n'est pas un corps.
fn parties<'a>(corps: &'a [u8], frontiere: &[u8]) -> Vec<&'a [u8]> {
    let mut ligne = Vec::with_capacity(frontiere.len().saturating_add(2));
    ligne.extend_from_slice(b"--");
    ligne.extend_from_slice(frontiere);
    let mut rendues = Vec::new();
    let mut debut: Option<usize> = None;
    let mut rang = 0_usize;
    while rang < corps.len() {
        let fin_de_ligne = corps
            .get(rang..)
            .and_then(|reste| reste.windows(2).position(|paire| paire == b"\r\n"))
            .map_or(corps.len(), |position| rang.saturating_add(position));
        let contenu = corps.get(rang..fin_de_ligne).unwrap_or_default();
        if let Some(apres) = contenu.strip_prefix(ligne.as_slice()) {
            let finale = apres.starts_with(b"--");
            if apres.trim_ascii().is_empty() || finale {
                if let Some(ouverte) = debut {
                    // La partie finit AVANT le CRLF qui précède la frontière.
                    let jusque = rang.saturating_sub(2).max(ouverte);
                    rendues.push(corps.get(ouverte..jusque).unwrap_or_default());
                }
                if finale {
                    return rendues;
                }
                debut = Some(fin_de_ligne.saturating_add(2).min(corps.len()));
            }
        }
        rang = fin_de_ligne.saturating_add(2);
    }
    // Pas de frontière finale : ce qui a été ouvert n'a pas été fermé.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::corps_seul;

    #[test]
    fn un_texte_seul_est_un_corps() {
        assert!(corps_seul(b"From: a@b.test\r\n\r\nbonjour\r\n"));
        assert!(corps_seul(
            b"Content-Type: text/plain; charset=utf-8\r\n\r\nbonjour\r\n"
        ));
        assert!(corps_seul(
            b"Content-Type: TEXT/HTML\r\n\r\n<p>bonjour</p>\r\n"
        ));
    }

    #[test]
    fn texte_et_html_en_alternative_sont_un_corps() {
        let message = b"Content-Type: multipart/alternative; boundary=\"b1\"\r\n\r\n\
            preambule\r\n--b1\r\nContent-Type: text/plain\r\n\r\nbonjour\r\n\
            --b1\r\nContent-Type: text/html\r\n\r\n<p>bonjour</p>\r\n--b1--\r\nepilogue\r\n";
        assert!(corps_seul(message));
        // Sans guillemets, et pliée.
        let message = b"Content-Type: multipart/alternative;\r\n boundary=b1\r\n\r\n\
            --b1\r\n\r\nbonjour\r\n--b1--\r\n";
        assert!(corps_seul(message));
    }

    #[test]
    fn une_piece_jointe_n_est_pas_un_corps() {
        for message in [
            &b"Content-Type: application/pdf\r\n\r\n%PDF\r\n"[..],
            b"Content-Type: text/plain\r\nContent-Disposition: attachment; filename=a.txt\r\n\r\nx\r\n",
            b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nx\r\n--b--\r\n",
            b"Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\n\
              Content-Type: image/png\r\n\r\nx\r\n--b--\r\n",
            // Une alternative sans frontière, sans partie, ou jamais fermée.
            b"Content-Type: multipart/alternative\r\n\r\nx\r\n",
            b"Content-Type: multipart/alternative; boundary=\"\"\r\n\r\nx\r\n",
            b"Content-Type: multipart/alternative; boundary=b\r\n\r\n--b--\r\n",
            b"Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\n\r\nx\r\n",
            // Trop d'emboîtements.
            b"Content-Type: multipart/alternative; boundary=a\r\n\r\n--a\r\n\
              Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\n\
              Content-Type: multipart/alternative; boundary=c\r\n\r\n--c\r\n\r\nx\r\n\
              --c--\r\n--b--\r\n--a--\r\n",
            // Illisible.
            b"pas un en-tete\r\n",
        ] {
            assert!(
                !corps_seul(message),
                "{}",
                String::from_utf8_lossy(message)
            );
        }
    }

    /// Deux niveaux d'alternative restent un corps ; un paramètre sans `=` ou
    /// d'un autre nom ne fait pas une frontière.
    #[test]
    fn les_bords_de_la_lecture() {
        let deux = b"Content-Type: multipart/alternative; boundary=a\r\n\r\n--a\r\n\
            Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\n\r\nx\r\n--b--\r\n--a--\r\n";
        assert!(corps_seul(deux));
        let bizarre = b"Content-Type: multipart/alternative; charset; autre=x; boundary=b\r\n\r\n\
            --b\r\n\r\nx\r\n--b other\r\n--b--\r\n";
        assert!(corps_seul(bizarre));
    }
}
