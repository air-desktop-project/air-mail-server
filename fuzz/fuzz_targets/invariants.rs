//! Ce qu'un message accepté doit tenir, quelles que soient les bornes.
//!
//! Partagé par les deux cibles : elles ne diffèrent que par la provenance des
//! bornes, jamais par ce qu'elles exigent d'une entrée acceptée.

use ams_mime::{Limits, Message};

/// Vérifie tout ce que `Message::parse` a promis en rendant `Ok`.
///
/// `input` est l'entrée d'origine — elle sert à la propriété de totalité, qui est
/// la plus forte des sept.
pub fn verifier(input: &[u8], message: &Message<'_>, limits: &Limits) {
    let entete = message.header_block();
    let corps = message.body();

    // 1. LE DÉCOUPAGE NE PERD NI N'INVENTE RIEN.
    //
    // La plus forte des propriétés, et la moins chère : l'entrée est exactement
    // l'en-tête, puis le CRLF vide, puis le corps. Un décodeur qui laisserait
    // tomber un octet, ou en dupliquerait un, échouerait ici — et un octet perdu
    // entre l'en-tête et le corps, c'est un en-tête qui devient du texte, ou
    // l'inverse.
    let mut recompose = Vec::with_capacity(input.len());
    recompose.extend_from_slice(entete);
    recompose.extend_from_slice(b"\r\n");
    recompose.extend_from_slice(corps);
    assert_eq!(
        recompose, input,
        "le découpage a perdu ou inventé des octets"
    );

    // 2. AUCUN CR NI LF ISOLÉ N'A SURVÉCU DANS L'EN-TÊTE.
    //
    // C'est la propriété qui ferme la contrebande SMTP : si un octet de fin de
    // ligne ambigu passait, le serveur suivant pourrait découper autrement et
    // voir un message que celui-ci n'a pas vu.
    let mut precedent = None;
    for (rang, &octet) in entete.iter().enumerate() {
        if octet == b'\n' {
            assert_eq!(
                precedent,
                Some(b'\r'),
                "LF isolé accepté à l'offset {rang} : {entete:?}"
            );
        }
        if precedent == Some(b'\r') {
            assert_eq!(
                octet, b'\n',
                "CR isolé accepté à l'offset {rang} : {entete:?}"
            );
        }
        precedent = Some(octet);
    }
    assert_ne!(
        precedent,
        Some(b'\r'),
        "l'en-tête se termine par un CR isolé"
    );

    // 3. LES BORNES ANNONCÉES SONT TENUES.
    assert!(
        entete.len() <= limits.max_header_octets,
        "en-tête au-delà de la borne"
    );
    for ligne in entete.split(|&b| b == b'\n') {
        let sans_cr = ligne.strip_suffix(b"\r").unwrap_or(ligne);
        assert!(
            sans_cr.len() <= limits.max_line_octets,
            "ligne au-delà de la borne : {sans_cr:?}"
        );
    }

    let mut champs = 0_usize;
    for champ in message.fields() {
        champs = champs.saturating_add(1);

        // 4. UN NOM DE CHAMP ACCEPTÉ EST NON VIDE ET DANS `ftext`.
        assert!(!champ.name().is_empty(), "nom de champ vide accepté");
        assert!(
            champ.name().iter().all(|&b| (33..=126).contains(&b)),
            "nom de champ hors %d33-126 accepté : {:?}",
            champ.name()
        );

        // 5. DÉPLIER NE PEUT QUE RETIRER DES OCTETS.
        let deplie: usize = champ.unfolded().map(<[u8]>::len).sum();
        assert!(
            deplie <= champ.raw_value().len(),
            "le dépliage a inventé des octets"
        );

        // 6. UN MORCEAU DÉPLIÉ NE CONTIENT PLUS DE FIN DE LIGNE.
        for morceau in champ.unfolded() {
            assert!(
                !morceau.contains(&b'\r') && !morceau.contains(&b'\n'),
                "un morceau déplié porte encore une fin de ligne : {morceau:?}"
            );
        }

        // 7. LA COMPARAISON DE NOM EST INSENSIBLE À LA CASSE, ET RÉFLEXIVE.
        assert!(champ.name_is(champ.name()), "un nom ne se reconnaît pas");
    }
    assert!(champs <= limits.max_fields, "plus de champs que la borne");
}
