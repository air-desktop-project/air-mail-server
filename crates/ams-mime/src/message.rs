//! Le squelette d'un message : en-tête, corps, champs, dépliage.

use crate::{Error, Limits};

/// Une tranche vide, pour les fins de parcours.
const EMPTY: &[u8] = &[];

/// Un message découpé en bloc d'en-tête et corps.
///
/// **La validation a lieu une fois, à la construction.** Passé
/// [`Message::parse`], plus rien ne peut échouer : [`Message::fields`] et
/// [`Field::unfolded`] ne rendent pas de `Result`, parce qu'il n'y a plus rien à
/// refuser. C'est ce qui permet aux appelants de ne pas semer des `?` sur des
/// chemins qui ne peuvent pas se tromper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    header_block: &'a [u8],
    body: &'a [u8],
}

impl<'a> Message<'a> {
    /// Découpe et valide un message.
    ///
    /// Le **corps n'est pas examiné** : il est rendu tel quel. Ses propres bornes
    /// relèvent de qui l'a produit — en SMTP, de la commande `DATA`, qui les
    /// applique au fil de la réception plutôt qu'après coup.
    ///
    /// # Errors
    ///
    /// Toutes les variantes d'[`Error`]. Aucune allocation n'a lieu, ni avant ni
    /// après : les longueurs venues du réseau servent à borner, jamais à réserver.
    pub fn parse(input: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        let (header_block, body) = split_at_blank_line(input)?;
        validate(header_block, limits)?;
        Ok(Self { header_block, body })
    }

    /// Le bloc d'en-tête brut, CRLF compris, sans la ligne vide qui le termine.
    #[must_use]
    pub fn header_block(&self) -> &'a [u8] {
        self.header_block
    }

    /// Le corps brut, tel qu'il a été reçu.
    #[must_use]
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Les champs d'en-tête, dans leur ordre d'apparition.
    ///
    /// L'ordre est significatif : plusieurs `Received` racontent un chemin, et
    /// les trier le détruirait.
    #[must_use]
    pub fn fields(&self) -> Fields<'a> {
        Fields {
            rest: self.header_block,
        }
    }
}

/// Sépare l'en-tête du corps sur la première ligne vide.
fn split_at_blank_line(input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    // Un message qui commence par une ligne vide n'a aucun champ. C'est
    // structurellement représentable, et ce n'est pas à cette couche de l'interdire :
    // exiger `From` et `Date` (RFC 5322 §3.6) est une règle de contenu, pas de
    // grammaire.
    if let [b'\r', b'\n', body @ ..] = input {
        return Ok((EMPTY, body));
    }
    let at = input
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(Error::MissingSeparator)?;
    // `at` désigne le CR qui termine le dernier champ ; le bloc d'en-tête inclut
    // ce CRLF, pour que toutes ses lignes se terminent de la même façon.
    let (header_block, after) = input.split_at(at.saturating_add(2));
    Ok((header_block, after.get(2..).unwrap_or(EMPTY)))
}

/// Découpe une ligne terminée par CRLF, en refusant tout CR ou LF isolé.
///
/// Rend `(contenu sans CRLF, reste)`.
fn next_line<'a>(
    rest: &'a [u8],
    line: usize,
    limits: &Limits,
) -> Result<(&'a [u8], &'a [u8]), Error> {
    // `unwrap_or` plutôt qu'un `ok_or(...)?` : le bloc d'en-tête se termine
    // TOUJOURS par un CRLF — `split_at_blank_line` le construit ainsi — donc
    // l'absence de fin de ligne ne peut pas se produire. Un `?` ouvrirait ici une
    // branche que rien ne saurait exercer, et C2 la compterait à jamais découverte.
    let at = rest
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(rest.len());
    let (content, from_break) = rest.split_at(at);
    if content.len() > limits.max_line_octets {
        return Err(Error::LineTooLong {
            line,
            limit: limits.max_line_octets,
        });
    }
    match from_break {
        [b'\r', b'\n', remainder @ ..] => Ok((content, remainder)),
        [b'\n', ..] => Err(Error::BareLineFeed { line }),
        // Le CR isolé. Ce bras absorbe aussi le cas « aucune fin de ligne »,
        // impossible par construction : le loger ici plutôt que dans une variante
        // à lui évite une branche morte, au prix d'un message qui ne sera jamais lu.
        _ => Err(Error::BareCarriageReturn { line }),
    }
}

/// Valide le bloc d'en-tête, ligne par ligne.
fn validate(header_block: &[u8], limits: &Limits) -> Result<(), Error> {
    if header_block.len() > limits.max_header_octets {
        return Err(Error::HeaderTooLong {
            limit: limits.max_header_octets,
        });
    }
    let mut rest = header_block;
    let mut line: usize = 1;
    let mut fields: usize = 0;
    while !rest.is_empty() {
        let (content, remainder) = next_line(rest, line, limits)?;
        match content.first() {
            // Une continuation (RFC 5322 §2.2.3). Elle doit continuer quelque chose.
            Some(b' ' | b'\t') => {
                if fields == 0 {
                    return Err(Error::FoldedFirstField { line });
                }
            }
            // Un nouveau champ. Le cas d'une ligne vide tombe ici aussi — il ne
            // peut pas se produire, le bloc s'arrêtant à la première ligne vide —
            // et `check_field_name` le refuserait comme un nom vide.
            _ => {
                fields = fields.saturating_add(1);
                if fields > limits.max_fields {
                    return Err(Error::TooManyFields {
                        limit: limits.max_fields,
                    });
                }
                check_field_name(content, line)?;
            }
        }
        rest = remainder;
        line = line.saturating_add(1);
    }
    Ok(())
}

/// Vérifie qu'une ligne de champ porte un nom recevable.
fn check_field_name(content: &[u8], line: usize) -> Result<(), Error> {
    let at = content
        .iter()
        .position(|&b| b == b':')
        .ok_or(Error::MissingColon { line })?;
    let (name, _) = content.split_at(at);
    if name.is_empty() {
        return Err(Error::EmptyFieldName { line });
    }
    // RFC 5322 §3.6.8 : `ftext` = %d33-57 / %d59-126, c'est-à-dire l'imprimable
    // US-ASCII sauf le deux-points. Le nom s'arrête AVANT le deux-points, donc
    // l'exclure une seconde fois serait une condition que rien ne peut exercer.
    if !name.iter().all(|&b| (33..=126).contains(&b)) {
        return Err(Error::InvalidFieldName { line });
    }
    Ok(())
}

/// Les champs d'un bloc d'en-tête validé.
#[derive(Debug, Clone, Copy)]
pub struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Fields<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Field<'a>> {
        if self.rest.is_empty() {
            return None;
        }
        // Un champ s'achève au premier CRLF qui n'est PAS suivi d'un blanc :
        // celui qui l'est plie la ligne suivante dans le même champ.
        let (raw, remainder) = match self
            .rest
            .windows(3)
            .position(|w| w[0] == b'\r' && w[1] == b'\n' && w[2] != b' ' && w[2] != b'\t')
        {
            Some(at) => self.rest.split_at(at.saturating_add(2)),
            // Le dernier champ : son CRLF final termine le bloc, et aucune
            // fenêtre de trois octets ne peut l'atteindre.
            None => (self.rest, EMPTY),
        };
        self.rest = remainder;
        Some(Field::from_raw(raw))
    }
}

/// Un champ d'en-tête : un nom, et une valeur encore pliée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> Field<'a> {
    /// Découpe un champ brut, CRLF final compris.
    fn from_raw(raw: &'a [u8]) -> Self {
        let trimmed = raw.get(..raw.len().saturating_sub(2)).unwrap_or(EMPTY);
        // Le bloc est validé : le deux-points est là. `unwrap_or` plutôt qu'un
        // `if let` — un bras que rien ne peut exercer n'a pas sa place ici.
        let at = trimmed
            .iter()
            .position(|&b| b == b':')
            .unwrap_or(trimmed.len());
        let (name, from_colon) = trimmed.split_at(at);
        Self {
            name,
            value: from_colon.get(1..).unwrap_or(EMPTY),
        }
    }

    /// Le nom du champ, sans le deux-points.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// La valeur brute, **encore pliée** : elle peut contenir des CRLF.
    #[must_use]
    pub fn raw_value(&self) -> &'a [u8] {
        self.value
    }

    /// Le nom vaut-il `expected`, à la casse près ?
    ///
    /// Les noms de champ sont insensibles à la casse (RFC 5322 §1.2.2), et les
    /// comparer octet à octet est une erreur classique.
    #[must_use]
    pub fn name_is(&self, expected: &[u8]) -> bool {
        self.name.eq_ignore_ascii_case(expected)
    }

    /// La valeur dépliée, morceau par morceau.
    ///
    /// Déplier, c'est **retirer les CRLF, et rien d'autre** (RFC 5322 §2.2.3) :
    /// le blanc qui suit appartient à la valeur et reste en place. Concaténer les
    /// morceaux rendus, sans rien insérer entre eux, donne la valeur dépliée.
    ///
    /// L'itérateur ne concatène pas lui-même : cette crate n'alloue pas, et c'est
    /// à l'appelant de choisir où poser les octets — un tampon qu'il a déjà, ou
    /// aucun s'il lui suffit de comparer.
    #[must_use]
    pub fn unfolded(&self) -> Unfolded<'a> {
        Unfolded { rest: self.value }
    }
}

/// Les morceaux d'une valeur dépliée.
#[derive(Debug, Clone, Copy)]
pub struct Unfolded<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Unfolded<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.rest.is_empty() {
            return None;
        }
        match self.rest.windows(2).position(|w| w == b"\r\n") {
            Some(at) => {
                let (segment, after) = self.rest.split_at(at);
                self.rest = after.get(2..).unwrap_or(EMPTY);
                Some(segment)
            }
            None => {
                let segment = self.rest;
                self.rest = EMPTY;
                Some(segment)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Field, Message};
    use crate::{Error, Limits};

    /// Concatène une valeur dépliée. La crate n'alloue pas ; les tests, si.
    fn deplier(champ: &Field<'_>) -> std::vec::Vec<u8> {
        let mut octets = std::vec::Vec::new();
        for morceau in champ.unfolded() {
            octets.extend_from_slice(morceau);
        }
        octets
    }

    fn analyser(brut: &[u8]) -> Result<Message<'_>, Error> {
        Message::parse(brut, &Limits::DEFAULT)
    }

    // ── Le cas ordinaire ────────────────────────────────────────────────────

    #[test]
    fn un_message_ordinaire_se_decoupe() {
        let message = analyser(b"From: moi\r\nTo: toi\r\n\r\nle corps").expect("recevable");
        assert_eq!(message.body(), b"le corps");
        assert_eq!(message.header_block(), b"From: moi\r\nTo: toi\r\n");

        let champs: std::vec::Vec<_> = message.fields().collect();
        assert_eq!(champs.len(), 2);
        assert_eq!(champs[0].name(), b"From");
        assert_eq!(champs[0].raw_value(), b" moi");
        assert_eq!(champs[1].name(), b"To");
    }

    #[test]
    fn un_corps_vide_reste_un_corps() {
        let message = analyser(b"From: moi\r\n\r\n").expect("recevable");
        assert_eq!(message.body(), b"");
        assert_eq!(message.fields().count(), 1);
    }

    #[test]
    fn l_ordre_des_champs_est_preserve() {
        // Plusieurs `Received` racontent un chemin ; les trier le détruirait.
        let message = analyser(b"Received: a\r\nReceived: b\r\nReceived: c\r\n\r\n").expect("ok");
        let valeurs: std::vec::Vec<_> = message.fields().map(|c| c.raw_value()).collect();
        assert_eq!(valeurs, [b" a", b" b", b" c"]);
    }

    #[test]
    fn les_noms_sont_insensibles_a_la_casse() {
        let message = analyser(b"SuBjEcT: bonjour\r\n\r\n").expect("recevable");
        let champ = message.fields().next().expect("un champ");
        assert!(champ.name_is(b"subject"));
        assert!(champ.name_is(b"SUBJECT"));
        assert!(!champ.name_is(b"from"));
    }

    // ── Le pliage ───────────────────────────────────────────────────────────

    #[test]
    fn deplier_retire_les_crlf_et_rien_d_autre() {
        // RFC 5322 §2.2.3 : le blanc qui suit le CRLF appartient à la valeur.
        let message = analyser(b"Subject: un\r\n sujet\r\n\tplie\r\n\r\n").expect("recevable");
        let champ = message.fields().next().expect("un champ");
        assert_eq!(deplier(&champ), b" un sujet\tplie");
        // La valeur BRUTE, elle, garde ses CRLF.
        assert_eq!(champ.raw_value(), b" un\r\n sujet\r\n\tplie");
    }

    #[test]
    fn un_champ_plie_n_avale_pas_le_suivant() {
        let message = analyser(b"A: un\r\n plie\r\nB: deux\r\n\r\n").expect("recevable");
        let champs: std::vec::Vec<_> = message.fields().collect();
        assert_eq!(champs.len(), 2);
        assert_eq!(deplier(&champs[0]), b" un plie");
        assert_eq!(deplier(&champs[1]), b" deux");
    }

    #[test]
    fn une_valeur_vide_se_deplie_en_rien() {
        let message = analyser(b"X:\r\n\r\n").expect("recevable");
        let champ = message.fields().next().expect("un champ");
        assert_eq!(champ.raw_value(), b"");
        assert_eq!(champ.unfolded().count(), 0);
    }

    // ── CR et LF isolés : le cœur du sujet ──────────────────────────────────

    #[test]
    fn un_cr_isole_est_refuse() {
        assert_eq!(
            analyser(b"From: moi\rTo: toi\r\n\r\n"),
            Err(Error::BareCarriageReturn { line: 1 })
        );
    }

    #[test]
    fn un_lf_isole_est_refuse() {
        // C'est la divergence d'interprétation de cet octet-là qui a rendu la
        // contrebande SMTP possible en 2023.
        assert_eq!(
            analyser(b"From: moi\nTo: toi\r\n\r\n"),
            Err(Error::BareLineFeed { line: 1 })
        );
    }

    #[test]
    fn le_numero_de_ligne_designe_la_bonne_ligne() {
        assert_eq!(
            analyser(b"A: un\r\nB: deux\r\nC: \ntrois\r\n\r\n"),
            Err(Error::BareLineFeed { line: 3 })
        );
    }

    #[test]
    fn le_corps_n_est_pas_examine() {
        // Un corps peut porter ce qu'il veut : ses bornes relèvent de qui l'a
        // produit — en SMTP, de `DATA`, qui les applique au fil de la réception.
        let message = analyser(b"From: moi\r\n\r\nligne\nsans\rcrlf").expect("recevable");
        assert_eq!(message.body(), b"ligne\nsans\rcrlf");
    }

    // ── La séparation en-tête / corps ───────────────────────────────────────

    #[test]
    fn sans_ligne_vide_le_message_est_refuse() {
        assert_eq!(analyser(b"From: moi\r\n"), Err(Error::MissingSeparator));
        assert_eq!(analyser(b""), Err(Error::MissingSeparator));
    }

    #[test]
    fn un_message_sans_aucun_champ_est_structurellement_valide() {
        // Exiger `From` et `Date` est une règle de CONTENU (RFC 5322 §3.6), pas
        // de grammaire : ce n'est pas à cette couche de la faire respecter.
        let message = analyser(b"\r\njuste un corps").expect("recevable");
        assert_eq!(message.header_block(), b"");
        assert_eq!(message.body(), b"juste un corps");
        assert_eq!(message.fields().count(), 0);
    }

    #[test]
    fn la_premiere_ligne_vide_separe_meme_s_il_y_en_a_d_autres() {
        let message = analyser(b"A: un\r\n\r\ncorps\r\n\r\nsuite").expect("recevable");
        assert_eq!(message.body(), b"corps\r\n\r\nsuite");
    }

    // ── Les noms de champ ───────────────────────────────────────────────────

    #[test]
    fn un_champ_sans_deux_points_est_refuse() {
        assert_eq!(
            analyser(b"From moi\r\n\r\n"),
            Err(Error::MissingColon { line: 1 })
        );
    }

    #[test]
    fn un_nom_de_champ_vide_est_refuse() {
        assert_eq!(
            analyser(b": rien\r\n\r\n"),
            Err(Error::EmptyFieldName { line: 1 })
        );
    }

    #[test]
    fn un_espace_avant_le_deux_points_est_refuse() {
        // `ftext` (RFC 5322 §3.6.8) exclut l'espace. Le tolérer rouvrirait une
        // divergence d'interprétation entre implémentations.
        assert_eq!(
            analyser(b"From : moi\r\n\r\n"),
            Err(Error::InvalidFieldName { line: 1 })
        );
    }

    #[test]
    fn un_octet_non_imprimable_dans_un_nom_est_refuse() {
        assert_eq!(
            analyser(b"Fr\x7fom: moi\r\n\r\n"),
            Err(Error::InvalidFieldName { line: 1 })
        );
    }

    #[test]
    fn les_bornes_de_ftext_sont_acceptees() {
        // `!` vaut 33 et `~` vaut 126 : les deux extrémités exactes.
        let message = analyser(b"!~: valeur\r\n\r\n").expect("recevable");
        assert_eq!(message.fields().next().expect("un champ").name(), b"!~");
    }

    #[test]
    fn une_continuation_en_tete_ne_continue_rien() {
        assert_eq!(
            analyser(b" plie\r\nFrom: moi\r\n\r\n"),
            Err(Error::FoldedFirstField { line: 1 })
        );
    }

    // ── Les bornes (C3) ─────────────────────────────────────────────────────

    #[test]
    fn une_ligne_trop_longue_est_refusee() {
        let bornes = Limits {
            max_line_octets: 5,
            ..Limits::DEFAULT
        };
        assert_eq!(
            Message::parse(b"From: moi\r\n\r\n", &bornes),
            Err(Error::LineTooLong { line: 1, limit: 5 })
        );
        // La borne est un maximum inclusif.
        let bornes = Limits {
            max_line_octets: 9,
            ..Limits::DEFAULT
        };
        assert!(Message::parse(b"From: moi\r\n\r\n", &bornes).is_ok());
    }

    #[test]
    fn trop_de_champs_est_refuse() {
        let bornes = Limits {
            max_fields: 1,
            ..Limits::DEFAULT
        };
        assert_eq!(
            Message::parse(b"A: un\r\nB: deux\r\n\r\n", &bornes),
            Err(Error::TooManyFields { limit: 1 })
        );
        // Une continuation n'est pas un champ de plus.
        assert!(Message::parse(b"A: un\r\n plie\r\n\r\n", &bornes).is_ok());
    }

    #[test]
    fn un_en_tete_trop_gros_est_refuse() {
        let bornes = Limits {
            max_header_octets: 5,
            ..Limits::DEFAULT
        };
        assert_eq!(
            Message::parse(b"From: moi\r\n\r\n", &bornes),
            Err(Error::HeaderTooLong { limit: 5 })
        );
    }

    // ── Les types se copient, se comparent, se déboguent ────────────────────

    #[test]
    fn les_types_publics_se_copient_et_se_deboguent() {
        let message = analyser(b"A: un\r\n\r\n").expect("recevable");
        let copie = message;
        assert_eq!(copie, message);
        assert!(!std::format!("{message:?}").is_empty());

        let champs = message.fields();
        assert!(!std::format!("{champs:?}").is_empty());
        assert_eq!(champs.count(), 1);

        let champ = message.fields().next().expect("un champ");
        assert_eq!(champ, champ);
        assert!(!std::format!("{champ:?}").is_empty());

        let deplie = champ.unfolded();
        assert!(!std::format!("{deplie:?}").is_empty());
        assert_eq!(deplie.count(), 1);
    }
}

/// Robustesse : le décodeur ne panique sur rien, et ce qu'il accepte tient debout.
///
/// **Ce n'est PAS une campagne de fuzz**, et l'appeler ainsi serait mentir : c'est
/// un tirage pseudo-aléatoire à graine fixe, sans couverture guidée, sans
/// minimisation, sans corpus qui s'enrichit. Le fuzz reste le contrôle qui manque
/// à C3 — il exige `cargo-fuzz`, donc un nightly, donc une seconde toolchain que
/// `rust-toolchain.toml` interdit aujourd'hui.
///
/// Ce que ce test apporte quand même : il tire des octets là où la grammaire se
/// décide — CR, LF, deux-points, blancs — plutôt qu'au hasard sur 256 valeurs, où
/// presque aucun tirage ne franchirait la première ligne.
#[cfg(test)]
mod robustesse {
    use super::Message;
    use crate::Limits;

    /// Xorshift64*. Déterministe : un échec se rejoue à l'identique.
    struct Graine(u64);

    impl Graine {
        fn suivant(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    /// L'alphabet où la grammaire se joue.
    const ALPHABET: &[u8] = b"\r\n: \tAz0!~\x7f";

    #[test]
    fn aucun_tirage_ne_fait_paniquer_ni_ne_ment() {
        let mut graine = Graine(0x5EED_1234_ABCD_0001);
        let bornes = Limits {
            max_line_octets: 32,
            max_fields: 8,
            max_header_octets: 256,
        };
        let mut recevables = 0_u32;

        for _ in 0..20_000 {
            let taille = usize::try_from(graine.suivant() % 48).expect("48 tient dans usize");
            let mut entree = std::vec::Vec::with_capacity(taille);
            for _ in 0..taille {
                let rang = usize::try_from(graine.suivant()).expect("u64 vers usize");
                entree.push(ALPHABET[rang % ALPHABET.len()]);
            }

            // Panique ⇒ le test échoue, et c'est la propriété principale.
            let Ok(message) = Message::parse(&entree, &bornes) else {
                continue;
            };
            recevables = recevables.saturating_add(1);

            let mut champs = 0_usize;
            for champ in message.fields() {
                champs = champs.saturating_add(1);
                // Ce que `parse` a promis doit tenir à la relecture.
                assert!(!champ.name().is_empty(), "nom vide accepté : {entree:?}");
                assert!(
                    champ.name().iter().all(|&b| (33..=126).contains(&b)),
                    "nom hors ftext accepté : {entree:?}"
                );
                // Déplier ne peut que retirer des octets.
                let deplie: usize = champ.unfolded().map(<[u8]>::len).sum();
                assert!(
                    deplie <= champ.raw_value().len(),
                    "le dépliage a inventé des octets : {entree:?}"
                );
            }
            assert!(champs <= bornes.max_fields, "plus de champs que la borne");
        }

        // Un tirage qui ne produirait QUE des refus ne prouverait rien du chemin
        // nominal : on exige que l'alphabet ait effectivement franchi la porte.
        assert!(
            recevables > 100,
            "seulement {recevables} messages recevables — le tirage n'atteint pas la grammaire"
        );
    }
}
