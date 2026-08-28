//! Chemins et boîtes (RFC 5321 §4.1.2).

use crate::domain::{ClientId, check_domain, parse_client_id};
use crate::{Error, Limits};

/// De quel côté de l'enveloppe se lit un chemin.
///
/// Les deux côtés n'admettent pas les mêmes valeurs, et confondre les deux est
/// une faute qu'un type sépare mieux qu'un commentaire : `<>` est l'expéditeur
/// nul d'un avis de non-remise, et l'accepter en destinataire ferait accepter un
/// message qui ne va nulle part. `<Postmaster>` est l'inverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// `MAIL FROM:` — admet `<>`.
    Reverse,
    /// `RCPT TO:` — admet `<Postmaster>`.
    Forward,
}

/// Un chemin d'enveloppe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path<'a> {
    /// `<>` — l'expéditeur nul. **Uniquement en `MAIL FROM:`** : c'est ce qui
    /// permet à un avis de non-remise de ne pas en provoquer un autre.
    Null,
    /// `<Postmaster>` sans domaine. **Uniquement en `RCPT TO:`**
    /// (RFC 5321 §4.1.1.3).
    Postmaster,
    /// Une boîte complète.
    Mailbox(Mailbox<'a>),
}

/// Une boîte : une partie locale, un `@`, un domaine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mailbox<'a> {
    local_part: LocalPart<'a>,
    domain: ClientId<'a>,
}

impl<'a> Mailbox<'a> {
    /// La partie locale.
    #[must_use]
    pub fn local_part(&self) -> LocalPart<'a> {
        self.local_part
    }

    /// Le domaine, ou le littéral d'adresse.
    #[must_use]
    pub fn domain(&self) -> ClientId<'a> {
        self.domain
    }
}

/// Une partie locale, telle qu'elle a été reçue.
///
/// # Elle n'est pas déguillemetée, et c'est délibéré
///
/// Retirer les guillemets et résoudre les échappements demanderait d'allouer.
/// Cette crate ne le fait pas (C3) : elle rend les octets reçus et dit s'ils
/// étaient entre guillemets. À l'appelant de décider où poser le résultat, s'il en
/// a besoin.
///
/// **La comparaison de deux parties locales n'est donc PAS une comparaison
/// d'octets** : `"jean"@example.com` et `jean@example.com` désignent la même boîte
/// et ne s'écrivent pas pareil. Rien ici ne prétend le contraire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalPart<'a> {
    raw: &'a [u8],
    quoted: bool,
}

impl<'a> LocalPart<'a> {
    /// Les octets tels qu'ils ont été reçus, **guillemets compris** s'il y en a.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// La partie locale était-elle entre guillemets ?
    #[must_use]
    pub fn is_quoted(&self) -> bool {
        self.quoted
    }
}

/// Analyse un chemin, chevrons compris.
///
/// # Errors
///
/// Les variantes de chemin d'[`Error`].
pub fn parse_path<'a>(
    octets: &'a [u8],
    kind: PathKind,
    limits: &Limits,
) -> Result<Path<'a>, Error> {
    if octets.len() > limits.max_path_octets {
        return Err(Error::PathTooLong {
            limit: limits.max_path_octets,
        });
    }
    let [b'<', interieur @ .., b'>'] = octets else {
        return Err(Error::MalformedPath);
    };
    match interieur {
        [] => match kind {
            PathKind::Reverse => Ok(Path::Null),
            PathKind::Forward => Err(Error::NullPathRefused),
        },
        // Une route source commence par `@` : `<@relais:boite@domaine>`. Syntaxe
        // obsolète de la RFC 821, et vecteur historique de relais ouvert — le
        // serveur y était prié de retransmettre vers un tiers.
        [b'@', ..] => Err(Error::SourceRouteRefused),
        _ => {
            if interieur.eq_ignore_ascii_case(b"Postmaster") && kind == PathKind::Forward {
                return Ok(Path::Postmaster);
            }
            Ok(Path::Mailbox(parse_mailbox(interieur, limits)?))
        }
    }
}

/// Analyse une boîte `partie-locale@domaine`.
///
/// # Errors
///
/// Les variantes de boîte d'[`Error`].
pub fn parse_mailbox<'a>(octets: &'a [u8], limits: &Limits) -> Result<Mailbox<'a>, Error> {
    let (local_part, apres) = split_local_part(octets)?;
    let [b'@', domaine @ ..] = apres else {
        return Err(Error::MalformedPath);
    };
    if local_part.raw.len() > limits.max_local_part_octets {
        return Err(Error::LocalPartTooLong {
            limit: limits.max_local_part_octets,
        });
    }
    Ok(Mailbox {
        local_part,
        domain: parse_client_id(domaine, limits)?,
    })
}

/// Détache la partie locale du reste, `@` compris.
fn split_local_part(octets: &[u8]) -> Result<(LocalPart<'_>, &[u8]), Error> {
    if let [b'"', ..] = octets {
        // Le `@` peut vivre DANS les guillemets : on ne peut pas le chercher
        // avant d'avoir trouvé où la citation se ferme.
        let fin = quoted_len(octets).ok_or(Error::MalformedLocalPart)?;
        let (raw, apres) = octets.split_at(fin);
        return Ok((LocalPart { raw, quoted: true }, apres));
    }
    let at = octets
        .iter()
        .position(|&b| b == b'@')
        .ok_or(Error::MalformedPath)?;
    let (raw, apres) = octets.split_at(at);
    check_dot_string(raw)?;
    Ok((LocalPart { raw, quoted: false }, apres))
}

/// La longueur d'une chaîne entre guillemets, guillemets compris.
///
/// Rend `None` si la citation ne se ferme pas, ou porte un octet interdit.
fn quoted_len(octets: &[u8]) -> Option<usize> {
    let mut echappe = false;
    for (rang, &octet) in octets.iter().enumerate().skip(1) {
        if echappe {
            // `quoted-pairSMTP` : la barre oblique inverse ne peut précéder qu'un
            // caractère imprimable (RFC 5321 §4.1.2).
            if !(32..=126).contains(&octet) {
                return None;
            }
            echappe = false;
            continue;
        }
        match octet {
            b'\\' => echappe = true,
            b'"' => return Some(rang.saturating_add(1)),
            // `qtextSMTP` : imprimable, sauf le guillemet et la barre oblique
            // inverse, tous deux traités au-dessus.
            32..=126 => {}
            _ => return None,
        }
    }
    None
}

/// `Dot-string = Atom *("." Atom)` — des atomes non vides séparés par des points.
fn check_dot_string(octets: &[u8]) -> Result<(), Error> {
    // Pas de garde sur le vide : `[].split(p)` rend UNE tranche vide, que la
    // boucle refuse déjà. La garde était redondante, et le gate de couverture
    // l'a révélée en la comptant à jamais découverte.
    for atome in octets.split(|&b| b == b'.') {
        if atome.is_empty() || !atome.iter().all(|&b| is_atext(b)) {
            return Err(Error::MalformedLocalPart);
        }
    }
    Ok(())
}

/// `atext` (RFC 5321 §4.1.2, identique à la RFC 5322 §3.2.3).
fn is_atext(octet: u8) -> bool {
    octet.is_ascii_alphanumeric()
        || matches!(
            octet,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

/// Valide un domaine seul, sans chevrons — utilisé par `EHLO`/`HELO`.
///
/// # Errors
///
/// [`Error::MalformedDomain`].
pub fn check_bare_domain(octets: &[u8]) -> Result<(), Error> {
    check_domain(octets)
}

#[cfg(test)]
mod tests {
    use super::{Mailbox, Path, PathKind, parse_mailbox, parse_path};
    use crate::{ClientId, Error, Limits};

    /// Extrait la boîte d'un chemin.
    ///
    /// TOTAL, et c'est le point : un `let … else { panic!() }` ouvrirait dans le
    /// test une branche que rien n'emprunte, et le 100 % de C2 la compterait à
    /// jamais découverte. Les deux bras d'ici sont exercés.
    fn boite<'a>(chemin: Path<'a>) -> Option<Mailbox<'a>> {
        match chemin {
            Path::Mailbox(boite) => Some(boite),
            Path::Null | Path::Postmaster => None,
        }
    }

    fn expediteur(octets: &[u8]) -> Result<Path<'_>, Error> {
        parse_path(octets, PathKind::Reverse, &Limits::DEFAULT)
    }

    fn destinataire(octets: &[u8]) -> Result<Path<'_>, Error> {
        parse_path(octets, PathKind::Forward, &Limits::DEFAULT)
    }

    // ── Les deux côtés de l'enveloppe n'admettent pas la même chose ──────────

    #[test]
    fn le_chemin_nul_est_un_expediteur_jamais_un_destinataire() {
        // `<>` est l'expéditeur d'un avis de non-remise : c'est ce qui empêche un
        // avis d'en provoquer un autre.
        assert_eq!(expediteur(b"<>"), Ok(Path::Null));
        // En destinataire, il désigne un message qui ne va nulle part.
        assert_eq!(destinataire(b"<>"), Err(Error::NullPathRefused));
    }

    #[test]
    fn postmaster_sans_domaine_est_un_destinataire_jamais_un_expediteur() {
        // RFC 5321 §4.1.1.3.
        assert_eq!(destinataire(b"<Postmaster>"), Ok(Path::Postmaster));
        assert_eq!(destinataire(b"<POSTMASTER>"), Ok(Path::Postmaster));
        // En expéditeur, c'est une boîte sans `@`.
        assert_eq!(expediteur(b"<Postmaster>"), Err(Error::MalformedPath));
    }

    // ── Les refus ───────────────────────────────────────────────────────────

    #[test]
    fn une_route_source_est_refusee() {
        // Syntaxe obsolète de la RFC 821, vecteur historique de relais ouvert.
        assert_eq!(
            expediteur(b"<@relais.example:moi@example.com>"),
            Err(Error::SourceRouteRefused)
        );
    }

    #[test]
    fn un_chemin_sans_chevrons_est_refuse() {
        for mauvais in [
            b"moi@example.com".as_slice(),
            b"<moi@example.com",
            b"moi@example.com>",
            b"",
        ] {
            assert_eq!(
                expediteur(mauvais),
                Err(Error::MalformedPath),
                "{mauvais:?} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn un_chemin_trop_long_est_refuse() {
        let bornes = Limits {
            max_path_octets: 8,
            ..Limits::DEFAULT
        };
        assert_eq!(
            parse_path(b"<moi@example.com>", PathKind::Reverse, &bornes),
            Err(Error::PathTooLong { limit: 8 })
        );
    }

    #[test]
    fn une_partie_locale_trop_longue_est_refusee() {
        let bornes = Limits {
            max_local_part_octets: 2,
            ..Limits::DEFAULT
        };
        assert_eq!(
            parse_path(b"<moi@example.com>", PathKind::Reverse, &bornes),
            Err(Error::LocalPartTooLong { limit: 2 })
        );
    }

    // ── Les boîtes ──────────────────────────────────────────────────────────

    #[test]
    fn une_boite_ordinaire_se_decoupe() {
        let boite = boite(expediteur(b"<jean.dupont+air@mail.example.com>").expect("recevable"))
            .expect("attendu une boîte");
        assert_eq!(boite.local_part().as_bytes(), b"jean.dupont+air");
        assert!(!boite.local_part().is_quoted());
        assert_eq!(boite.domain(), ClientId::Domain(b"mail.example.com"));
    }

    #[test]
    fn une_boite_sur_litteral_d_adresse() {
        let boite = boite(expediteur(b"<moi@[192.0.2.1]>").expect("recevable")).expect("une boîte");
        assert_eq!(boite.domain(), ClientId::AddressLiteral(b"[192.0.2.1]"));
    }

    #[test]
    fn une_partie_locale_entre_guillemets_garde_ses_guillemets() {
        // Déguillemeter demanderait d'allouer ; la crate ne le fait pas.
        let boite = boite(expediteur(b"<\"jean dupont\"@example.com>").expect("recevable"))
            .expect("une boîte");
        assert_eq!(boite.local_part().as_bytes(), b"\"jean dupont\"");
        assert!(boite.local_part().is_quoted());
    }

    #[test]
    fn un_arobase_entre_guillemets_ne_coupe_pas_la_boite() {
        // C'est la raison d'être du scanner de citation : le `@` de la partie
        // locale n'est pas le séparateur.
        let boite =
            boite(expediteur(b"<\"a@b\"@example.com>").expect("recevable")).expect("une boîte");
        assert_eq!(boite.local_part().as_bytes(), b"\"a@b\"");
        assert_eq!(boite.domain(), ClientId::Domain(b"example.com"));
    }

    #[test]
    fn un_echappement_licite_est_accepte() {
        let boite =
            boite(expediteur(b"<\"a\\\"b\"@example.com>").expect("recevable")).expect("une boîte");
        assert_eq!(boite.local_part().as_bytes(), b"\"a\\\"b\"");
    }

    #[test]
    fn les_citations_mal_formees_sont_refusees() {
        for mauvais in [
            b"<\"jamais fermee@example.com>".as_slice(), // pas de guillemet fermant
            b"<\"a\\\x01b\"@example.com>",               // échappement non imprimable
            b"<\"a\x01b\"@example.com>",                 // octet non imprimable
        ] {
            assert_eq!(
                expediteur(mauvais),
                Err(Error::MalformedLocalPart),
                "{mauvais:?} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn une_citation_fermee_doit_etre_suivie_d_un_arobase() {
        assert_eq!(expediteur(b"<\"jean\">"), Err(Error::MalformedPath));
    }

    #[test]
    fn les_parties_locales_mal_formees_sont_refusees() {
        for mauvais in [
            b"<@example.com>".as_slice(), // vide — mais c'est une route source
            b"<.moi@example.com>",        // point de tête
            b"<moi.@example.com>",        // point de queue
            b"<mo..i@example.com>",       // point doublé
            b"<mo,i@example.com>",        // hors d'`atext`
        ] {
            let resultat = expediteur(mauvais);
            assert!(
                resultat == Err(Error::MalformedLocalPart)
                    || resultat == Err(Error::SourceRouteRefused),
                "{mauvais:?} : {resultat:?}"
            );
        }
    }

    #[test]
    fn tout_atext_est_accepte_dans_une_partie_locale() {
        let boite = parse_mailbox(b"a!#$%&'*+-/=?^_`{|}~0@example.com", &Limits::DEFAULT)
            .expect("recevable");
        assert_eq!(boite.local_part().as_bytes(), b"a!#$%&'*+-/=?^_`{|}~0");
    }

    #[test]
    fn l_extracteur_ne_rend_rien_pour_les_chemins_sans_boite() {
        assert_eq!(boite(Path::Null), None);
        assert_eq!(boite(Path::Postmaster), None);
    }

    #[test]
    fn les_types_de_chemin_se_copient_et_se_deboguent() {
        let chemin = expediteur(b"<moi@example.com>").expect("recevable");
        let copie = chemin;
        assert_eq!(copie, chemin);
        assert!(!std::format!("{chemin:?}").is_empty());
        assert!(!std::format!("{:?}", PathKind::Forward).is_empty());
        assert_ne!(PathKind::Forward, PathKind::Reverse);

        let boite = boite(chemin).expect("une boîte");
        assert_eq!(boite, boite);
        assert!(!std::format!("{boite:?}").is_empty());
        let locale = boite.local_part();
        assert_eq!(locale, locale);
        assert!(!std::format!("{locale:?}").is_empty());
    }
}
